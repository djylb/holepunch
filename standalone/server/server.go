package server

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/broker"
	"github.com/djylb/holepunch/standalone/proto"
)

// Defaults of Config.
const (
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultWriteTimeout     = 5 * time.Second
	DefaultHeartbeat        = 15 * time.Second
	DefaultMaxConns         = 16384
)

// closeJoin bounds the join of the server's goroutines in Close.
const closeJoin = 2 * time.Second

// Errors of the server.
var (
	ErrClosed       = errors.New("server: closed")
	ErrBusy         = errors.New("server: connection limit reached")
	ErrCloseTimeout = errors.New("server: goroutines still running after the close bound")
)

// Config configures a Server.
type Config struct {
	// Broker matches the sessions; required. The server does not own it.
	Broker *broker.Broker
	// TLS terminates every accepted connection. nil uses the connections as
	// they are, for listeners that already yield secured connections; the
	// coordinator then accepts only what Security vouches for.
	TLS *tls.Config
	// Security is passed to every Attach (coord.AttachOptions.Security): the
	// default, protocol.ControlSecurityAuto, accepts TLS connections.
	Security protocol.ControlSecurity
	// AuthToken is the shared token required on Register and Open; empty
	// disables the check. Surrounding white space is ignored and the
	// comparison runs in constant time.
	AuthToken string
	// Authorize, when set, is asked after the token check; an error refuses
	// the request with proto.CodeUnauthorized. It runs on the connection's
	// goroutine, outside every lock, inside a recover boundary (a panic
	// refuses).
	Authorize func(AuthRequest) error //holepunch:callback
	// OnTransport receives the hosts' transport reports (telemetry only).
	// It runs on the host link's goroutine, inside a recover boundary, and
	// must not block for long.
	OnTransport func(TransportReport) //holepunch:callback
	// Logger receives connection-level events at debug level and recovered
	// panics at warn level; nil discards them.
	Logger *slog.Logger
	// HandshakeTimeout bounds the TLS handshake plus the first request.
	HandshakeTimeout time.Duration
	// WriteTimeout bounds every frame the server writes.
	WriteTimeout time.Duration
	// Heartbeat is the registration links' heartbeat interval; a link silent
	// for three intervals is dropped. Within [1 s, 300 s].
	Heartbeat time.Duration
	// MaxConns bounds the connections the server holds: streams not yet
	// handed to a session plus registration links. More are closed at once.
	MaxConns int
}

// AuthScope is what an AuthRequest asks for.
type AuthScope string

// Auth scopes.
const (
	ScopeRegister AuthScope = "register"
	ScopeOpen     AuthScope = "open"
)

// AuthRequest is what Config.Authorize decides on.
type AuthRequest struct {
	Scope    AuthScope
	HostID   string
	DialerID string // ScopeOpen only; self-declared
	Token    string // the auth token the client sent
	Metadata map[string]string
	Remote   net.Addr
	// TLS is the connection's TLS state (client certificates, SNI), nil
	// without Config.TLS.
	TLS *tls.ConnectionState
}

// TransportReport is a host's report on a session's upper-layer transport.
type TransportReport struct {
	HostID    string
	SessionID string
	OK        bool
	Detail    string
}

// Stats are the server's counters.
type Stats struct {
	Accepted        uint64 // connections taken by Serve or ServeConn
	Refused         uint64 // requests answered with Fail, connections over MaxConns
	HandshakeFailed uint64 // TLS handshakes or first requests that failed
	Registered      uint64 // registration links opened
	Opened          uint64 // dialer streams handed to a session
	Joined          uint64 // host streams handed to a session
	Panics          uint64 // recovered in connection goroutines and hooks
	Conns           int    // connections held now
	Hosts           int    // registration links now
}

// Server serves standalone clients. Create it with New.
type Server struct {
	cfg      Config
	log      *slog.Logger
	group    *life.Group
	tokenSum *[sha256.Size]byte

	// The connections and listeners are tracked by pointers of the
	// server's own, since a caller's net.Conn or net.Listener need not be
	// comparable.
	mu        sync.Mutex
	closed    bool
	listeners map[*net.Listener]struct{}
	conns     map[*stream]struct{}
	hosts     int

	accepted, refused, handshakeFailed atomic.Uint64
	registered, opened, joined, panics atomic.Uint64

	closeOnce sync.Once
	closeErr  error
}

// New validates cfg and returns a server; it starts nothing.
func New(cfg Config) (*Server, error) {
	if cfg.Broker == nil {
		return nil, errors.New("server: Config.Broker is required")
	}
	cfg.HandshakeTimeout = cmp.Or(cfg.HandshakeTimeout, DefaultHandshakeTimeout)
	cfg.WriteTimeout = cmp.Or(cfg.WriteTimeout, DefaultWriteTimeout)
	cfg.Heartbeat = cmp.Or(cfg.Heartbeat, DefaultHeartbeat)
	cfg.MaxConns = cmp.Or(cfg.MaxConns, DefaultMaxConns)
	switch {
	case cfg.HandshakeTimeout < 0 || cfg.WriteTimeout < 0 || cfg.MaxConns < 0:
		return nil, errors.New("server: negative timeout or limit")
	case cfg.Heartbeat < proto.MinHeartbeatMs*time.Millisecond || cfg.Heartbeat > proto.MaxHeartbeatMs*time.Millisecond:
		return nil, fmt.Errorf("server: Heartbeat %v outside [1s, 300s]", cfg.Heartbeat)
	}
	s := &Server{
		cfg:       cfg,
		log:       cfg.Logger,
		group:     life.New(context.Background()),
		listeners: map[*net.Listener]struct{}{},
		conns:     map[*stream]struct{}{},
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if tok := strings.TrimSpace(cfg.AuthToken); tok != "" {
		sum := sha256.Sum256([]byte(tok))
		s.tokenSum = &sum
	}
	return s, nil
}

// Serve accepts connections on l and serves each one (ServeConn) until the
// server is closed, when it returns nil; l is closed when Serve returns.
// Accept errors other than a closed listener are retried with a backoff
// growing to 1 s, so that a full file table does not end the server.
func (s *Server) Serve(l net.Listener) error {
	if !s.trackListener(&l) {
		_ = l.Close()
		return ErrClosed
	}
	defer s.untrackListener(&l)
	var delay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			// The listener's error is the caller's: inspecting it runs its
			// methods, inside a recover boundary.
			var closed bool
			if perr := life.Safe("server.accept-error", func() { closed = errors.Is(err, net.ErrClosed) }); perr != nil {
				return perr
			}
			if closed {
				return err
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			s.log.Debug("accept failed", "err", err, "retry_in", delay)
			if !s.pause(delay) {
				return nil
			}
			continue
		}
		delay = 0
		_ = s.ServeConn(conn)
	}
}

// ServeConn serves one accepted connection on a goroutine of its own and
// owns it from now on, even when it returns an error (ErrClosed, ErrBusy),
// in which case conn is already closed.
func (s *Server) ServeConn(conn net.Conn) error {
	if life.IsNil(conn) {
		return errors.New("server: nil connection")
	}
	s.accepted.Add(1)
	st := &stream{raw: conn, conn: conn}
	if err := s.track(st); err != nil {
		s.closeConn(conn)
		return err
	}
	if !s.group.Go("standalone.conn", func(ctx context.Context) { s.handle(ctx, st) }) {
		s.drop(st)
		return ErrClosed
	}
	return nil
}

// Close stops the listeners, closes every connection the server still owns
// and joins the server's goroutines within 2 s, returning ErrCloseTimeout
// when some are left. Sessions already handed to the broker are not
// touched. It is idempotent and safe for concurrent use.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		ls := s.listeners
		cs := s.conns
		s.listeners, s.conns = nil, nil
		s.mu.Unlock()
		for l := range ls {
			s.closeConn(*l)
		}
		for st := range cs {
			s.closeConn(st.raw)
		}
		s.closeErr = s.group.Close(closeJoin)
		if s.group.Stats().Leaked > 0 {
			s.closeErr = ErrCloseTimeout
		}
	})
	return s.closeErr
}

// Stats returns a snapshot of the counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	conns, hosts := len(s.conns), s.hosts
	s.mu.Unlock()
	return Stats{
		Accepted: s.accepted.Load(), Refused: s.refused.Load(), HandshakeFailed: s.handshakeFailed.Load(),
		Registered: s.registered.Load(), Opened: s.opened.Load(), Joined: s.joined.Load(),
		Panics: s.panics.Load(), Conns: conns, Hosts: hosts,
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// pause waits d unless the server closes first; it reports whether the
// wait completed.
func (s *Server) pause(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-s.group.Context().Done():
		return false
	}
}

func (s *Server) trackListener(l *net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.listeners[l] = struct{}{}
	return true
}

func (s *Server) untrackListener(l *net.Listener) {
	s.mu.Lock()
	delete(s.listeners, l)
	s.mu.Unlock()
	_ = (*l).Close()
}

func (s *Server) track(st *stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return ErrClosed
	case len(s.conns) >= s.cfg.MaxConns:
		s.refused.Add(1)
		return ErrBusy
	}
	s.conns[st] = struct{}{}
	return nil
}

// untrack gives st up: it was handed to a session.
func (s *Server) untrack(st *stream) {
	s.mu.Lock()
	delete(s.conns, st)
	s.mu.Unlock()
}

// drop untracks and closes st.
func (s *Server) drop(st *stream) {
	s.untrack(st)
	s.closeConn(st.raw)
}

// closeConn closes a connection or listener the server owns. Its Close is
// the caller's code: a panic in it is recovered and counted, so that it
// neither ends the server's other connections nor stops Close half-way.
func (s *Server) closeConn(c io.Closer) {
	if perr := life.Safe("standalone.close", func() { _ = c.Close() }); perr != nil {
		s.panics.Add(1)
		s.log.Warn("close panicked", "err", perr)
	}
}

package quicpath

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/protocol"
)

const (
	// maxDialAttempts bounds a dial's QUIC handshake attempts within the
	// session's TransportTimeout. QUIC retransmits its own Initial packets;
	// another attempt only follows an explicit refusal.
	maxDialAttempts = 3
	// dialRetryDelay separates two attempts.
	dialRetryDelay = 200 * time.Millisecond
	// defaultTransportTimeout applies when the session carries none.
	defaultTransportTimeout = 10 * time.Second
	// defaultIdleTimeout applies when the path has no keepalive advice.
	defaultIdleTimeout = 30 * time.Second
)

// ErrRole is the error of a call this side's role does not make: the
// initiator dials, the responder accepts.
var ErrRole = errors.New("quicpath: not this role's side")

// errUnexpectedPeer refuses a connection attempt from an address that is
// not the peer's on a path of the socket.
var errUnexpectedPeer = errors.New("quicpath: not a confirmed peer address")

// Dial connects QUIC to the peer on the session's primary path; this side
// must be the initiator (ErrRole). It waits at most the session's
// TransportTimeout, in at most three attempts, and stops at once when the
// socket is closed or the peer fails the TLS handshake — a pin mismatch.
// On success the Conn owns sess: its Close closes the QUIC connection, the
// QUIC transport and the Session. On error, sess stays the caller's, with
// nothing left reading its socket.
func Dial(ctx context.Context, sess *holepunch.Session, tlsConf *tls.Config, quicConf *quic.Config) (*Conn, error) {
	return connect(ctx, sess, tlsConf, quicConf, (*Endpoint).Dial)
}

// Accept waits for the peer's QUIC connection on the session's primary
// path; this side must be the responder (ErrRole). It waits at most the
// session's TransportTimeout and takes connections from the path's
// confirmed peer address only. Once it has one it stops listening. On
// success the Conn owns sess, as with Dial; on error, sess stays the
// caller's, with nothing left reading its socket.
func Accept(ctx context.Context, sess *holepunch.Session, tlsConf *tls.Config, quicConf *quic.Config) (*Conn, error) {
	c, err := connect(ctx, sess, tlsConf, quicConf, (*Endpoint).Accept)
	if err == nil {
		c.ep.stopListening()
	}
	return c, err
}

// connect runs one pipe on the primary path of a private Endpoint, which
// the Conn then owns.
func connect(ctx context.Context, sess *holepunch.Session, tlsConf *tls.Config, quicConf *quic.Config,
	open func(*Endpoint, context.Context, int) (*Conn, error)) (*Conn, error) {
	e, err := NewEndpoint(sess, tlsConf, quicConf)
	if err != nil {
		return nil, err
	}
	c, err := open(e, ctx, 0)
	if err != nil {
		e.shutdown(false)
		return nil, err
	}
	c.own = true
	return c, nil
}

// Endpoint runs QUIC pipes on every confirmed path of a session, the extra
// paths (Result.ExtraPaths) included: the initiator dials a path, the
// responder accepts on it, and each pipe is a Conn. The Endpoint owns the
// session — Close closes every pipe, the QUIC transports and the Session.
// It runs one quic.Transport per socket, created at the first pipe on it:
// two paths of different kinds of network may share a socket
// (Session.PacketConns), and their pipes then share the transport, which
// tells them apart by the peer address.
//
// A path may carry a new pipe after its previous one died: the initiator
// dials it again and the responder accepts again. Until Close, a
// responder's transport keeps listening, and a connection the peer opened
// on another path of the same socket waits for the next Accept on that
// path (the newest one per path; an older one is closed).
type Endpoint struct {
	sess    *holepunch.Session
	role    protocol.Role
	paths   []holepunch.Path // Result.Paths(): the primary path first
	pathOf  []*socket        // the socket of each path
	socks   []*socket        // one per distinct socket
	tls     *tls.Config
	quic    *quic.Config // the caller's (a copy); nil for none
	timeout time.Duration

	mu     sync.Mutex
	conns  map[*Conn]struct{}
	closed bool

	closeOnce sync.Once
	closeErr  error
}

// NewEndpoint takes over sess. Its pipes use tlsConf — a client
// configuration for the initiator, a server one for the responder; it must
// name an application protocol (NextProtos) — and quicConf, nil for the
// defaults (see the package documentation). Both are copied. On error, sess
// stays the caller's.
func NewEndpoint(sess *holepunch.Session, tlsConf *tls.Config, quicConf *quic.Config) (*Endpoint, error) {
	switch {
	case sess == nil:
		return nil, errors.New("quicpath: nil session")
	case tlsConf == nil || len(tlsConf.NextProtos) == 0:
		return nil, errors.New("quicpath: the TLS configuration must name an application protocol (NextProtos)")
	}
	res := sess.Result()
	if !res.Role.IsPunch() {
		return nil, fmt.Errorf("%w: role %q", ErrRole, res.Role)
	}
	e := &Endpoint{
		sess:    sess,
		role:    res.Role,
		paths:   res.Paths(),
		tls:     tlsConf.Clone(),
		timeout: res.TransportTimeout,
		conns:   make(map[*Conn]struct{}),
	}
	if e.timeout <= 0 {
		e.timeout = defaultTransportTimeout
	}
	if quicConf != nil {
		e.quic = quicConf.Clone()
	}
	for i, p := range e.paths {
		e.paths[i].RemoteAddr = unmap(p.RemoteAddr)
		var s *socket
		for _, x := range e.socks {
			if sameConn(x.pc, p.Conn) {
				s = x
				break
			}
		}
		if s == nil {
			s = &socket{pc: p.Conn, changed: make(chan struct{})}
			e.socks = append(e.socks, s)
		}
		e.pathOf = append(e.pathOf, s)
	}
	return e, nil
}

// Session returns the session the Endpoint owns.
func (e *Endpoint) Session() *holepunch.Session { return e.sess }

// Paths returns the session's confirmed paths, the primary one first: the
// indexes of Dial and Accept.
func (e *Endpoint) Paths() []holepunch.Path {
	out := make([]holepunch.Path, len(e.paths))
	copy(out, e.paths)
	for i := range out {
		if pm := out[i].PortMapping; pm != nil {
			c := *pm
			out[i].PortMapping = &c
		}
	}
	return out
}

// Dial connects QUIC to the peer on path i (Paths); this side must be the
// initiator (ErrRole). It waits at most the session's TransportTimeout, in
// at most three attempts, and stops at once when the socket is closed — an
// error wrapping ErrClosed — or the peer fails the TLS handshake.
func (e *Endpoint) Dial(ctx context.Context, i int) (*Conn, error) {
	if e.role != protocol.RoleInitiator {
		return nil, fmt.Errorf("%w: the %s accepts", ErrRole, e.role)
	}
	p, tr, _, err := e.open(i)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	conf := pathConfig(e.quic, p, e.timeout)
	remote := net.UDPAddrFromAddrPort(p.RemoteAddr)
	var last error
	for attempt := 1; ; attempt++ {
		qc, err := tr.Dial(ctx, remote, e.tls, conf)
		if err == nil {
			return e.track(qc, p)
		}
		last = err
		if attempt >= maxDialAttempts || ctx.Err() != nil || final(err) || !pause(ctx, dialRetryDelay) {
			break
		}
	}
	if errors.Is(last, net.ErrClosed) {
		return nil, fmt.Errorf("%w: dial %v: %w", ErrClosed, p.RemoteAddr, last)
	}
	return nil, fmt.Errorf("quicpath: dial %v: %w", p.RemoteAddr, last)
}

// Accept waits for the peer's QUIC connection on path i (Paths); this side
// must be the responder (ErrRole). It waits at most the session's
// TransportTimeout and takes connections from the path's confirmed peer
// address only; the transport refuses every other before its handshake.
func (e *Endpoint) Accept(ctx context.Context, i int) (*Conn, error) {
	if e.role != protocol.RoleResponder {
		return nil, fmt.Errorf("%w: the %s dials", ErrRole, e.role)
	}
	p, _, ln, err := e.open(i)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	s := e.pathOf[i]
	qc, err := s.accept(ctx, ln, p.RemoteAddr, func(a netip.AddrPort) bool {
		_, ok := e.pathFrom(s, a)
		return ok
	})
	if err != nil {
		return nil, fmt.Errorf("quicpath: accept from %v: %w", p.RemoteAddr, err)
	}
	return e.track(qc, p)
}

// Close closes every pipe, telling the peer, then the QUIC transports and
// the Session, and returns the Session's error. It is idempotent.
func (e *Endpoint) Close() error {
	e.shutdown(true)
	return e.closeErr
}

// shutdown closes the pipes and the transports, and the session if
// closeSession; only the first call acts.
func (e *Endpoint) shutdown(closeSession bool) {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		conns := e.conns
		e.conns = nil
		e.mu.Unlock()
		for c := range conns {
			_ = c.qc.CloseWithError(codeClosed, "closed")
		}
		for _, s := range e.socks {
			s.close()
		}
		if closeSession {
			e.closeErr = e.sess.Close()
		}
	})
}

// open checks path i and returns it with its socket's transport and, for
// the responder, listener, creating them at the first use of the socket.
func (e *Endpoint) open(i int) (holepunch.Path, *quic.Transport, *quic.Listener, error) {
	if i < 0 || i >= len(e.paths) {
		return holepunch.Path{}, nil, nil, fmt.Errorf("quicpath: no path %d (the session has %d)", i, len(e.paths))
	}
	p, s := e.paths[i], e.pathOf[i]
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return p, nil, nil, ErrClosed
	}
	if s.tr == nil {
		// Defensive: the session handed the socket over with clear
		// deadlines, and quic-go expects none.
		if err := s.pc.SetDeadline(time.Time{}); err != nil {
			return p, nil, nil, fmt.Errorf("quicpath: socket: %w", err)
		}
		tr := &quic.Transport{Conn: s.pc}
		if e.role == protocol.RoleResponder {
			ln, err := tr.Listen(e.tls, e.listenConfig(s, p))
			if err != nil {
				_ = tr.Close()
				return p, nil, nil, fmt.Errorf("quicpath: listen: %w", err)
			}
			s.ln = ln
		}
		s.tr = tr
	}
	return p, s.tr, s.ln, nil
}

// listenConfig is the configuration of s's listener: each incoming
// connection gets the configuration of its path, found by its address, and
// one from any other address is refused before its handshake. The
// caller's GetConfigForClient, if any, picks the base configuration.
func (e *Endpoint) listenConfig(s *socket, first holepunch.Path) *quic.Config {
	conf := pathConfig(e.quic, first, e.timeout)
	var user func(*quic.ClientInfo) (*quic.Config, error)
	if e.quic != nil {
		user = e.quic.GetConfigForClient
	}
	conf.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) {
		var p holepunch.Path
		a, ok := addrPort(info.RemoteAddr)
		if ok {
			p, ok = e.pathFrom(s, a)
		}
		if !ok {
			return nil, errUnexpectedPeer
		}
		base := e.quic
		if user != nil {
			c, err := user(info)
			if err != nil {
				return nil, err
			}
			if c != nil {
				base = c
			}
		}
		return pathConfig(base, p, e.timeout), nil
	}
	return conf
}

// pathFrom returns the path on s whose peer address is a.
func (e *Endpoint) pathFrom(s *socket, a netip.AddrPort) (holepunch.Path, bool) {
	for i, p := range e.paths {
		if e.pathOf[i] == s && p.RemoteAddr == a {
			return p, true
		}
	}
	return holepunch.Path{}, false
}

// track registers a new pipe, or closes it if the Endpoint closed
// meanwhile.
func (e *Endpoint) track(qc *quic.Conn, p holepunch.Path) (*Conn, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		_ = qc.CloseWithError(codeClosed, "closed")
		return nil, ErrClosed
	}
	c := &Conn{qc: qc, path: p, ep: e}
	e.conns[c] = struct{}{}
	e.mu.Unlock()
	// A pipe that dies on its own is forgotten too, so that an Endpoint
	// redialing its paths for a long time keeps no dead ones.
	context.AfterFunc(qc.Context(), func() { e.untrack(c) })
	return c, nil
}

// untrack forgets a closed pipe.
func (e *Endpoint) untrack(c *Conn) {
	e.mu.Lock()
	delete(e.conns, c)
	e.mu.Unlock()
}

// stopListening closes the responder's listeners; the pipes stay.
func (e *Endpoint) stopListening() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.socks {
		if s.ln != nil {
			_ = s.ln.Close()
		}
	}
}

// socket is one distinct socket of the session and the QUIC transport that
// reads it.
type socket struct {
	pc net.PacketConn
	tr *quic.Transport // set once, under Endpoint.mu
	ln *quic.Listener  // the responder's; set once, under Endpoint.mu

	mu        sync.Mutex
	accepting bool                          // an Accept is reading ln
	parked    map[netip.AddrPort]*quic.Conn // accepted for another path, by peer address
	changed   chan struct{}                 // closed and replaced when accepting or parked changes
}

// accept returns the next connection from peer: one parked for it, or the
// next one ln accepts. One Accept at a time reads ln; a connection it gets
// for another path of the socket is parked for that path, and the waiting
// Accepts look again.
func (s *socket) accept(ctx context.Context, ln *quic.Listener, peer netip.AddrPort, known func(netip.AddrPort) bool) (*quic.Conn, error) {
	for {
		s.mu.Lock()
		if qc := s.parked[peer]; qc != nil {
			delete(s.parked, peer)
			s.mu.Unlock()
			if qc.Context().Err() != nil {
				continue // it died while parked: wait for the next one
			}
			return qc, nil
		}
		if s.accepting {
			wait := s.changed
			s.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		s.accepting = true
		s.mu.Unlock()

		qc, err := ln.Accept(ctx)
		var (
			got     *quic.Conn
			discard *quic.Conn
			code    quic.ApplicationErrorCode
		)
		s.mu.Lock()
		s.accepting = false
		if err == nil {
			from, _ := addrPort(qc.RemoteAddr())
			switch {
			case from == peer:
				got = qc
			case known(from):
				if s.parked == nil {
					s.parked = make(map[netip.AddrPort]*quic.Conn)
				}
				discard, code = s.parked[from], codeSuperseded
				s.parked[from] = qc
			default:
				discard, code = qc, codeUnexpectedPeer
			}
		}
		close(s.changed)
		s.changed = make(chan struct{})
		s.mu.Unlock()
		if discard != nil {
			_ = discard.CloseWithError(code, "")
		}
		if err != nil {
			return nil, err
		}
		if got != nil {
			return got, nil
		}
	}
}

// close closes the parked connections, the listener and the transport; the
// socket itself stays open.
func (s *socket) close() {
	s.mu.Lock()
	parked := s.parked
	s.parked = nil
	s.mu.Unlock()
	for _, qc := range parked {
		_ = qc.CloseWithError(codeClosed, "closed")
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	if s.tr != nil {
		_ = s.tr.Close()
	}
}

// pathConfig completes base (nil for none) with the path's defaults: the
// keepalive advice as keep-alive period and idle timeout, the transport
// timeout as handshake idle timeout. Fields base sets are kept.
func pathConfig(base *quic.Config, p holepunch.Path, transport time.Duration) *quic.Config {
	c := &quic.Config{}
	if base != nil {
		c = base.Clone()
	}
	c.GetConfigForClient = nil
	if c.HandshakeIdleTimeout <= 0 {
		c.HandshakeIdleTimeout = transport
	}
	if c.MaxIdleTimeout <= 0 {
		c.MaxIdleTimeout = p.Keepalive.Timeout
		if c.MaxIdleTimeout <= 0 {
			c.MaxIdleTimeout = defaultIdleTimeout
		}
	}
	if c.KeepAlivePeriod <= 0 {
		c.KeepAlivePeriod = p.Keepalive.Interval
		if c.KeepAlivePeriod <= 0 || c.KeepAlivePeriod >= c.MaxIdleTimeout {
			c.KeepAlivePeriod = c.MaxIdleTimeout / 3
		}
	}
	return c
}

// final reports a dial error that another attempt cannot cure: a closed
// socket or transport (net.ErrClosed covers quic-go's transport-closed error
// too), or a TLS failure such as a pin mismatch.
func final(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	var te *quic.TransportError
	return errors.As(err, &te) && te.ErrorCode.IsCryptoError()
}

// pause waits d unless ctx ends first; it reports whether the wait
// completed.
func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// addrPort returns a socket address as an AddrPort, IPv4-mapped addresses
// unmapped.
func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch a := a.(type) {
	case nil:
		return netip.AddrPort{}, false
	case *net.UDPAddr:
		if a == nil {
			return netip.AddrPort{}, false
		}
		return unmap(a.AddrPort()), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return unmap(ap), true
}

func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// sameConn reports whether a and b are the same socket. A conn whose
// dynamic type == cannot compare would panic; such conns count as
// different, as they do for Session.PacketConns.
func sameConn(a, b net.PacketConn) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}

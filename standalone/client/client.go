package client

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone"
	"github.com/djylb/holepunch/standalone/internal/life"
	"github.com/djylb/holepunch/standalone/proto"
)

// DefaultHandshakeTimeout bounds the TLS handshake plus the server's answer
// when Config.HandshakeTimeout is zero.
const DefaultHandshakeTimeout = 10 * time.Second

// closeJoin bounds the join of the Client's goroutines in Close.
const closeJoin = 2 * time.Second

// Errors of the client. A request the server refused returns its
// *proto.Fail; a failed punch returns the *holepunch.Error.
var (
	ErrClosed       = errors.New("client: closed")
	ErrServing      = errors.New("client: Serve is already running")
	ErrNoLink       = errors.New("client: no registration link to report on")
	ErrCloseTimeout = errors.New("client: goroutines still running after the close bound")
)

// Config configures a Client.
type Config struct {
	// Server is the server's address, "host:port". The default dialer
	// connects to it, and its host is the TLS server name when TLS has none.
	Server string
	// TLS authenticates the server; nil verifies it against the system
	// roots. The control streams carry the sessions' keys, so the server
	// must be authenticated (pin its certificate, or use a CA).
	TLS *tls.Config
	// Dial opens the transport under TLS; nil dials Server over TCP with
	// standalone.DialTCP. It is called inside a recover boundary.
	Dial func(ctx context.Context) (net.Conn, error) //holepunch:callback
	// AuthToken is the server's shared token, if it requires one.
	AuthToken string
	// Session is the template of every session's holepunch.Options; the
	// TransportMode and TransportData of the OpenRequest or Registration
	// replace its own.
	Session holepunch.Options
	// HandshakeTimeout bounds the TLS handshake plus the server's answer;
	// 0 means DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// Logger receives Serve's background events; nil discards them.
	Logger *slog.Logger
}

// Client is a standalone client. Create it with New; it is safe for
// concurrent use.
type Client struct {
	cfg   Config
	tls   *tls.Config
	log   *slog.Logger
	group *life.Group

	mu       sync.Mutex
	serving  bool
	link     *link                 // the current registration link of Serve
	sessions map[*Session]struct{} // the Handlers' sessions; nil once closed

	closeOnce sync.Once
	closeErr  error
}

// New validates cfg and returns a Client; it opens nothing.
func New(cfg Config) (*Client, error) {
	cfg.HandshakeTimeout = cmp.Or(cfg.HandshakeTimeout, DefaultHandshakeTimeout)
	if cfg.HandshakeTimeout < 0 {
		return nil, errors.New("client: negative HandshakeTimeout")
	}
	cfg.AuthToken = strings.TrimSpace(cfg.AuthToken)
	if cfg.Dial == nil && cfg.Server == "" {
		return nil, errors.New("client: Config.Server or Config.Dial is required")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13}
	if cfg.TLS != nil {
		tc = cfg.TLS.Clone()
	}
	if tc.ServerName == "" && cfg.Server != "" {
		host, _, err := net.SplitHostPort(cfg.Server)
		if err != nil {
			return nil, fmt.Errorf("client: Config.Server: %w", err)
		}
		tc.ServerName = host
	}
	if tc.ServerName == "" && !tc.InsecureSkipVerify {
		return nil, errors.New("client: no TLS server name to verify the server with")
	}
	c := &Client{cfg: cfg, tls: tc, log: cfg.Logger, group: life.New(context.Background()), sessions: map[*Session]struct{}{}}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	return c, nil
}

// OpenRequest asks for a session with a host.
type OpenRequest struct {
	HostID   string
	DialerID string // optional, shown to the host
	Metadata map[string]string
	// TransportMode and TransportData are this side's transport offer
	// (holepunch.Options); the host's data arrives in
	// Result.PeerTransportData.
	TransportMode string
	TransportData []byte
}

// Open opens a session with the host req.HostID and punches it: it returns
// once holepunch.Punch has, with the punched path. ctx bounds the
// whole call; the server's answer must come within Config.HandshakeTimeout.
// Errors: ErrClosed, the server's *proto.Fail, a *holepunch.Error, or a
// dialing or TLS error.
func (c *Client) Open(ctx context.Context, req OpenRequest) (*Session, error) {
	if c.group.Context().Err() != nil {
		return nil, ErrClosed
	}
	conn, info, err := c.request(ctx, &proto.Open{HostID: req.HostID, DialerID: req.DialerID, AuthToken: c.cfg.AuthToken, Metadata: req.Metadata})
	if err != nil {
		return nil, err
	}
	return c.attach(ctx, conn, info, protocol.RoleInitiator, req.TransportMode, req.TransportData, nil)
}

// Close stops Serve and the sessions it serves: it closes the registration
// link, cancels the Handlers' context and waits at most 2 s for the
// Client's goroutines, so that a Handler can still end its session in order
// (a QUIC close, say). Goroutines still running then — a Handler that
// ignores its context — are reported as ErrCloseTimeout, and their sessions
// are closed under them. It is idempotent and safe for concurrent use.
// Sessions returned by Open are the caller's and stay open.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		l := c.link
		c.mu.Unlock()
		if l != nil {
			_ = l.conn.Close()
		}
		c.closeErr = c.group.Close(closeJoin)
		c.mu.Lock()
		stuck := c.sessions
		c.sessions = nil
		c.mu.Unlock()
		for s := range stuck {
			_ = s.Close()
		}
		if n := c.group.Leaked(); n > 0 {
			c.closeErr = fmt.Errorf("%w: %d left", ErrCloseTimeout, n)
		}
	})
	return c.closeErr
}

// track records a Handler's session; false means the Client is closed and
// the session must be closed now.
func (c *Client) track(s *Session) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sessions == nil {
		return false
	}
	c.sessions[s] = struct{}{}
	return true
}

func (c *Client) untrack(s *Session) {
	c.mu.Lock()
	delete(c.sessions, s)
	c.mu.Unlock()
}

// dial opens a TLS stream to the server.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	var (
		raw net.Conn
		err error
	)
	dial := c.cfg.Dial
	if dial == nil {
		dial = func(ctx context.Context) (net.Conn, error) { return standalone.DialTCP(ctx, c.cfg.Server) }
	}
	if perr := life.Safe("client.Dial", func() { raw, err = dial(ctx) }); perr != nil {
		return nil, perr
	}
	if err != nil {
		return nil, err
	}
	if life.IsNil(raw) {
		return nil, errors.New("client: Dial returned no connection")
	}
	tc := tls.Client(raw, c.tls) // tc owns raw from here on
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		return nil, err
	}
	return tc, nil
}

// request opens a stream, sends m and reads the SessionInfo answering it.
// On success the stream is the caller's, positioned before punch_start.
func (c *Client) request(ctx context.Context, m proto.Message) (net.Conn, *proto.SessionInfo, error) {
	hctx, cancel := context.WithTimeout(ctx, c.cfg.HandshakeTimeout)
	defer cancel()
	conn, err := c.dial(hctx)
	if err != nil {
		return nil, nil, err
	}
	if err := proto.Write(conn, m, c.cfg.HandshakeTimeout); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	info, err := proto.Expect[*proto.SessionInfo](hctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, info, nil
}

// attach runs the punch on the stream and closes the stream afterwards:
// after Punch the server has no further part in the session.
func (c *Client) attach(ctx context.Context, conn net.Conn, info *proto.SessionInfo, role protocol.Role, mode string, data []byte, report func(proto.Transport) error) (*Session, error) {
	opts := c.cfg.Session
	opts.TransportMode, opts.TransportData = mode, data
	hp, err := holepunch.Punch(ctx, conn, opts)
	_ = conn.Close()
	if err != nil {
		return nil, err
	}
	if res := hp.Result(); res.SessionID != info.SessionID || res.Role != role {
		_ = hp.Close()
		return nil, fmt.Errorf("client: punched session %s as %s, the server announced %s as %s", res.SessionID, res.Role, info.SessionID, role)
	}
	return newSession(*info, role, hp, report), nil
}

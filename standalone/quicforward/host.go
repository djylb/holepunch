package quicforward

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/djylb/holepunch/standalone"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/internal/life"
	"github.com/djylb/holepunch/standalone/proto"
)

const (
	// DefaultDialTimeout bounds a target dial when HostConfig.DialTimeout
	// is zero.
	DefaultDialTimeout = 10 * time.Second
	// closeJoin bounds the join of a forward connection's goroutines.
	closeJoin = 2 * time.Second
)

// HostConfig configures the host side.
type HostConfig struct {
	// Targets are the TCP targets ("host:port") the host forwards to; the
	// first is the default for a stream that names none. A stream asking
	// for any other target, or for one the session's AccessPolicy does not
	// allow, is refused. At least one is required.
	Targets []string
	// Dial connects a target; nil dials TCP with standalone.DialTCP. It is
	// called inside a recover boundary.
	Dial func(ctx context.Context, address string) (net.Conn, error) //holepunch:callback
	// DialTimeout bounds a target dial; 0 means DefaultDialTimeout. A
	// stream's request, the dial and the answer must all fit in 15 s, after
	// which the dialer takes the unanswered stream for a sign of a dead
	// connection and opens a new session: keep it well below that.
	DialTimeout time.Duration
	// Logger receives the forwarding events; nil discards them.
	Logger *slog.Logger
}

// normalize checks the configuration and puts its targets in canonical
// form.
func (cfg HostConfig) normalize() (HostConfig, error) {
	if len(cfg.Targets) == 0 {
		return cfg, errors.New("quicforward: HostConfig.Targets is empty")
	}
	targets := make([]string, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		c, err := proto.CanonicalTarget(t)
		if err != nil {
			return cfg, fmt.Errorf("quicforward: target %q: %w", t, err)
		}
		targets = append(targets, c)
	}
	cfg.Targets = targets
	cfg.DialTimeout = cmp.Or(cfg.DialTimeout, DefaultDialTimeout)
	if cfg.Dial == nil {
		cfg.Dial = standalone.DialTCP
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return cfg, nil
}

// resolve picks the stream's target.
func (cfg HostConfig) resolve(requested string, policy proto.AccessPolicy) (string, error) {
	target := cfg.Targets[0]
	if requested != "" {
		t, err := proto.CanonicalTarget(requested)
		if err != nil {
			return "", err
		}
		target = t
	}
	if !slices.Contains(cfg.Targets, target) || !policy.Allows(target) {
		return "", fmt.Errorf("target %s is not allowed", target)
	}
	return target, nil
}

// Serve registers reg.HostID through c and forwards every session dialers
// open with it (ServeSession), until ctx ends or c is closed (client.Serve).
// reg's transport offer is replaced by a fresh Identity's.
func Serve(ctx context.Context, c *client.Client, reg client.Registration, cfg HostConfig) error {
	cfg, err := cfg.normalize()
	if err != nil {
		return err
	}
	id, err := NewIdentity()
	if err != nil {
		return err
	}
	reg.TransportMode, reg.TransportData = Mode, id.TransportData()
	return c.Serve(ctx, reg, func(ctx context.Context, sess *client.Session) {
		if err := ServeSession(ctx, sess, id, cfg); err != nil {
			cfg.Logger.Info("forward session ended", "session", sess.ID(), "err", err)
		}
	})
}

// ServeSession runs the host side of one session and closes sess before it
// returns. It accepts the dialer's QUIC connection within the session's
// TransportTimeout — failing that, the listener, the transport and the
// socket are closed — reports the outcome to the server, and forwards every
// stream until the connection ends (nil when the dialer closed it or ctx
// ended).
func ServeSession(ctx context.Context, sess *client.Session, id *Identity, cfg HostConfig) error {
	defer func() { _ = sess.Close() }()
	cfg, err := cfg.normalize()
	if err != nil {
		return err
	}
	conn, err := Accept(ctx, sess, id)
	if err != nil {
		reportTransport(cfg.Logger, sess, false, "quic_accept_failed")
		return err
	}
	reportTransport(cfg.Logger, sess, true, Mode)
	g := life.New(ctx)
	defer func() {
		_ = conn.Close()
		_ = g.Close(closeJoin)
	}()
	policy := sess.Info().Policy
	for {
		st, err := conn.qc.AcceptStream(g.Context())
		if err != nil {
			if g.Context().Err() != nil || peerClosed(err) {
				return nil
			}
			return err
		}
		if !g.Go("quicforward.stream", func(gctx context.Context) {
			if perr := life.Safe("quicforward.stream", func() { serveStream(gctx, g, conn, st, policy, cfg) }); perr != nil {
				cfg.Logger.Warn("stream handler panicked", "session", sess.ID(), "err", perr)
			}
		}) {
			resetStream(st)
			return nil
		}
	}
}

// reportTransport sends the transport's outcome to the server. A failure
// is logged only: the report is telemetry, and the QUIC connection stands.
func reportTransport(log *slog.Logger, sess *client.Session, ok bool, detail string) {
	if err := sess.ReportTransport(ok, detail); err != nil {
		log.Debug("transport report failed", "session", sess.ID(), "ok", ok, "err", err)
	}
}

// peerClosed reports the dialer's orderly close of the QUIC connection.
func peerClosed(err error) bool {
	var ae *quic.ApplicationError
	return errors.As(err, &ae) && ae.Remote && ae.ErrorCode == codeClosed
}

// serveStream answers one stream: it reads the request, connects the
// target and relays.
func serveStream(ctx context.Context, g *life.Group, conn *Conn, st *quic.Stream, policy proto.AccessPolicy, cfg HostConfig) {
	if err := st.SetDeadline(time.Now().Add(streamSetupTimeout)); err != nil {
		resetStream(st)
		return
	}
	var req streamRequest
	if err := readFrame(st, &req); err != nil {
		resetStream(st)
		return
	}
	target, err := cfg.resolve(req.Target, policy)
	if err != nil {
		cfg.Logger.Info("target refused", "target", req.Target, "err", err)
		refuse(st, refusedNotAllowed)
		return
	}
	tc, err := dialTarget(ctx, cfg, target)
	if err != nil {
		cfg.Logger.Info("target dial failed", "target", target, "err", err)
		refuse(st, refusedUnreachable)
		return
	}
	if !g.Own("quicforward.target", tc) {
		resetStream(st)
		return
	}
	defer g.Disown(tc)
	if err := writeFrame(st, streamAnswer{}); err != nil || st.SetDeadline(time.Time{}) != nil {
		resetStream(st)
		_ = tc.Close()
		return
	}
	sc := newStreamConn(st, conn.qc)
	defer func() { _ = sc.Close() }() // relay closes both; Close is idempotent
	relay(g, sc, tc)
}

// Refusal reasons a host sends: fixed words, the details stay in its log.
const (
	refusedNotAllowed  = "target_not_allowed" // not a target of the host, or not one the session's policy allows
	refusedUnreachable = "target_unreachable" // the host could not connect the target
)

// refuse answers a stream with a refusal and ends it: the answer is sent
// with a clean FIN, and the request side is no longer read.
func refuse(st *quic.Stream, reason string) {
	_ = writeFrame(st, streamAnswer{Error: reason})
	_ = st.Close()
	st.CancelRead(streamCanceled)
}

func dialTarget(ctx context.Context, cfg HostConfig, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()
	var (
		c   net.Conn
		err error
	)
	if perr := life.Safe("quicforward.Dial", func() { c, err = cfg.Dial(ctx, target) }); perr != nil {
		return nil, perr
	}
	if err == nil && life.IsNil(c) {
		err = errors.New("quicforward: Dial returned no connection")
	}
	return c, err
}

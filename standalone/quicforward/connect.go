package quicforward

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/standalone/client"
)

// reopenGap is the shortest time between two attempts to open a session
// after a failed one: local connections arriving meanwhile fail at once.
const reopenGap = time.Second

// ConnectConfig configures the dialer side.
type ConnectConfig struct {
	// Open names the host; its TransportMode and TransportData are replaced
	// by Connect's Identity.
	Open client.OpenRequest
	// Listener accepts the local connections to forward; Connect owns it
	// and closes it when it returns.
	Listener net.Listener
	// Target is the target asked of the host; "" means the host's default.
	Target string
	// Logger receives the forwarding events; nil discards them.
	Logger *slog.Logger
}

// Connect opens a session with the host and forwards every connection
// accepted on cfg.Listener over a new QUIC stream to cfg.Target, until ctx
// ends (nil) or the listener fails. The first session is opened before
// anything is accepted, so that an unreachable host is reported at once;
// when its QUIC connection is lost, the next local connection opens a new
// one. The sessions and the listener are closed when Connect returns.
func Connect(ctx context.Context, c *client.Client, cfg ConnectConfig) error {
	if life.IsNil(cfg.Listener) {
		return errors.New("quicforward: ConnectConfig.Listener is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	id, err := NewIdentity()
	if err != nil {
		_ = cfg.Listener.Close()
		return err
	}
	cfg.Open.TransportMode, cfg.Open.TransportData = Mode, id.TransportData()
	g := life.New(ctx)
	g.Own("quicforward.listener", cfg.Listener)
	d := &dialer{c: c, id: id, req: cfg.Open}
	defer func() {
		d.close()
		_ = g.Close(closeJoin)
	}()
	if _, err := d.get(g.Context()); err != nil {
		return err
	}
	// The listener's Accept does not watch ctx; this closes it when ctx
	// ends, and the goroutine is gone once Connect returns.
	g.Go("quicforward.listener-closer", func(gctx context.Context) {
		<-gctx.Done()
		_ = cfg.Listener.Close()
	})
	for {
		lc, err := cfg.Listener.Accept()
		if err != nil {
			if g.Context().Err() != nil {
				return nil
			}
			return err
		}
		if !g.Go("quicforward.forward", func(gctx context.Context) {
			if perr := life.Safe("quicforward.forward", func() { d.forward(gctx, g, lc, cfg.Target, cfg.Logger) }); perr != nil {
				cfg.Logger.Warn("forward panicked", "err", perr)
			}
		}) {
			_ = lc.Close()
			return nil
		}
	}
}

// forwarding is one session the dialer forwards over.
type forwarding struct {
	sess *client.Session
	conn *Conn
}

func (f *forwarding) alive() bool { return f.conn.qc.Context().Err() == nil }

func (f *forwarding) close() {
	_ = f.conn.Close()
	_ = f.sess.Close()
}

// dialer keeps the current forwarding session, opening a new one when the
// previous connection is gone. One opening runs at a time; the others wait
// for it.
type dialer struct {
	c   *client.Client
	id  *Identity
	req client.OpenRequest

	mu       sync.Mutex
	cur      *forwarding
	opening  chan struct{} // closed when the opening under way ends
	lastErr  error
	failedAt time.Time
	closed   bool
}

// get returns a live forward connection, opening a session if needed.
func (d *dialer) get(ctx context.Context) (*Conn, error) {
	for {
		d.mu.Lock()
		switch {
		case d.closed:
			d.mu.Unlock()
			return nil, net.ErrClosed
		case d.cur != nil && d.cur.alive():
			conn := d.cur.conn
			d.mu.Unlock()
			return conn, nil
		case d.opening != nil:
			wait := d.opening
			d.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case d.lastErr != nil && time.Since(d.failedAt) < reopenGap:
			err := d.lastErr
			d.mu.Unlock()
			return nil, err
		}
		stale := d.cur
		d.cur = nil
		opening := make(chan struct{})
		d.opening = opening
		d.mu.Unlock()
		if stale != nil {
			stale.close()
		}
		f, err := d.open(ctx)
		d.mu.Lock()
		d.opening = nil
		close(opening)
		if err != nil {
			d.lastErr, d.failedAt = err, time.Now()
			d.mu.Unlock()
			return nil, err
		}
		if d.closed {
			d.mu.Unlock()
			f.close()
			return nil, net.ErrClosed
		}
		d.cur, d.lastErr = f, nil
		d.mu.Unlock()
		return f.conn, nil
	}
}

// open opens a session and dials QUIC on it.
func (d *dialer) open(ctx context.Context) (*forwarding, error) {
	sess, err := d.c.Open(ctx, d.req)
	if err != nil {
		return nil, err
	}
	conn, err := Dial(ctx, sess, d.id)
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	return &forwarding{sess: sess, conn: conn}, nil
}

// drop retires conn if it is still the current connection: a stream that
// failed without the host's answer means the connection is unusable even
// if QUIC has not noticed yet, and the next get opens a new session.
func (d *dialer) drop(conn *Conn) {
	d.mu.Lock()
	cur := d.cur
	if cur == nil || cur.conn != conn {
		d.mu.Unlock()
		return
	}
	d.cur = nil
	d.mu.Unlock()
	cur.close()
}

// close closes the current session; later gets fail.
func (d *dialer) close() {
	d.mu.Lock()
	d.closed = true
	cur := d.cur
	d.cur = nil
	d.mu.Unlock()
	if cur != nil {
		cur.close()
	}
}

// forward relays one local connection over a new stream.
func (d *dialer) forward(ctx context.Context, g *life.Group, lc net.Conn, target string, log *slog.Logger) {
	if !g.Own("quicforward.local", lc) {
		return
	}
	defer func() {
		g.Disown(lc)
		_ = lc.Close()
	}()
	conn, err := d.get(ctx)
	if err != nil {
		log.Info("no forward session", "err", err)
		return
	}
	sc, err := conn.OpenStream(ctx, target)
	if err != nil {
		log.Info("stream failed", "target", target, "err", err)
		if !errors.Is(err, ErrRefused) {
			d.drop(conn)
		}
		return
	}
	relay(g, lc, sc)
}

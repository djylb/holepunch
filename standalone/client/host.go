package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/proto"
)

// Backoff of Serve's re-registration: from retryMin doubling to retryMax,
// back to retryMin after a link that lived retryReset.
const (
	retryMin   = time.Second
	retryMax   = 30 * time.Second
	retryReset = time.Minute
)

// Registration registers this client as a host.
type Registration struct {
	HostID   string
	Metadata map[string]string // shown to the dialers
	// TransportMode and TransportData are this side's transport offer for
	// every incoming session (holepunch.Options).
	TransportMode, TransportData string
}

// Handler serves one incoming session. ctx ends when Serve stops or the
// Client is closed; the session is closed when the Handler returns.
type Handler func(ctx context.Context, s *Session)

// link is a registration link.
type link struct {
	conn    net.Conn
	timeout time.Duration // write bound: one heartbeat interval
	done    chan struct{}

	mu sync.Mutex // serialises writes: heartbeats and transport reports
}

func (l *link) write(m proto.Message) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return proto.Write(l.conn, m, l.timeout)
}

// Serve registers reg.HostID and serves every session dialers open with it,
// each on its own goroutine through h, until ctx ends or the Client is
// closed; it then returns nil. A lost link is re-registered with a backoff,
// presenting the last credential. A refusal that retrying cannot cure
// (unauthorized, invalid request, an ID held by someone else) is returned as
// the server's *proto.Fail. Only one Serve may run at a time (ErrServing).
func (c *Client) Serve(ctx context.Context, reg Registration, h Handler) error {
	if h == nil || !proto.ValidName(reg.HostID) {
		return fmt.Errorf("client: Serve needs a handler and a valid host ID: %w", proto.ErrInvalid)
	}
	if err := c.beginServe(); err != nil {
		return err
	}
	defer c.endServe()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !c.group.Go("client.serve-watch", func(gctx context.Context) {
		select {
		case <-gctx.Done():
			cancel()
		case <-sctx.Done():
		}
	}) {
		return ErrClosed
	}
	var credential string
	backoff := retryMin
	for {
		start := time.Now()
		l, regd, err := c.register(sctx, reg, credential)
		if err == nil {
			credential = regd.Credential
			err = c.runLink(sctx, l, regd, reg, h)
			if time.Since(start) >= retryReset {
				backoff = retryMin
			}
		}
		if sctx.Err() != nil {
			return nil
		}
		if permanent(err) {
			return err
		}
		c.log.Info("registration link lost", "host", reg.HostID, "err", err, "retry_in", backoff)
		if !pause(sctx, backoff) {
			return nil
		}
		backoff = min(2*backoff, retryMax)
	}
}

func (c *Client) beginServe() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.group.Context().Err() != nil:
		return ErrClosed
	case c.serving:
		return ErrServing
	}
	c.serving = true
	return nil
}

func (c *Client) endServe() {
	c.mu.Lock()
	c.serving = false
	c.mu.Unlock()
}

// register opens a registration link.
func (c *Client) register(ctx context.Context, reg Registration, credential string) (*link, *proto.Registered, error) {
	hctx, cancel := context.WithTimeout(ctx, c.cfg.HandshakeTimeout)
	defer cancel()
	conn, err := c.dial(hctx)
	if err != nil {
		return nil, nil, err
	}
	m := &proto.Register{HostID: reg.HostID, AuthToken: c.cfg.AuthToken, Credential: credential, Metadata: reg.Metadata}
	if err := proto.Write(conn, m, c.cfg.HandshakeTimeout); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	regd, err := proto.Expect[*proto.Registered](hctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	hb := time.Duration(regd.HeartbeatMs) * time.Millisecond
	return &link{conn: conn, timeout: hb, done: make(chan struct{})}, regd, nil
}

// runLink serves a registration link until it fails or ctx ends. The link
// is read with a deadline of three heartbeat intervals; a heartbeat
// goroutine writes one every interval, and a watcher closes the link when
// ctx or the Client ends.
func (c *Client) runLink(ctx context.Context, l *link, regd *proto.Registered, reg Registration, h Handler) error {
	defer close(l.done)
	defer func() { _ = l.conn.Close() }()
	if !c.setLink(l) {
		return ErrClosed
	}
	defer c.clearLink(l)
	hb := time.Duration(regd.HeartbeatMs) * time.Millisecond
	watch := func(gctx context.Context) {
		select {
		case <-ctx.Done():
		case <-gctx.Done():
		case <-l.done:
		}
		_ = l.conn.Close()
	}
	beat := func(gctx context.Context) {
		t := time.NewTicker(hb)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if l.write(&proto.Heartbeat{}) != nil {
					_ = l.conn.Close()
					return
				}
			case <-l.done:
				return
			case <-gctx.Done():
				return
			}
		}
	}
	if !c.group.Go("client.link-watch", watch) || !c.group.Go("client.heartbeat", beat) {
		return ErrClosed
	}
	c.log.Debug("host registered", "host", reg.HostID)
	for {
		if err := l.conn.SetReadDeadline(time.Now().Add(3 * hb)); err != nil {
			return err
		}
		m, err := proto.Decode(l.conn)
		if err != nil {
			return err
		}
		switch m := m.(type) {
		case *proto.Heartbeat:
		case *proto.Incoming:
			c.incoming(ctx, *m, reg, h)
		default:
			return fmt.Errorf("%w: %v on the registration link", proto.ErrUnexpected, m.Type())
		}
	}
}

func (c *Client) setLink(l *link) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.group.Context().Err() != nil {
		return false
	}
	c.link = l
	return true
}

func (c *Client) clearLink(l *link) {
	c.mu.Lock()
	if c.link == l {
		c.link = nil
	}
	c.mu.Unlock()
}

// report sends a transport report on the current registration link.
func (c *Client) report(t proto.Transport) error {
	c.mu.Lock()
	l := c.link
	c.mu.Unlock()
	if l == nil {
		return ErrNoLink
	}
	return l.write(&t)
}

// incoming joins and serves one session on a goroutine of its own.
func (c *Client) incoming(ctx context.Context, in proto.Incoming, reg Registration, h Handler) {
	c.group.Go("client.session", func(context.Context) {
		if perr := life.Safe("client.session", func() { c.serveIncoming(ctx, in, reg, h) }); perr != nil {
			c.log.Warn("incoming session panicked", "session", in.SessionID, "err", perr)
		}
	})
}

func (c *Client) serveIncoming(ctx context.Context, in proto.Incoming, reg Registration, h Handler) {
	conn, info, err := c.request(ctx, &proto.Join{SessionID: in.SessionID, Ticket: in.Ticket})
	if err != nil {
		c.log.Info("join failed", "session", in.SessionID, "err", err)
		return
	}
	sess, err := c.attach(ctx, conn, info, protocol.RoleResponder, reg.TransportMode, reg.TransportData, c.report)
	if err != nil {
		c.log.Info("punch failed", "session", in.SessionID, "err", err)
		return
	}
	defer func() { _ = sess.Close() }()
	if !c.track(sess) {
		return
	}
	defer c.untrack(sess)
	if perr := life.Safe("client.Handler", func() { h(ctx, sess) }); perr != nil {
		c.log.Warn("handler panicked", "session", sess.ID(), "err", perr)
	}
}

// permanent reports whether err is a refusal of the server that retrying
// cannot cure. err may come from Config.Dial or from its connection, whose
// methods are the caller's code: it is inspected inside a recover boundary,
// and an error that panics there counts as transient.
func permanent(err error) bool {
	var fatal bool
	_ = life.Safe("client.retryable", func() {
		var f *proto.Fail
		fatal = errors.As(err, &f) && !f.Code.Retryable()
	})
	return fatal
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

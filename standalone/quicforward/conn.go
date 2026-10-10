package quicforward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/standalone/client"
)

const (
	// maxDialAttempts bounds the dialer's QUIC handshake attempts within the
	// session's TransportTimeout.
	maxDialAttempts = 3
	// dialRetryDelay separates two attempts.
	dialRetryDelay = 200 * time.Millisecond
	// defaultTransportTimeout applies when the session carries none.
	defaultTransportTimeout = 10 * time.Second
	// defaultIdleTimeout applies when the session has no keepalive advice.
	defaultIdleTimeout = 30 * time.Second
)

// Application error codes of the QUIC connection.
const (
	codeClosed         quic.ApplicationErrorCode = 0
	codeUnexpectedPeer quic.ApplicationErrorCode = 1
)

// Conn is a forward connection: a QUIC connection on a session's punched
// socket together with the QUIC transport that reads the socket. Closing it
// leaves the socket open: the session owns it.
type Conn struct {
	qc *quic.Conn
	tr *quic.Transport

	closeOnce sync.Once
}

// QUIC returns the QUIC connection.
func (c *Conn) QUIC() *quic.Conn { return c.qc }

// Close closes the QUIC connection and stops its transport from reading the
// socket. It is idempotent.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.qc.CloseWithError(codeClosed, "closed")
		_ = c.tr.Close()
	})
	return nil
}

// prepare checks that sess is a pinned QUIC session and returns its peer's
// pin and its raw socket with clear deadlines.
func prepare(sess *client.Session) (holepunch.Result, string, net.PacketConn, error) {
	res := sess.Result()
	if res.TransportMode != Mode {
		return res, "", nil, fmt.Errorf("%w: transport mode %q", ErrTransport, res.TransportMode)
	}
	pin, err := peerPin(res.TransportData)
	if err != nil {
		return res, "", nil, err
	}
	pc := sess.Holepunch().PacketConn()
	if err := pc.SetDeadline(time.Time{}); err != nil {
		return res, "", nil, err
	}
	return res, pin, pc, nil
}

// Accept waits for the dialer's QUIC connection on the host side of sess,
// for at most the session's TransportTimeout. Only a connection from the
// punched peer address whose certificate has the peer's pin is accepted;
// the listener is closed once it is. On failure the QUIC listener and
// transport are closed; the session, and its socket, stay the caller's.
func Accept(ctx context.Context, sess *client.Session, id *Identity) (*Conn, error) {
	res, pin, pc, err := prepare(sess)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: pc}
	ln, err := tr.Listen(id.serverTLS(pin), quicConfig(res))
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("quicforward: listen: %w", err)
	}
	actx, cancel := context.WithTimeout(ctx, transportTimeout(res))
	defer cancel()
	for {
		qc, err := ln.Accept(actx)
		if err != nil {
			_ = ln.Close()
			_ = tr.Close()
			return nil, fmt.Errorf("quicforward: accept: %w", err)
		}
		if sameAddr(qc.RemoteAddr(), res.Path.RemoteAddr) {
			_ = ln.Close()
			return &Conn{qc: qc, tr: tr}, nil
		}
		_ = qc.CloseWithError(codeUnexpectedPeer, "unexpected peer")
	}
}

// Dial connects QUIC to the host side of sess within the session's
// TransportTimeout, in at most three attempts; it stops at once when the
// socket is closed or the host's certificate does not have its pin. On
// failure the QUIC transport is closed; the session stays the caller's.
func Dial(ctx context.Context, sess *client.Session, id *Identity) (*Conn, error) {
	res, pin, pc, err := prepare(sess)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: pc}
	dctx, cancel := context.WithTimeout(ctx, transportTimeout(res))
	defer cancel()
	remote := net.UDPAddrFromAddrPort(res.Path.RemoteAddr)
	var last error
	for attempt := 1; ; attempt++ {
		qc, err := tr.Dial(dctx, remote, id.clientTLS(pin), quicConfig(res))
		if err == nil {
			return &Conn{qc: qc, tr: tr}, nil
		}
		last = err
		if attempt >= maxDialAttempts || dctx.Err() != nil || final(err) || !pause(dctx, dialRetryDelay) {
			break
		}
	}
	_ = tr.Close()
	return nil, fmt.Errorf("quicforward: dial %v: %w", res.Path.RemoteAddr, last)
}

// final reports a dial error that another attempt cannot cure: a closed
// socket or transport, or a TLS failure such as a pin mismatch.
func final(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	var te *quic.TransportError
	return errors.As(err, &te) && te.ErrorCode.IsCryptoError()
}

func quicConfig(res holepunch.Result) *quic.Config {
	idle := res.Path.Keepalive.Timeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	keepalive := res.Path.Keepalive.Interval
	if keepalive <= 0 || keepalive >= idle {
		keepalive = idle / 3
	}
	return &quic.Config{
		HandshakeIdleTimeout: transportTimeout(res),
		MaxIdleTimeout:       idle,
		KeepAlivePeriod:      keepalive,
	}
}

func transportTimeout(res holepunch.Result) time.Duration {
	if res.TransportTimeout > 0 {
		return res.TransportTimeout
	}
	return defaultTransportTimeout
}

// sameAddr compares a socket address with the punched peer address.
func sameAddr(a net.Addr, want netip.AddrPort) bool {
	if a == nil {
		return false
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return false
	}
	return ap.Addr().Unmap() == want.Addr().Unmap() && ap.Port() == want.Port()
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

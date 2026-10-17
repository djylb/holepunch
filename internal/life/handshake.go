package life

import (
	"context"
	"time"
)

// TLSConn is a TLS connection whose handshake can be run, as *tls.Conn's.
type TLSConn interface {
	SetDeadline(t time.Time) error
	Handshake() error
}

// Handshake runs c's handshake within timeout and until ctx ends, without
// letting either close c, as tls.Conn.HandshakeContext would: it bounds the
// handshake with c's deadline, moves that deadline into the past when ctx
// ends, and clears it afterwards. A failed handshake leaves c unusable but
// open, its owner's to close. The caller runs it inside a recover boundary:
// c's methods are its owner's code.
func Handshake(ctx context.Context, c TLSConn, timeout time.Duration) error {
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = Safe("handshake-interrupt", func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	})
	err := c.Handshake()
	if !stop() {
		<-done
	}
	if cerr := c.SetDeadline(time.Time{}); err == nil {
		err = cerr
	}
	return err
}

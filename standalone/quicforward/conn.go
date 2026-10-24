package quicforward

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/quic-go/quic-go"

	"github.com/djylb/holepunch/quicpath"
	"github.com/djylb/holepunch/standalone/client"
)

// Conn is a forward connection: a quicpath pipe on the primary path of a
// session's punched socket.
type Conn struct {
	pipe *quicpath.Conn
	qc   *quic.Conn
}

// QUIC returns the QUIC connection.
func (c *Conn) QUIC() *quic.Conn { return c.qc }

// alive reports whether the QUIC connection is still up.
func (c *Conn) alive() bool { return c.pipe.Err() == nil }

// Close closes the QUIC connection, its transport and the session's
// socket, releasing a port mapping. It is idempotent.
func (c *Conn) Close() error { return c.pipe.Close() }

// tlsConfig checks that sess is a pinned QUIC session and returns this
// side's TLS configuration, which pins the peer's certificate.
func tlsConfig(sess *client.Session, id *Identity) (*tls.Config, error) {
	res := sess.Result()
	if res.TransportMode != Mode {
		return nil, fmt.Errorf("%w: transport mode %q", ErrTransport, res.TransportMode)
	}
	conf, err := id.TLSConfig(res)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	return conf, nil
}

// Accept waits for the dialer's QUIC connection on the host side of sess,
// for at most the session's TransportTimeout. Only a connection from the
// punched peer address whose certificate has the peer's pin is accepted;
// the listener is closed once it is. On failure the QUIC listener and
// transport are closed; the session, and its socket, stay the caller's. On
// success the Conn owns the session's socket.
func Accept(ctx context.Context, sess *client.Session, id *Identity) (*Conn, error) {
	conf, err := tlsConfig(sess, id)
	if err != nil {
		return nil, err
	}
	pipe, err := quicpath.Accept(ctx, sess.Holepunch(), conf, nil)
	if err != nil {
		return nil, fmt.Errorf("quicforward: accept: %w", err)
	}
	return &Conn{pipe: pipe, qc: pipe.QUIC()}, nil
}

// Dial connects QUIC to the host side of sess within the session's
// TransportTimeout, in at most three attempts; it stops at once when the
// socket is closed or the host's certificate does not have its pin. On
// failure the QUIC transport is closed; the session stays the caller's. On
// success the Conn owns the session's socket.
func Dial(ctx context.Context, sess *client.Session, id *Identity) (*Conn, error) {
	conf, err := tlsConfig(sess, id)
	if err != nil {
		return nil, err
	}
	pipe, err := quicpath.Dial(ctx, sess.Holepunch(), conf, nil)
	if err != nil {
		return nil, fmt.Errorf("quicforward: %w", err)
	}
	return &Conn{pipe: pipe, qc: pipe.QUIC()}, nil
}

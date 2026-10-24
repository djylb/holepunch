package quicpath

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	"github.com/djylb/holepunch"
)

// Application error codes of the QUIC connections.
const (
	codeClosed         quic.ApplicationErrorCode = 0 // a local Close
	codeUnexpectedPeer quic.ApplicationErrorCode = 1 // not the peer of the path
	codeSuperseded     quic.ApplicationErrorCode = 2 // a newer connection of the peer on the same path
)

// Why a pipe died (Conn.Err). Each wraps quic-go's own error, which stays
// reachable with errors.As.
var (
	// ErrClosed means the pipe was closed on this side — Conn.Close,
	// Endpoint.Close, a CloseWithError on the QUIC connection, or its
	// socket was closed.
	ErrClosed = errors.New("quicpath: closed")
	// ErrPeerClosed means the peer closed the connection, or reset it after
	// losing its state.
	ErrPeerClosed = errors.New("quicpath: closed by the peer")
	// ErrIdleTimeout means nothing arrived from the peer for the idle
	// timeout: the path died, or the peer vanished without closing.
	ErrIdleTimeout = errors.New("quicpath: path idle timeout")
)

// Conn is one pipe: a QUIC connection on one confirmed path of a session.
type Conn struct {
	qc   *quic.Conn
	path holepunch.Path
	ep   *Endpoint
	own  bool // Close closes ep too: the Conn of Dial or Accept

	closeOnce sync.Once
	closeErr  error
}

// QUIC returns the QUIC connection, for streams and datagrams.
func (c *Conn) QUIC() *quic.Conn { return c.qc }

// Path returns the path the pipe runs on.
func (c *Conn) Path() holepunch.Path { return c.path }

// Done returns a channel that is closed when the pipe dies, for whatever
// reason (Err).
func (c *Conn) Done() <-chan struct{} { return c.qc.Context().Done() }

// Err returns nil while the pipe is alive and, once Done is closed, why it
// died: an error wrapping ErrIdleTimeout, ErrPeerClosed or ErrClosed, or
// quic-go's error as is for any other cause.
func (c *Conn) Err() error {
	ctx := c.qc.Context()
	if ctx.Err() == nil {
		return nil
	}
	return classify(context.Cause(ctx))
}

// Close closes the QUIC connection, telling the peer. The Conn of Dial or
// Accept then closes the QUIC transport and the Session, releasing its port
// mappings, and returns the Session's error; a Conn of an Endpoint leaves
// both to the Endpoint. Close is idempotent.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.qc.CloseWithError(codeClosed, "closed")
		c.ep.untrack(c)
		if c.own {
			c.closeErr = c.ep.Close()
		}
	})
	return c.closeErr
}

// classify maps the cause of a QUIC connection's end to the package's
// errors.
func classify(cause error) error {
	var (
		ae *quic.ApplicationError
		te *quic.TransportError
		it *quic.IdleTimeoutError
		sr *quic.StatelessResetError
	)
	switch {
	case cause == nil:
		return ErrClosed
	case errors.As(cause, &it):
		return fmt.Errorf("%w: %w", ErrIdleTimeout, cause)
	case errors.As(cause, &ae) && !ae.Remote:
		return fmt.Errorf("%w: %w", ErrClosed, cause)
	case errors.As(cause, &ae), errors.As(cause, &te) && te.Remote, errors.As(cause, &sr):
		return fmt.Errorf("%w: %w", ErrPeerClosed, cause)
	case te == nil && errors.Is(cause, net.ErrClosed): // quic-go's own errors match net.ErrClosed too
		return fmt.Errorf("%w: %w", ErrClosed, cause)
	default:
		return cause
	}
}

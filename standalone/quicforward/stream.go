package quicforward

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/djylb/holepunch/internal/life"
)

const (
	// maxStreamFrame bounds a stream's request and answer.
	maxStreamFrame = 1024
	// streamSetupTimeout bounds a stream's request, the target dial and the
	// answer, when the caller's context does not bound them sooner.
	streamSetupTimeout = 15 * time.Second
	// streamCanceled is the stream error code of an aborted relay.
	streamCanceled quic.StreamErrorCode = 1
)

// streamRequest opens a forward stream (dialer → host).
type streamRequest struct {
	Target string `json:"target,omitempty"` // "" means the host's default target
}

// streamAnswer answers it (host → dialer); an empty Error means the target
// is connected and the relay begins.
type streamAnswer struct {
	Error string `json:"error,omitempty"`
}

// ErrRefused is the error of a stream the host refused; the host's reason
// follows it.
var ErrRefused = errors.New("quicforward: host refused the stream")

// writeFrame writes v as a 2-byte big-endian length and its JSON.
func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxStreamFrame {
		return fmt.Errorf("quicforward: stream frame of %d bytes", len(b))
	}
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(b)), uint16(len(b)))
	_, err = w.Write(append(frame, b...))
	return err
}

// readFrame reads one frame into v.
func readFrame(r io.Reader, v any) error {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > maxStreamFrame {
		return fmt.Errorf("quicforward: stream frame of %d bytes", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// OpenStream opens a forward stream to target ("" for the host's default
// target) and returns it once the host has connected the target. A refusal
// wraps ErrRefused. ctx bounds the whole setup, within streamSetupTimeout.
func (c *Conn) OpenStream(ctx context.Context, target string) (net.Conn, error) {
	sc, _, err := c.openStream(ctx, target)
	return sc, err
}

// openStream is OpenStream. unanswered reports a failure after the stream
// was opened and before the host answered, which a connection that still
// works does not produce; waiting for a stream that the peer's stream limit
// does not grant yet is no such failure.
func (c *Conn) openStream(ctx context.Context, target string) (_ net.Conn, unanswered bool, _ error) {
	ctx, cancel := context.WithTimeout(ctx, streamSetupTimeout)
	defer cancel()
	st, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, false, err
	}
	sc := newStreamConn(st, c.qc)
	ans, err := request(ctx, st, target)
	if err != nil {
		_ = sc.Close()
		return nil, true, err
	}
	if ans.Error != "" {
		_ = sc.Close()
		return nil, false, fmt.Errorf("%w: %s", ErrRefused, ans.Error)
	}
	return sc, false, nil
}

// request writes a stream's request and reads the host's answer within ctx,
// whose end interrupts the wait; the stream is left without deadlines.
func request(ctx context.Context, st *quic.Stream, target string) (streamAnswer, error) {
	var ans streamAnswer
	deadline, _ := ctx.Deadline()
	if err := st.SetWriteDeadline(deadline); err != nil {
		return ans, err
	}
	if err := writeFrame(st, streamRequest{Target: target}); err != nil {
		return ans, err
	}
	if err := st.SetWriteDeadline(time.Time{}); err != nil {
		return ans, err
	}
	restore := life.InterruptRead(ctx, st)
	err := readFrame(st, &ans)
	if rerr := restore(); err == nil {
		err = rerr
	}
	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	return ans, err
}

// streamConn presents a QUIC stream as a net.Conn with half-closes.
type streamConn struct {
	*quic.Stream
	qc *quic.Conn

	finSent, eofRead atomic.Bool
	closeOnce        sync.Once
}

func newStreamConn(st *quic.Stream, qc *quic.Conn) *streamConn {
	return &streamConn{Stream: st, qc: qc}
}

// Read reads the stream and notes its clean end.
func (s *streamConn) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	if errors.Is(err, io.EOF) {
		s.eofRead.Store(true)
	}
	return n, err
}

// CloseWrite ends the sending direction cleanly (FIN).
func (s *streamConn) CloseWrite() error {
	s.finSent.Store(true)
	return s.Stream.Close()
}

// Close releases a stream that ended cleanly both ways and resets every
// other: a reset after the FIN would discard data the peer has not read.
func (s *streamConn) Close() error {
	s.closeOnce.Do(func() {
		if s.finSent.Load() && s.eofRead.Load() {
			return
		}
		resetStream(s.Stream)
	})
	return nil
}

// resetStream aborts both directions of st.
func resetStream(st *quic.Stream) {
	st.CancelRead(streamCanceled)
	st.CancelWrite(streamCanceled)
}

// LocalAddr returns the QUIC connection's local address.
func (s *streamConn) LocalAddr() net.Addr { return s.qc.LocalAddr() }

// RemoteAddr returns the QUIC connection's remote address.
func (s *streamConn) RemoteAddr() net.Addr { return s.qc.RemoteAddr() }

// relay copies a↔b until both directions end, then closes both. A
// direction that ends cleanly half-closes its destination; one that fails
// aborts both connections, which ends the other direction too. The second
// direction runs on a goroutine of g.
func relay(g *life.Group, a, b net.Conn) {
	abort := func() {
		_ = a.Close()
		_ = b.Close()
	}
	done := make(chan struct{})
	if !g.Go("quicforward.relay", func(context.Context) {
		defer close(done)
		pipe(a, b, abort)
	}) {
		abort()
		return
	}
	pipe(b, a, abort)
	<-done
	abort()
}

// pipe copies src to dst.
func pipe(dst, src net.Conn, abort func()) {
	if _, err := io.Copy(dst, src); err != nil {
		abort()
		return
	}
	cw, ok := dst.(interface{ CloseWrite() error })
	if !ok || cw.CloseWrite() != nil {
		abort()
	}
}

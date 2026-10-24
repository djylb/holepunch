package controlwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/internal/wiretype"
)

func TestMain(m *testing.M) { goroutines.VerifyTestMain(m) }

// memConn is a net.Conn whose reads come from a fixed byte stream (optionally
// in small chunks) and whose writes are discarded. Deadlines are accepted and
// ignored: reads never block.
type memConn struct {
	r     *bytes.Reader
	chunk int
}

func newMemConn(data []byte, chunk int) *memConn {
	return &memConn{r: bytes.NewReader(data), chunk: chunk}
}

func (m *memConn) Read(p []byte) (int, error) {
	if m.chunk > 0 && len(p) > m.chunk {
		p = p[:m.chunk]
	}
	return m.r.Read(p)
}
func (m *memConn) Write(p []byte) (int, error)      { return len(p), nil }
func (m *memConn) Close() error                     { return nil }
func (m *memConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (m *memConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (m *memConn) SetDeadline(time.Time) error      { return nil }
func (m *memConn) SetReadDeadline(time.Time) error  { return nil }
func (m *memConn) SetWriteDeadline(time.Time) error { return nil }

func mustConn(t testing.TB, nc net.Conn, opts ConnOptions) *Conn {
	t.Helper()
	c, err := NewConn(nc, opts)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		if s := c.g.Stats(); s.Running != 0 || s.Leaked != 0 || s.Panics != 0 {
			t.Errorf("conn goroutines after Close: %+v", s)
		}
	})
	return c
}

// rawFrame encodes a frame with an arbitrary major version and length field.
func rawFrame(major uint8, t Type, payload string) []byte {
	b := []byte{'h', 'p', major, byte(t), 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[4:], uint32(len(payload)))
	return append(b, payload...)
}

func frameBytes(t Type, payload string) []byte { return rawFrame(wiretype.Version, t, payload) }

// readFrames reads n complete frames from r.
func readFrames(t testing.TB, r io.Reader, n int) []Frame {
	t.Helper()
	out := make([]Frame, 0, n)
	for len(out) < n {
		var h [HeaderSize]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			t.Fatalf("peer: header of frame %d: %v", len(out), err)
		}
		typ, size, err := ParseHeader(h, nil)
		if err != nil {
			t.Fatalf("peer: frame %d: %v", len(out), err)
		}
		p := make([]byte, size)
		if _, err := io.ReadFull(r, p); err != nil {
			t.Fatalf("peer: payload of frame %d: %v", len(out), err)
		}
		out = append(out, Frame{Type: typ, Payload: p})
	}
	return out
}

func payloadsOf(frames []Frame) []string {
	out := make([]string, len(frames))
	for i, f := range frames {
		out[i] = string(f.Payload)
	}
	return out
}

// within runs fn and fails if it does not return within d.
func within[T any](t testing.TB, what string, d time.Duration, fn func() T) T {
	t.Helper()
	ch := make(chan T, 1)
	go func() { ch <- fn() }()
	var v T
	select {
	case v = <-ch:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
	return v
}

func isTimeout(err error) bool { return errors.Is(err, os.ErrDeadlineExceeded) }

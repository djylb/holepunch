package controlwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// event is one call the library made on a recorded connection.
type event struct {
	op string    // "read", "write", "rdl", "wdl", "close"
	t  time.Time // deadline argument for rdl/wdl
	at time.Time // when the call started
}

// recConn wraps a net.Conn, counts and records every call, and lets tests
// inject faults per call.
type recConn struct {
	net.Conn

	reads, writes, setRead, setWrite atomic.Int64

	mu     sync.Mutex
	events []event

	// Hooks run before the call is forwarded; a hook may block or panic.
	onRead     func(p []byte)
	onWrite    func(p []byte)
	onSetWrite func(t time.Time)
	onSetRead  func(t time.Time)
}

func (c *recConn) record(op string, t time.Time) {
	c.mu.Lock()
	c.events = append(c.events, event{op: op, t: t, at: time.Now()})
	c.mu.Unlock()
}

func (c *recConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	c.record("read", time.Time{})
	if c.onRead != nil {
		c.onRead(p)
	}
	return c.Conn.Read(p)
}

func (c *recConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	c.record("write", time.Time{})
	if c.onWrite != nil {
		c.onWrite(p)
	}
	return c.Conn.Write(p)
}

func (c *recConn) SetReadDeadline(t time.Time) error {
	c.setRead.Add(1)
	c.record("rdl", t)
	if c.onSetRead != nil {
		c.onSetRead(t)
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *recConn) SetWriteDeadline(t time.Time) error {
	c.setWrite.Add(1)
	c.record("wdl", t)
	if c.onSetWrite != nil {
		c.onSetWrite(t)
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *recConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *recConn) snapshot() []event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event(nil), c.events...)
}

// eventsAfter returns the calls that started after t.
func (c *recConn) eventsAfter(t time.Time) []event {
	var out []event
	for _, e := range c.snapshot() {
		if e.at.After(t) {
			out = append(out, e)
		}
	}
	return out
}

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

func frameBytes(t Type, payload string) []byte { return rawFrame(Version, t, payload) }

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

func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
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

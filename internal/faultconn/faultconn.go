// Package faultconn wraps a net.Conn for the robustness tests of control
// links: faults armed on the whole connection (writes that fail, writes
// that block until Close whatever the deadline, no deadline support), hooks
// run inside Write and SetWriteDeadline (which may block or panic), counters
// of the calls the code under test made and an optional log of them.
//
// A Conn is safe for concurrent use. It owns nothing but the wrapped
// connection, which Close closes. It is test support only, never imported
// by library code.
package faultconn

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrNoDeadline is returned by the deadline methods of a Conn without
// deadline support.
var ErrNoDeadline = errors.New("faultconn: deadlines unsupported")

// Op names a call in the log of a Conn.
type Op string

// The calls a Conn logs. SetDeadline is logged as its two halves.
const (
	OpRead             Op = "read"
	OpWrite            Op = "write"
	OpSetReadDeadline  Op = "rdl"
	OpSetWriteDeadline Op = "wdl"
)

// Event is one logged call.
type Event struct {
	Op       Op
	Deadline time.Time // the argument of a deadline call
	At       time.Time // when the call started
}

// Conn is a net.Conn with injectable faults.
type Conn struct {
	net.Conn

	mu        sync.Mutex
	f         faults
	recording bool
	events    []Event

	closed chan struct{}
	once   sync.Once

	reads, readReturns, writes, readDeadlines, writeDeadlines atomic.Int64
}

// faults are the faults and hooks armed on a Conn.
type faults struct {
	writeErr    error
	blockWrites bool
	noDeadline  bool
	onWrite     func(p []byte)
	onWriteDL   func(t time.Time)
}

// Wrap returns c with no fault armed.
func Wrap(c net.Conn) *Conn { return &Conn{Conn: c, closed: make(chan struct{})} }

// FailWrites makes every later Write return err.
func (c *Conn) FailWrites(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.f.writeErr = err
}

// BlockWrites makes every later Write block until Close, ignoring deadlines.
func (c *Conn) BlockWrites() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.f.blockWrites = true
}

// NoDeadlines makes SetDeadline, SetReadDeadline and SetWriteDeadline fail.
func (c *Conn) NoDeadlines() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.f.noDeadline = true
}

// OnWrite makes every later Write call fn with its bytes first, before the
// armed faults. fn may block or panic.
func (c *Conn) OnWrite(fn func(p []byte)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.f.onWrite = fn
}

// OnSetWriteDeadline makes every later SetWriteDeadline call fn with its
// deadline first. fn may block or panic.
func (c *Conn) OnSetWriteDeadline(fn func(t time.Time)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.f.onWriteDL = fn
}

// Record starts the log of Read, Write and deadline calls that EventsAfter
// returns.
func (c *Conn) Record() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recording = true
}

// EventsAfter returns the logged calls that started after t.
func (c *Conn) EventsAfter(t time.Time) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Event
	for _, e := range c.events {
		if e.At.After(t) {
			out = append(out, e)
		}
	}
	return out
}

// Reads is the number of Read calls made, including one still blocked.
func (c *Conn) Reads() int64 { return c.reads.Load() }

// ReadReturns is the number of Read calls that returned.
func (c *Conn) ReadReturns() int64 { return c.readReturns.Load() }

// Writes is the number of Write calls made.
func (c *Conn) Writes() int64 { return c.writes.Load() }

// ReadDeadlines is the number of SetReadDeadline calls, SetDeadline
// included.
func (c *Conn) ReadDeadlines() int64 { return c.readDeadlines.Load() }

// WriteDeadlines is the number of SetWriteDeadline calls, SetDeadline
// included.
func (c *Conn) WriteDeadlines() int64 { return c.writeDeadlines.Load() }

// start logs a call and returns the faults armed for it.
func (c *Conn) start(op Op, deadline time.Time) faults {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recording {
		c.events = append(c.events, Event{Op: op, Deadline: deadline, At: time.Now()})
	}
	return c.f
}

// Read implements net.Conn.
func (c *Conn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	c.start(OpRead, time.Time{})
	n, err := c.Conn.Read(p)
	c.readReturns.Add(1)
	return n, err
}

// Write implements net.Conn with the armed faults.
func (c *Conn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	f := c.start(OpWrite, time.Time{})
	if f.onWrite != nil {
		f.onWrite(p)
	}
	switch {
	case f.writeErr != nil:
		return 0, f.writeErr
	case f.blockWrites:
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

// Close implements net.Conn; it releases blocked writes.
func (c *Conn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// SetDeadline implements net.Conn as SetReadDeadline and then
// SetWriteDeadline.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadlines.Add(1)
	if c.start(OpSetReadDeadline, t).noDeadline {
		return ErrNoDeadline
	}
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadlines.Add(1)
	f := c.start(OpSetWriteDeadline, t)
	if f.onWriteDL != nil {
		f.onWriteDL(t)
	}
	if f.noDeadline {
		return ErrNoDeadline
	}
	return c.Conn.SetWriteDeadline(t)
}

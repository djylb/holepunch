// Package faultconn wraps a net.Conn with the faults coord's robustness tests
// inject on the server side of a control link:
// writes that fail, writes that block until Close whatever the deadline,
// a close after the n-th write, connections without deadline support, and
// counters of the calls the coordinator made.
//
// A Conn is safe for concurrent use. It owns nothing but the wrapped
// connection, which Close closes.
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

// Conn is a net.Conn with injectable faults.
type Conn struct {
	net.Conn

	mu          sync.Mutex
	writeErr    error
	blockWrites bool
	closeAfter  int // close after this many writes; 0: never
	writes      int
	noDeadline  bool

	closed chan struct{}
	once   sync.Once

	reads, readDeadlines, writeCalls atomic.Int64
}

// Wrap returns c with no fault armed.
func Wrap(c net.Conn) *Conn { return &Conn{Conn: c, closed: make(chan struct{})} }

// FailWrites makes every later Write return err.
func (c *Conn) FailWrites(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeErr = err
}

// BlockWrites makes every later Write block until Close, ignoring deadlines.
func (c *Conn) BlockWrites() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockWrites = true
}

// CloseAfterWrites closes the connection right after the n-th Write.
func (c *Conn) CloseAfterWrites(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeAfter = n
}

// NoDeadlines makes SetDeadline, SetReadDeadline and SetWriteDeadline fail.
func (c *Conn) NoDeadlines() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noDeadline = true
}

// Reads is the number of Read calls that returned.
func (c *Conn) Reads() int64 { return c.reads.Load() }

// ReadDeadlines is the number of SetReadDeadline calls.
func (c *Conn) ReadDeadlines() int64 { return c.readDeadlines.Load() }

// Writes is the number of Write calls.
func (c *Conn) Writes() int64 { return c.writeCalls.Load() }

// Read implements net.Conn.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.reads.Add(1)
	return n, err
}

// Write implements net.Conn with the armed faults.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeCalls.Add(1)
	c.mu.Lock()
	err, block := c.writeErr, c.blockWrites
	c.writes++
	closeNow := c.closeAfter > 0 && c.writes >= c.closeAfter
	c.mu.Unlock()
	switch {
	case err != nil:
		return 0, err
	case block:
		<-c.closed
		return 0, net.ErrClosed
	}
	n, werr := c.Conn.Write(p)
	if closeNow {
		_ = c.Close()
	}
	return n, werr
}

// Close implements net.Conn; it releases blocked writes.
func (c *Conn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// SetDeadline implements net.Conn.
func (c *Conn) SetDeadline(t time.Time) error {
	if c.deadlineless() {
		return ErrNoDeadline
	}
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadlines.Add(1)
	if c.deadlineless() {
		return ErrNoDeadline
	}
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.deadlineless() {
		return ErrNoDeadline
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *Conn) deadlineless() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.noDeadline
}

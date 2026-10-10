package controlwire

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/djylb/holepunch/internal/life"
)

// Release stops the Conn and hands the connection back to the caller
// without closing it:
//
//  1. The write queues stop accepting frames and drop the frames that have
//     not started (their WriteFrame callers get ErrDropped); the reader will
//     not start another frame.
//  2. Grace: the frame being written and the frame being read may run to
//     their end for at most 50 ms, so that the stream is handed back at a
//     frame boundary.
//  3. Interrupt: the write deadline is moved into the past if a write is
//     still running, ordered against the writer's per-frame deadline so that
//     the writer can neither push it back nor start another Write; the read is
//     interrupted once through life.InterruptRead, and the reader issues no
//     further Read.
//  4. The two goroutines are joined with a bound.
//  5. The read and write deadlines are cleared.
//
// When Release returns nil, the stream is at a frame boundary in both
// directions, both deadlines are zero and the library will never use the
// connection again. ErrUnreturnable means the stream was cut inside a frame,
// clearing a deadline failed, a goroutine (blocked in Intercept, or in a
// connection that ignores deadlines) did not stop in time, or Release itself
// panicked (the error also matches the *life.PanicError); in the
// goroutine and panic cases the deadlines may be left in the past. Either way
// the library starts no further call on the connection, and the caller must
// close it.
//
// Release is idempotent and safe for concurrent use; all callers get the
// first result. After Close it returns net.ErrClosed. It must not be called
// from Intercept.
func (c *Conn) Release() error { return c.terminate(termRelease, c.release) }

// Close stops the Conn and closes the connection; it is for owners of the
// connection such as the coordinator, whose reads end with net.ErrClosed. It
// returns the error from closing (net.ErrClosed ignored), or a
// *life.PanicError if it panicked (the connection is closed all the same), is
// idempotent and safe for concurrent use, and returns ErrReleased after
// Release.
func (c *Conn) Close() error { return c.terminate(termClose, c.closeConn) }

// termMode is the terminal operation that stopped a Conn.
type termMode uint8

const (
	termRelease termMode = iota + 1
	termClose
)

// cause is the error a stopped Conn reports for mode: ErrReleased after
// Release, net.ErrClosed after Close.
func (m termMode) cause() error {
	if m == termRelease {
		return ErrReleased
	}
	return net.ErrClosed
}

// terminate runs the first terminal operation, Release or Close, and gives
// every caller its result. done is closed in a defer and a panic in run is
// recovered: a defect in run can neither leave
// later callers waiting forever, nor reach the caller, nor pass for a clean
// stop. halt then stops whatever run left running, and the panic is the
// result — for Release wrapped in ErrUnreturnable, since the stream was not
// handed back. A caller of the other operation gets the first one's cause.
func (c *Conn) terminate(mode termMode, run func() error) error {
	c.term.once.Do(func() {
		defer close(c.term.done)
		c.term.mode = mode
		perr := life.Safe("controlwire:terminate", func() { c.term.err = run() })
		if perr == nil {
			return
		}
		c.term.err = perr
		if mode == termRelease {
			c.term.err = fmt.Errorf("%w: %w", ErrUnreturnable, perr)
		}
		_ = life.Safe("controlwire:halt", func() { c.halt(mode) })
	})
	<-c.term.done
	if c.term.mode != mode {
		return c.term.mode.cause()
	}
	return c.term.err
}

// halt is terminate's backstop after run panicked. Every step is idempotent,
// so it may repeat what run already did: Done closes, the queues stop and
// wake their waiters, neither goroutine starts another Read or Write, both
// blocking calls are interrupted, Close's connection is closed, and the
// goroutines are joined with the usual bound. As in release, the read
// interrupt is only unregistered once both goroutines are gone.
func (c *Conn) halt(mode termMode) {
	cause := mode.cause()
	c.fail(cause)
	c.stopQueues(cause)
	c.stopReadingAtBoundary(cause)
	c.rmu.Lock()
	c.rhard = true
	c.rmu.Unlock()
	c.interruptWrite()
	c.interrupt()
	if mode == termClose {
		_ = life.Safe("controlwire:close", func() { _ = c.nc.Close() })
	}
	_ = c.g.Close(releaseJoin)
	if c.g.Stats().Leaked == 0 {
		_ = c.restoreRead()
	}
}

func (c *Conn) release() error {
	c.fail(ErrReleased)

	// 1. Stop taking work.
	c.stopQueues(ErrReleased)
	flight := c.flightChan()
	boundary := c.stopReadingAtBoundary(ErrReleased)

	// 2. Grace for the frames in progress, shared by both directions.
	grace, cancel := context.WithTimeout(context.Background(), releaseGrace)
	defer cancel()
	if flight != nil {
		select {
		case <-flight:
		case <-grace.Done():
		}
	}
	if boundary != nil {
		select {
		case <-boundary:
		case <-grace.Done():
		}
	}

	// 3. Interrupt whatever is still blocked.
	c.interruptWrite()
	c.rmu.Lock()
	c.rhard = true
	c.rmu.Unlock()
	c.interrupt()

	// 4. Bounded join.
	_ = c.g.Close(releaseJoin)
	if c.g.Stats().Leaked > 0 {
		// The stuck goroutine may still return from its current call; the
		// past deadlines make any Read or Write it could reach return at
		// once, and its stop checks keep it from starting new ones. Clearing
		// the deadlines now could let it block on the caller's connection.
		return fmt.Errorf("%w: a control goroutine did not stop within %v", ErrUnreturnable, releaseJoin)
	}

	// 5. Hand the deadlines back cleared.
	rerr := c.restoreRead()
	var werr error
	if perr := life.Safe("controlwire:clear-write-deadline", func() { werr = c.nc.SetWriteDeadline(time.Time{}) }); perr != nil {
		werr = perr
	}
	if !c.atBoundary() {
		return fmt.Errorf("%w: stream stopped inside a frame", ErrUnreturnable)
	}
	if err := errors.Join(rerr, werr); err != nil {
		return fmt.Errorf("%w: clearing deadlines: %w", ErrUnreturnable, err)
	}
	return nil
}

func (c *Conn) closeConn() error {
	c.fail(net.ErrClosed)
	c.stopQueues(net.ErrClosed)
	c.stopReadingAtBoundary(net.ErrClosed)
	c.rmu.Lock()
	c.rhard = true
	c.rmu.Unlock()
	c.dmu.Lock()
	c.dstop = true
	c.dmu.Unlock()

	var err error
	if perr := life.Safe("controlwire:close", func() { err = c.nc.Close() }); perr != nil {
		err = perr
	}
	_ = c.g.Close(releaseJoin)
	// Unregister the read interrupt; it is not needed once the connection is
	// closed, and leaving it armed would let it run after Close returns.
	_ = c.restoreRead()
	c.interrupt()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return err
}

// flightChan returns the completion channel of the frame being written, or
// nil when the writer is idle.
func (c *Conn) flightChan() <-chan struct{} {
	c.qmu.Lock()
	defer c.qmu.Unlock()
	if c.flight == nil {
		return nil
	}
	return c.flightDone
}

// stopReadingAtBoundary tells the reader not to start another frame and
// returns a channel closed when it reaches the end of the frame it is in, or
// nil when it is already at a boundary (or no longer running). It is
// idempotent, for halt: only the first cause is kept.
func (c *Conn) stopReadingAtBoundary(cause error) <-chan struct{} {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if !c.rsoft {
		c.stopErr = cause
		c.rsoft = true
		close(c.rstop)
	}
	select {
	case <-c.readDone:
		return nil
	default:
	}
	if !c.rmid {
		return nil
	}
	if c.rbound == nil {
		c.rbound = make(chan struct{})
	}
	return c.rbound
}

// interruptWrite forbids further writes and interrupts a Write in progress
// (see writeOut for why this cannot be undone by the writer's own deadline).
func (c *Conn) interruptWrite() {
	c.dmu.Lock()
	c.dstop = true
	writing := c.writing
	c.dmu.Unlock()
	if writing {
		_ = life.Safe("controlwire:interrupt-write", func() { _ = c.nc.SetWriteDeadline(time.Unix(1, 0)) })
	}
}

// atBoundary reports whether both directions stopped between frames.
func (c *Conn) atBoundary() bool {
	c.rmu.Lock()
	mid := c.rmid
	c.rmu.Unlock()
	c.dmu.Lock()
	dirty := c.wdirty
	c.dmu.Unlock()
	return !mid && !dirty
}

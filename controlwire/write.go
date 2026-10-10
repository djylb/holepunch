package controlwire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
)

// outFrame is a frame in a write queue.
type outFrame struct {
	typ      Type
	payload  []byte
	build    func(now time.Time) ([]byte, error) // SendFunc: payload built right before writing
	key      string                              // SendCoalesced key
	seq      uint64                              // enqueue order, for Flush
	deadline time.Time                           // WriteFrame: absolute deadline
	done     chan error                          // WriteFrame: completion (buffered, written once)
}

// Send queues f without blocking; the writing goroutine writes it with a
// per-frame deadline. Frames go out by priority — P0 pong, P1 ping and the
// reliable protocol frames, P2 punch_assist, P3 punch_progress — and in
// order within a priority. Queues are bounded: P0–P2 return ErrQueueFull when
// full, P3 evicts its oldest frame. Send takes ownership of f.Payload.
//
// Errors: ErrWrongDirection, ErrFrameTooLarge, ErrQueueFull, and after the
// write side stopped, the reason it stopped (a write error, ErrReleased or
// net.ErrClosed).
func (c *Conn) Send(f Frame) error {
	if err := c.checkSend(f.Type, len(f.Payload)); err != nil {
		return err
	}
	return c.enqueue(&outFrame{typ: f.Type, payload: f.Payload}, false)
}

// SendCoalesced is Send, except that a queued frame of the same type and key
// that has not started being written is replaced in place (keeping its queue
// position) instead of adding another frame. The client merges progress
// frames of the same stage this way.
func (c *Conn) SendCoalesced(f Frame, key string) error {
	if err := c.checkSend(f.Type, len(f.Payload)); err != nil {
		return err
	}
	return c.enqueue(&outFrame{typ: f.Type, payload: f.Payload, key: key}, true)
}

// SendFunc queues a frame whose payload is produced by build right before it
// is written, on the writing goroutine; build gets the current time
// (ConnOptions.Now). A pong built this way reports how long the ping waited,
// queue time included. If build fails, panics or returns more than the type's
// Cap, the frame is dropped and counted; the Conn stays usable. build must not
// block or call Release or Close.
func (c *Conn) SendFunc(t Type, build func(now time.Time) ([]byte, error)) error {
	if build == nil {
		return errors.New("controlwire: SendFunc with a nil builder")
	}
	if err := c.checkSend(t, 0); err != nil {
		return err
	}
	return c.enqueue(&outFrame{typ: t, build: build}, false)
}

// WriteFrame queues f like Send and waits until it has been written. The
// frame must be written within min(WriteTimeout, ctx deadline) of the call;
// missing that fails the write side with an error wrapping
// os.ErrDeadlineExceeded. WriteFrame always returns within that bound plus a
// short slack, even when the connection ignores deadlines or panics.
//
// If ctx ends while the frame is still queued, it is withdrawn and ctx's
// cause is returned; if it is already being written, the cause is returned
// and the outcome of that write is not reported.
func (c *Conn) WriteFrame(ctx context.Context, f Frame) error {
	if err := c.checkSend(f.Type, len(f.Payload)); err != nil {
		return err
	}
	deadline := time.Now().Add(c.wtimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	of := &outFrame{typ: f.Type, payload: f.Payload, deadline: deadline, done: make(chan error, 1)}
	if err := c.enqueue(of, false); err != nil {
		return err
	}
	t := time.NewTimer(time.Until(deadline) + stallSlack)
	defer t.Stop()
	select {
	case err := <-of.done:
		return err
	case <-ctx.Done():
		c.withdraw(of)
		select {
		case err := <-of.done:
			return err
		default:
			return context.Cause(ctx)
		}
	case <-t.C:
		if !c.withdraw(of) {
			select {
			case err := <-of.done:
				return err
			default:
			}
		}
		err := writeTimeout(f.Type)
		c.failWrite(err)
		return err
	}
}

// Flush waits until every frame queued before the call has left the queues:
// written, evicted by queue policy, or lost. It returns nil when none of them
// was lost, the reason the write side stopped otherwise, ctx's cause if ctx
// ends first, and an error wrapping os.ErrDeadlineExceeded when the queues do
// not drain within WriteTimeout (frames stay queued in that case). Flush
// returns within min(WriteTimeout, ctx deadline) whatever the connection does.
func (c *Conn) Flush(ctx context.Context) error {
	// The own bound only matters when ctx does not end sooner; otherwise ctx
	// reports the expiry with its own cause.
	var bound <-chan time.Time
	if d, ok := ctx.Deadline(); !ok || time.Until(d) > c.wtimeout {
		t := time.NewTimer(c.wtimeout)
		defer t.Stop()
		bound = t.C
	}
	c.qmu.Lock()
	target := c.seq
	for {
		if c.oldestOutstanding() > target {
			var err error
			if c.lostMin != 0 && c.lostMin <= target {
				err = c.wstop
			}
			c.qmu.Unlock()
			return err
		}
		progress := c.progress
		c.qmu.Unlock()
		select {
		case <-progress:
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-bound:
			return fmt.Errorf("controlwire: flush: %w", os.ErrDeadlineExceeded)
		}
		c.qmu.Lock()
	}
}

func (c *Conn) checkSend(t Type, n int) error {
	if !c.side.Sends(t) {
		return fmt.Errorf("%w: %v by %v", ErrWrongDirection, t, c.side)
	}
	if n > t.Cap() {
		return fmt.Errorf("%w: %v payload %d > %d", ErrFrameTooLarge, t, n, t.Cap())
	}
	return nil
}

func (c *Conn) enqueue(f *outFrame, coalesce bool) error {
	inf, _ := f.typ.info()
	p := inf.prio
	c.qmu.Lock()
	defer c.qmu.Unlock()
	if c.wstop != nil {
		return c.wstop
	}
	q := c.queues[p]
	if coalesce {
		for _, old := range q {
			if old.typ == f.typ && old.key == f.key && old.done == nil {
				old.payload, old.build = f.payload, f.build
				return nil
			}
		}
	}
	if len(q) >= p.queueCap() {
		if p != prioP3 {
			return fmt.Errorf("%w: %v", ErrQueueFull, f.typ)
		}
		evicted := q[0]
		n := copy(q, q[1:])
		q[n] = nil
		q = q[:n]
		c.dropped.Add(1)
		c.complete(evicted, fmt.Errorf("%w: evicted by a newer frame", ErrDropped), false)
	}
	c.seq++
	f.seq = c.seq
	c.queues[p] = append(q, f)
	c.qcond.Signal()
	return nil
}

// withdraw removes f from its queue if it has not been picked by the writer.
func (c *Conn) withdraw(f *outFrame) bool {
	inf, _ := f.typ.info()
	c.qmu.Lock()
	defer c.qmu.Unlock()
	q := c.queues[inf.prio]
	for i, x := range q {
		if x == f {
			copy(q[i:], q[i+1:])
			q[len(q)-1] = nil
			c.queues[inf.prio] = q[:len(q)-1]
			c.bumpProgress()
			return true
		}
	}
	return false
}

// complete reports the outcome of a frame that has left the queues. lost
// marks frames that did not reach the wire because the write side failed or
// stopped. Callers hold qmu.
func (c *Conn) complete(f *outFrame, err error, lost bool) {
	if lost && (c.lostMin == 0 || f.seq < c.lostMin) {
		c.lostMin = f.seq
	}
	if f.done != nil {
		f.done <- err
	}
	c.bumpProgress()
}

func (c *Conn) bumpProgress() {
	close(c.progress)
	c.progress = make(chan struct{})
}

// oldestOutstanding is the lowest seq still queued or in flight, or
// MaxUint64 when nothing is outstanding. Within a queue, seq increases from
// head to tail. Callers hold qmu.
func (c *Conn) oldestOutstanding() uint64 {
	oldest := ^uint64(0)
	if c.flight != nil {
		oldest = c.flight.seq
	}
	for _, q := range c.queues {
		if len(q) > 0 && q[0].seq < oldest {
			oldest = q[0].seq
		}
	}
	return oldest
}

// stopQueues stops accepting frames and drops the queued ones; the frame in
// flight is left to the writer. It is idempotent: only the first cause is kept.
func (c *Conn) stopQueues(cause error) {
	c.qmu.Lock()
	defer c.qmu.Unlock()
	if c.wstop != nil {
		return
	}
	c.wstop = cause
	for p := range c.queues {
		for _, f := range c.queues[p] {
			c.dropped.Add(1)
			c.complete(f, fmt.Errorf("%w: %w", ErrDropped, cause), true)
		}
		clear(c.queues[p])
		c.queues[p] = c.queues[p][:0]
	}
	c.qcond.Broadcast()
}

// failWrite marks the write side failed: queued frames are dropped with err
// and the Conn reports err through Done and Err.
func (c *Conn) failWrite(err error) {
	c.stopQueues(err)
	c.fail(err)
}

func writeTimeout(t Type) error {
	return fmt.Errorf("controlwire: write %v: %w", t, os.ErrDeadlineExceeded)
}

// writeLoop is the writing goroutine: the only code that writes the
// connection or changes its write deadline (apart from Release's interrupt,
// which it excludes through dmu).
func (c *Conn) writeLoop() {
	for {
		f := c.nextOut()
		if f == nil {
			return
		}
		cont := false
		// writeOut contains every call into the connection and the builders
		// in boundaries of their own; this one keeps a defect in writeOut
		// itself from leaving the frame in flight and its waiters asleep.
		if perr := life.Safe("ctl-write", func() { cont = c.writeOut(f) }); perr != nil {
			c.settleFlight(f, perr)
			c.failWrite(perr)
			return
		}
		if !cont {
			return
		}
	}
}

// settleFlight completes f if it is still in flight.
func (c *Conn) settleFlight(f *outFrame, err error) {
	c.qmu.Lock()
	inFlight := c.flight == f
	c.qmu.Unlock()
	if inFlight {
		c.endFlight(f, err, true)
	}
}

// nextOut waits for the highest-priority queued frame and marks it in
// flight. It returns nil once the write side has stopped.
func (c *Conn) nextOut() *outFrame {
	c.qmu.Lock()
	defer c.qmu.Unlock()
	for c.wstop == nil {
		for p := range c.queues {
			q := c.queues[p]
			if len(q) == 0 {
				continue
			}
			f := q[0]
			n := copy(q, q[1:])
			q[n] = nil
			c.queues[p] = q[:n]
			c.flight = f
			c.flightDone = make(chan struct{})
			return f
		}
		c.qcond.Wait()
	}
	return nil
}

// endFlight completes the in-flight frame.
func (c *Conn) endFlight(f *outFrame, err error, lost bool) {
	c.qmu.Lock()
	defer c.qmu.Unlock()
	c.flight = nil
	close(c.flightDone)
	c.complete(f, err, lost)
}

// writeOut writes one frame and reports whether the writer should continue.
func (c *Conn) writeOut(f *outFrame) bool {
	payload := f.payload
	if f.build != nil {
		var err error
		if perr := life.Safe("ctl-write:build "+f.typ.String(), func() { payload, err = f.build(c.now()) }); perr != nil {
			err = perr
		}
		if err == nil && len(payload) > f.typ.Cap() {
			err = fmt.Errorf("%w: %v payload %d > %d", ErrFrameTooLarge, f.typ, len(payload), f.typ.Cap())
		}
		if err != nil {
			c.dropped.Add(1)
			c.endFlight(f, fmt.Errorf("%w: %w", ErrDropped, err), false)
			return true
		}
	}
	buf, err := AppendFrame(c.wbuf[:0], Frame{Type: f.typ, Payload: payload})
	if err != nil {
		c.endFlight(f, err, false)
		return true
	}
	c.wbuf = buf

	now := time.Now()
	deadline := now.Add(c.wtimeout)
	if !f.deadline.IsZero() {
		if !f.deadline.After(now) {
			err := writeTimeout(f.typ)
			c.endFlight(f, err, true)
			c.failWrite(err)
			return false
		}
		if f.deadline.Before(deadline) {
			deadline = f.deadline
		}
	}

	// Ordering against Release without holding a lock across connection
	// calls: the deadline is set first and dstop checked afterwards under dmu.
	// A Write starts only if dstop was still false; then Release finds
	// writing set and moves the deadline into the past after this
	// SetWriteDeadline returned. Otherwise the frame is dropped without a
	// Write and Release clears the deadline once the writer has exited.
	// Either way no deadline set here can outlive Release's interrupt.
	if c.writeStopped() {
		c.endFlight(f, fmt.Errorf("%w: %w", ErrDropped, c.stopCause()), true)
		return false
	}
	var derr error
	if perr := life.Safe("ctl-write:set-deadline", func() { derr = c.nc.SetWriteDeadline(deadline) }); perr != nil {
		derr = perr
	}
	if derr != nil {
		c.endFlight(f, derr, true)
		c.failWrite(derr)
		return false
	}
	c.dmu.Lock()
	stopped := c.dstop
	c.writing = !stopped
	c.dmu.Unlock()
	if stopped {
		c.endFlight(f, fmt.Errorf("%w: %w", ErrDropped, c.stopCause()), true)
		return false
	}

	var (
		n    int
		werr error
	)
	perr := life.Safe("ctl-write:write", func() {
		if werr = faultinject.Point("ctl.write"); werr == nil {
			n, werr = c.nc.Write(buf)
		}
	})

	c.dmu.Lock()
	c.writing = false
	switch {
	case perr != nil:
		// How much of the frame reached the wire is unknown.
		werr = perr
		c.wdirty = true
	case werr == nil && n != len(buf):
		werr = io.ErrShortWrite
		c.wdirty = n > 0
	case werr != nil && n > 0 && n < len(buf):
		c.wdirty = true
	}
	c.dmu.Unlock()

	if werr != nil {
		c.endFlight(f, werr, true)
		c.failWrite(werr)
		return false
	}
	c.framesOut.Add(1)
	c.endFlight(f, nil, false)
	return true
}

func (c *Conn) writeStopped() bool {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	return c.dstop
}

// stopCause is the reason the write side stopped, for frames dropped after
// the stop.
func (c *Conn) stopCause() error {
	c.qmu.Lock()
	defer c.qmu.Unlock()
	if c.wstop != nil {
		return c.wstop
	}
	return ErrReleased
}

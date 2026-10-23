package controlwire

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/wiretype"
)

// maxEmptyReads bounds consecutive (0, nil) results from Read, which
// io.Reader discourages but does not forbid.
const maxEmptyReads = 100

// errStopped is fill's result when the hard stop of Release or Close came
// before a Read.
var errStopped = errors.New("controlwire: reading stopped")

// readLoop is the reading goroutine. It is the only code that reads the
// connection: two Read calls per frame (header, payload), never across a
// frame boundary, and no deadline of its own. While the link is idle it sits
// in a single blocked Read; Release interrupts that Read exactly once through
// life.InterruptRead.
func (c *Conn) readLoop() {
	var err error
	// readDone is closed however the goroutine ends, so that neither
	// ReadFrame nor Release can wait for a reader that is gone; the error it
	// publishes is set before anything that could fail.
	defer close(c.readDone)
	// The recover boundary is here rather than only in Group.Go so that a
	// panic still publishes the read error.
	if perr := life.Safe("ctl-read", func() { err = c.readFrames() }); perr != nil {
		err = perr
	}
	c.readErr = err
	c.rmu.Lock()
	// readFrames returns nil when it stopped between frames, and a hard stop
	// is told by rhard whatever the error: no error value is matched, since
	// that would call the Is and Unwrap methods of the connection's errors,
	// or of a value Intercept panicked with — user code, outside every
	// boundary.
	stopped := err == nil || c.rhard
	if stopped {
		c.readErr = c.stopErr
	}
	c.rmu.Unlock()
	// Done and Err report the failure before ReadFrame can return it.
	if !stopped {
		c.fail(err)
	}
}

// readFrames reads frames until reading fails or stops. It returns nil when
// Release or Close stopped it between frames, and the failure otherwise.
func (c *Conn) readFrames() error {
	var hdr [HeaderSize]byte
	discarded := 0
	for {
		if !c.beginFrame() {
			return nil
		}
		if err := c.fill(hdr[:], true); err != nil {
			return err
		}
		t, n, err := ParseHeader(hdr, c.capFor)
		if err != nil {
			return err
		}
		accept := c.side.Receives(t)
		var payload []byte
		if accept {
			payload = make([]byte, n)
		} else {
			if c.scratch == nil {
				c.scratch = make([]byte, wiretype.DiscardCap)
			}
			payload = c.scratch[:n]
		}
		if n > 0 {
			if err := c.fill(payload, false); err != nil {
				return err
			}
		}
		c.endFrame()

		if c.framesIn.Add(1) > uint64(c.maxFrames) {
			return fmt.Errorf("%w: more than %d frames", ErrFlood, c.maxFrames)
		}
		if !accept {
			c.discarded.Add(1)
			if discarded++; discarded > MaxDiscarded {
				return fmt.Errorf("%w: %d frames, last %v", ErrTooManyUnknown, discarded, t)
			}
			continue
		}
		var at time.Time
		if perr := life.Safe("ctl-read:now", func() { at = c.now() }); perr != nil {
			return perr
		}
		f := Frame{Type: t, Payload: payload, At: at}
		if c.intercept != nil {
			var consumed bool
			if perr := life.Safe("ctl-read:intercept", func() { consumed = c.intercept(c, f) }); perr != nil {
				return perr
			}
			if consumed {
				continue
			}
		}
		// A frame read completely is delivered whenever the inbox has room,
		// even when Release is under way; only a full inbox makes the
		// reader wait, and then a stop wins.
		select {
		case c.inbox <- f:
		default:
			select {
			case c.inbox <- f:
			case <-c.rstop:
				return nil
			}
		}
	}
}

// capFor applies the type's cap to accepted frames and DiscardCap to frames
// that will be dropped.
func (c *Conn) capFor(t Type) int {
	if c.side.Receives(t) {
		return t.Cap()
	}
	return wiretype.DiscardCap
}

// beginFrame reports whether the reader may start another frame.
func (c *Conn) beginFrame() bool {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return !c.rsoft && !c.rhard
}

// endFrame records that the reader is at a frame boundary and wakes a
// Release waiting for one.
func (c *Conn) endFrame() {
	c.rmu.Lock()
	c.rmid = false
	if c.rbound != nil {
		close(c.rbound)
		c.rbound = nil
	}
	c.rmu.Unlock()
}

// fill reads exactly len(buf) bytes. Before every Read it checks the hard
// stop, so that once Release has interrupted the connection no new Read is
// issued (fill then returns errStopped); first marks buf as the start of a
// frame.
func (c *Conn) fill(buf []byte, first bool) error {
	empty := 0
	for off := 0; off < len(buf); {
		c.rmu.Lock()
		hard := c.rhard
		c.rmu.Unlock()
		if hard {
			return errStopped
		}
		var (
			n   int
			err error
		)
		if perr := life.Safe("ctl-read:read", func() {
			if err = faultinject.Point("ctl.read"); err == nil {
				n, err = c.nc.Read(buf[off:])
			}
		}); perr != nil {
			return perr
		}
		if n < 0 || n > len(buf)-off {
			return fmt.Errorf("controlwire: Read returned invalid count %d", n)
		}
		if n > 0 && first && off == 0 {
			c.rmu.Lock()
			c.rmid = true
			c.rmu.Unlock()
		}
		off += n
		switch {
		case off == len(buf):
			return nil
		case err != nil:
			if errors.Is(err, io.EOF) && (off > 0 || !first) {
				err = io.ErrUnexpectedEOF
			}
			return err
		case n == 0:
			if empty++; empty >= maxEmptyReads {
				return io.ErrNoProgress
			}
		default:
			empty = 0
		}
	}
	return nil
}

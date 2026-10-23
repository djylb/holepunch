package controlwire

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/wiretype"
)

// Conn limits and timings.
const (
	// DefaultInboxSize bounds the frames waiting for ReadFrame.
	DefaultInboxSize = 32

	// releaseGrace is how long Release lets the frame currently being read
	// or written run to its end, so that the stream handed back never holds
	// half a frame.
	releaseGrace = 50 * time.Millisecond
	// releaseJoin bounds the wait for the two goroutines after they have been
	// interrupted. With a connection that honors deadlines they stop within
	// microseconds; reaching the bound means the connection or Intercept is
	// stuck, and the connection is reported unreturnable.
	releaseJoin = 500 * time.Millisecond
	// stallSlack is how long a synchronous writer waits beyond its frame's
	// deadline before declaring the writing goroutine stuck. It only matters
	// for connections that ignore write deadlines.
	stallSlack = 100 * time.Millisecond
)

// ConnOptions configures a Conn.
type ConnOptions struct {
	// Side decides which frame types are accepted on reading and which may be
	// sent. The zero value is SideClient.
	Side Side
	// WriteTimeout is the deadline for writing one frame (0: DefaultWriteTimeout;
	// coord uses 3 s). A frame that misses it fails the write side.
	WriteTimeout time.Duration
	// MaxFrames bounds the frames received on the link (0: DefaultMaxFrames).
	MaxFrames int
	// InboxSize bounds the frames waiting for ReadFrame (0: DefaultInboxSize).
	// When the inbox is full the reading goroutine waits, which applies
	// backpressure to the peer.
	InboxSize int
	// Intercept, if set, sees every accepted frame on the reading goroutine
	// before it is queued for ReadFrame; returning true consumes the frame.
	// It receives the Conn because it can run before NewConn returns. It is
	// how the client answers ping at any phase (SendFunc of a pong) and how
	// dispatchers route frames without an extra goroutine. It may call the
	// Send methods; it must not call ReadFrame, Release or Close, and must not
	// block for long: Release waits for it only up to an internal bound and
	// then reports ErrUnreturnable. A panic in Intercept fails the read side
	// with a *life.PanicError (a control-flow fault).
	//
	//holepunch:callback
	Intercept func(c *Conn, f Frame) bool
	// Now stamps Frame.At and is passed to SendFunc builders (nil: time.Now),
	// so that a runtime driven by a fake clock measures start delays and pong
	// hold times on its own time line. Write deadlines always use real time.
	//
	//holepunch:callback
	Now func() time.Time
}

// Stats counts frames on a Conn.
type Stats struct {
	FramesIn  uint64 // frames read, including discarded ones
	FramesOut uint64 // frames written completely
	Discarded uint64 // reserved or wrong-direction frames read and dropped
	Dropped   uint64 // frames dropped from the write queues before being written
}

// Conn is a framed control connection with one reading and one writing
// goroutine. See the package documentation for the model.
type Conn struct {
	nc        net.Conn
	side      Side
	wtimeout  time.Duration
	maxFrames int
	intercept func(*Conn, Frame) bool
	now       func() time.Time

	g           *life.Group
	interrupt   context.CancelFunc // ends the InterruptRead context
	restoreRead func() error

	// Read side. Only the reading goroutine reads the connection; rmu orders
	// its stop checks against Release and Close.
	inbox    chan Frame
	readDone chan struct{} // closed when the reading goroutine has exited
	readErr  error         // why reading ended; valid once readDone is closed
	scratch  []byte        // buffer for discarded payloads (reading goroutine only)

	rmu     sync.Mutex
	rsoft   bool          // stop at the next frame boundary
	rhard   bool          // stop before the next Read call
	rmid    bool          // part of a frame has been consumed
	rbound  chan struct{} // closed by the reader at a boundary while Release waits for one
	rstop   chan struct{} // closed together with rsoft; wakes a reader waiting on the inbox
	stopErr error         // ErrReleased or net.ErrClosed once terminating

	// Write side. qmu guards the queues; dmu orders the writer's per-frame
	// deadline against Release's interrupt (see writeOut). Neither lock is
	// held while calling into the connection.
	qmu        sync.Mutex
	qcond      sync.Cond
	queues     [wiretype.NumPriorities][]*outFrame
	seq        uint64
	flight     *outFrame
	flightDone chan struct{} // closed when the in-flight frame leaves the writer
	wstop      error         // why the queues stopped accepting frames
	lostMin    uint64        // lowest seq of a frame lost to a failure or stop; 0: none
	progress   chan struct{} // closed and replaced whenever a frame leaves the queues
	wbuf       []byte        // encoding buffer (writing goroutine only)

	dmu     sync.Mutex
	dstop   bool // no new deadline and no new Write may start
	writing bool // a Write call is in progress
	wdirty  bool // a write stopped inside a frame

	failOnce sync.Once
	done     chan struct{}
	err      error

	term struct {
		once sync.Once
		done chan struct{}
		mode termMode // which terminal operation ran
		err  error
	}

	framesIn, framesOut, discarded, dropped atomic.Uint64
}

// NewConn wraps nc and starts the reading and writing goroutines.
//
// nc must support read and write deadlines; NewConn checks this by clearing
// both (which also discards any deadline the caller left behind) and returns
// ErrDeadlineUnsupported if either call fails. A nil or typed-nil nc is
// ErrNilConn. On error nothing has been read or written.
//
// The connection stays the caller's: Release hands it back, Close closes it
// (for owners such as the coordinator).
func NewConn(nc net.Conn, opts ConnOptions) (*Conn, error) {
	if life.IsNil(nc) {
		return nil, ErrNilConn
	}
	if err := probeDeadlines(nc); err != nil {
		return nil, err
	}
	c := &Conn{
		nc:        nc,
		side:      opts.Side,
		wtimeout:  opts.WriteTimeout,
		maxFrames: opts.MaxFrames,
		intercept: opts.Intercept,
		now:       opts.Now,
		readDone:  make(chan struct{}),
		rstop:     make(chan struct{}),
		progress:  make(chan struct{}),
		done:      make(chan struct{}),
	}
	if c.wtimeout <= 0 {
		c.wtimeout = DefaultWriteTimeout
	}
	if c.maxFrames <= 0 {
		c.maxFrames = DefaultMaxFrames
	}
	if c.now == nil {
		c.now = time.Now
	}
	inbox := opts.InboxSize
	if inbox <= 0 {
		inbox = DefaultInboxSize
	}
	c.inbox = make(chan Frame, inbox)
	c.qcond.L = &c.qmu
	c.term.done = make(chan struct{})

	ictx, cancel := context.WithCancel(context.Background())
	c.interrupt = cancel
	c.restoreRead = life.InterruptRead(ictx, nc)
	c.g = life.New(context.Background())
	c.g.Go("ctl-read", func(context.Context) { c.readLoop() })
	c.g.Go("ctl-write", func(context.Context) { c.writeLoop() })
	return c, nil
}

func probeDeadlines(nc net.Conn) error {
	for _, set := range [...]func(time.Time) error{nc.SetReadDeadline, nc.SetWriteDeadline} {
		var err error
		if perr := life.Safe("controlwire:probe-deadline", func() { err = set(time.Time{}) }); perr != nil {
			err = perr
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrDeadlineUnsupported, err)
		}
	}
	return nil
}

// ReadFrame returns the next accepted frame that Intercept did not consume.
// It only waits on the inbox; it never touches the connection. When reading
// has ended, queued frames are returned first and then the reason reading
// ended: an I/O error, a frame-layer error (ErrBadMagic, ErrVersion,
// ErrZeroType, ErrFrameTooLarge, ErrTooManyUnknown, ErrFlood), a
// *life.PanicError, ErrReleased or net.ErrClosed. If ctx ends first, its cause
// is returned.
func (c *Conn) ReadFrame(ctx context.Context) (Frame, error) {
	select {
	case f := <-c.inbox:
		return f, nil
	default:
	}
	select {
	case f := <-c.inbox:
		return f, nil
	case <-c.readDone:
		select {
		case f := <-c.inbox:
			return f, nil
		default:
			return Frame{}, c.readErr
		}
	case <-ctx.Done():
		return Frame{}, context.Cause(ctx)
	}
}

// Done is closed when the Conn stops being usable in either direction:
// reading ended, a write failed, or Release or Close began. Err reports why.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns the first reason the Conn stopped, or nil while it is usable.
func (c *Conn) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

// Stats returns the Conn's frame counters.
func (c *Conn) Stats() Stats {
	return Stats{
		FramesIn:  c.framesIn.Load(),
		FramesOut: c.framesOut.Load(),
		Discarded: c.discarded.Load(),
		Dropped:   c.dropped.Load(),
	}
}

func (c *Conn) fail(err error) {
	c.failOnce.Do(func() {
		c.err = err
		close(c.done)
	})
}

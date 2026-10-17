package coord

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/protocol"
)

// linkInbox bounds the frames a link holds for the session goroutine; when it
// is full the link's reader waits, which pushes back on the client.
const linkInbox = 16

// maxRound is the wire limit on round numbers, rescue round included.
const maxRound = 8

// link is one attached control stream: a controlwire.Conn (one reading and one
// writing goroutine) whose accepted frames go to the session goroutine
// through in.
type link struct {
	role protocol.Role
	idx  int
	conn *controlwire.Conn
	in   chan controlwire.Frame
	quit chan struct{} // closed by close; releases a reader blocked on in
	once sync.Once

	// Write instants of the frames that carry RTT samples, stored by
	// the writing goroutine right before the frame is written, as session
	// time in ns plus one (0: not written).
	markStart   atomic.Int64
	markSummary atomic.Int64
	markGo      [maxRound + 1]atomic.Int64
	markPing    [pingsPerLink + 1]atomic.Int64

	// Guarded by the session mutex.
	dead      bool // failed or closed: nothing more is sent or handled
	frames    bucket
	assistIn  bucket
	relayTo   bucket // peer_seen forwarded to this link
	progress  int
	ping      pingState
	attachAt  time.Duration
	insecure  bool
	probe     *protocol.ProbeSpec // AttachOptions.Probe, normalized
	readyFams []protocol.Family
}

func newLink(idx int, role protocol.Role) *link {
	return &link{
		idx:  idx,
		role: role,
		in:   make(chan controlwire.Frame, linkInbox),
		quit: make(chan struct{}),
	}
}

// intercept is the Conn's Intercept: it hands every accepted frame to the
// session goroutine and never lets the Conn queue it for ReadFrame.
func (l *link) intercept(_ *controlwire.Conn, f controlwire.Frame) bool {
	select {
	case l.in <- f:
	case <-l.quit:
	}
	return true
}

// close stops the link and closes the connection: the Conn's reading
// goroutine ends with net.ErrClosed and both of its goroutines are joined.
// It must not be called with the session mutex held.
func (l *link) close() {
	l.once.Do(func() {
		close(l.quit)
		_ = l.conn.Close()
	})
}

// send queues m without blocking.
func (l *link) send(m protocol.Message) error {
	f, err := msgframe.Encode(m)
	if err != nil {
		return err
	}
	return l.conn.Send(f)
}

// sendMarked queues the encoded frame f and records its write instant in
// mark: the builder runs on the writing goroutine right before the frame is
// written (t_flushed of the RTT sample), with the time of the session clock.
func (l *link) sendMarked(f controlwire.Frame, mark *atomic.Int64, epoch time.Time) error {
	payload := f.Payload
	return l.conn.SendFunc(f.Type, func(now time.Time) ([]byte, error) {
		mark.Store(int64(now.Sub(epoch)) + 1)
		return payload, nil
	})
}

// sentAt is the session time a mark recorded; ok is false before the frame
// was written.
func sentAt(mark *atomic.Int64) (time.Duration, bool) {
	v := mark.Load()
	return time.Duration(v - 1), v != 0
}

// lossKind classifies why a link stopped.
type lossKind uint8

const (
	lossLink     lossKind = iota // EOF, reset, write failure or timeout, stalled queue
	lossProtocol                 // a frame-layer violation by the client
	lossInternal                 // a panic in the connection's code
)

// linkLoss is why a link stopped: the end's code and detail, and the kind.
type linkLoss struct {
	code   protocol.Reason
	detail string
	kind   lossKind
}

// lossStalled: a reliable frame did not fit the link's write queue (the
// client does not read).
var lossStalled = linkLoss{code: protocol.ReasonPeerOffline, detail: detailStalled, kind: lossLink}

// classifyLoss maps the reason a link stopped (Conn.Err, or an error of the
// session's own) to a linkLoss.
func classifyLoss(err error) linkLoss {
	var pe *life.PanicError
	if errors.As(err, &pe) {
		return linkLoss{code: protocol.ReasonInternal, detail: panicDetail(pe), kind: lossInternal}
	}
	if r, d, ok := msgframe.Reason(err); ok {
		return linkLoss{code: r, detail: d, kind: lossProtocol}
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return linkLoss{code: protocol.ReasonPeerOffline, detail: detailWriteTimeout, kind: lossLink}
	}
	return linkLoss{code: protocol.ReasonPeerOffline, kind: lossLink}
}

// classifyLink is classifyLoss for the error a link's Conn stopped with,
// which may be an error of the caller's connection: its methods are user
// code, so it is examined outside the session mutex and in a recover
// boundary. An error that panics there is a plain link failure.
func (s *Session) classifyLink(err error) linkLoss {
	var loss linkLoss
	if perr := life.Safe("coord.link_error", func() { loss = classifyLoss(err) }); perr != nil {
		s.c.noteCallbackPanic(s.id, perr)
		return linkLoss{code: protocol.ReasonPeerOffline, kind: lossLink}
	}
	return loss
}

// queueFull reports whether a send failed because the link's write queue was
// full; any other send error means the write side stopped, which the link's
// Done reports. The error may be the write error of the caller's connection,
// so this runs outside the session mutex and in a recover boundary.
func (s *Session) queueFull(err error) bool {
	full := false
	if perr := life.Safe("coord.send_error", func() { full = errors.Is(err, controlwire.ErrQueueFull) }); perr != nil {
		s.c.noteCallbackPanic(s.id, perr)
	}
	return full
}

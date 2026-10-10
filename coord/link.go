package coord

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

// linkInbox bounds the frames a link holds for the session goroutine; when it
// is full the link's reader waits, which pushes back on the client.
const linkInbox = 16

// maxRound is the wire limit on round numbers, rescue round included.
const maxRound = 8

// errStalled: a reliable frame did not fit the link's write queue (the client
// does not read); the link is lost with detail stalled.
var errStalled = errors.New("coord: control link stalled")

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
	f, err := protocol.Marshal(m)
	if err != nil {
		return err
	}
	return l.conn.Send(f)
}

// sendMarked queues m and records its write instant in mark: the builder runs
// on the writing goroutine right before the frame is written (t_flushed of
// the RTT sample), with the time of the session clock.
func (l *link) sendMarked(m protocol.Message, mark *atomic.Int64, epoch time.Time) error {
	f, err := protocol.Marshal(m)
	if err != nil {
		return err
	}
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

// classifyLoss maps the reason a link stopped (Conn.Err, or errStalled) to a
// code and detail.
func classifyLoss(err error) (protocol.Reason, string, lossKind) {
	var pe *life.PanicError
	if errors.As(err, &pe) {
		return protocol.ReasonInternal, panicDetail(pe), lossInternal
	}
	if r, d, ok := protocol.WireReason(err); ok {
		return r, d, lossProtocol
	}
	switch {
	case errors.Is(err, errStalled):
		return protocol.ReasonPeerOffline, detailStalled, lossLink
	case errors.Is(err, os.ErrDeadlineExceeded):
		return protocol.ReasonPeerOffline, detailWriteTimeout, lossLink
	}
	return protocol.ReasonPeerOffline, "", lossLink
}

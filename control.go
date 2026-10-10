package holepunch

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/protocol"
)

// Mailbox sizes of the control dispatcher.
const (
	goMailbox     = 4
	assistMailbox = 32
	maxEarlyPings = 8 // pings read before punch_start is accepted, answered once it is
)

// abortDrain bounds how long a stopped control link keeps reading for a
// punch_abort still on its way.
const abortDrain = 50 * time.Millisecond

// stamped is a decoded control message with the instant the reading
// goroutine finished reading its frame (start delays count from there).
type stamped[T any] struct {
	msg T
	at  time.Time
}

// startMsg is the first library frame, valid or not.
type startMsg struct {
	msg protocol.PunchStart
	at  time.Time
	err error
}

type earlyPing struct {
	ping protocol.Ping
	at   time.Time
}

// control is the client's control-plane dispatcher around a controlwire.Conn.
// The Conn owns the only reading goroutine (ctl-read) and the only writing
// goroutine (ctl-write); this type runs inside ctl-read through Intercept:
// it decodes each frame, answers ping at once (pong at P0), and routes the
// rest to bounded typed mailboxes — summary 1, go 4 (larger rounds kept),
// assist 32 (newest dropped), abort 1 — so the reader never blocks on the
// session. Ordering faults (a frame its phase does not allow) go to the
// fault mailbox. After local Confirm every control fault is ignored.
type control struct {
	rt   *runtime
	conn *controlwire.Conn

	startCh   chan startMsg
	summaryCh chan stamped[protocol.ProbeSummary]
	goCh      chan stamped[protocol.PunchGo]
	assistCh  chan stamped[protocol.Assist]
	abortCh   chan stamped[protocol.Abort]
	faultCh   chan *failure

	mu          sync.Mutex
	sessionID   string
	seenStart   bool
	accepted    bool
	early       []earlyPing
	seenSummary bool
	round1      protocol.RoundPlan // probe_summary.plan.round1 as the summary carried it, before any clamp
	maxGo       uint8
	confirmed   bool
}

func newControl(rt *runtime) *control {
	return &control{
		rt:        rt,
		startCh:   make(chan startMsg, 1),
		summaryCh: make(chan stamped[protocol.ProbeSummary], 1),
		goCh:      make(chan stamped[protocol.PunchGo], goMailbox),
		assistCh:  make(chan stamped[protocol.Assist], assistMailbox),
		abortCh:   make(chan stamped[protocol.Abort], 1),
		faultCh:   make(chan *failure, 1),
	}
}

// open wraps the caller's connection. Nothing is read or written on error.
func (ct *control) open(nc net.Conn) error {
	conn, err := controlwire.NewConn(nc, controlwire.ConnOptions{
		Side:      controlwire.SideClient,
		Intercept: ct.intercept,
		Now:       ct.rt.clk.Now,
	})
	if err != nil {
		return err
	}
	ct.conn = conn
	return nil
}

// intercept consumes every accepted frame on the reading goroutine.
func (ct *control) intercept(c *controlwire.Conn, f controlwire.Frame) bool {
	switch protocol.MessageType(f.Type) {
	case protocol.MsgPing:
		ct.onPing(c, f)
	case protocol.MsgPunchStart:
		ct.onStart(f)
	case protocol.MsgProbeSummary:
		ct.onSummary(f)
	case protocol.MsgPunchGo:
		ct.onGo(f)
	case protocol.MsgAssist:
		ct.onAssist(f)
	case protocol.MsgAbort:
		ct.onAbort(f)
	}
	return true
}

// fault reports a protocol fault, unless the session already confirmed.
func (ct *control) fault(f *failure) {
	ct.mu.Lock()
	confirmed := ct.confirmed
	ct.mu.Unlock()
	if confirmed {
		return
	}
	select {
	case ct.faultCh <- f:
	default:
	}
}

func (ct *control) violation(err error) {
	r, d, ok := protocol.WireReason(err)
	if !ok {
		r, d = protocol.ReasonProtocolViolation, "decode"
	}
	ct.fault(fail(r, d, err))
}

func (ct *control) order(detail string) {
	ct.fault(fail(protocol.ReasonProtocolViolation, detail, nil))
}

// onPing answers at once in every phase; before punch_start is
// accepted the ping waits, so a rejected start writes no frame at all.
func (ct *control) onPing(c *controlwire.Conn, f controlwire.Frame) {
	p, err := protocol.Unmarshal[protocol.Ping](f)
	if err != nil {
		ct.violation(err)
		return
	}
	ct.mu.Lock()
	if !ct.accepted {
		if len(ct.early) < maxEarlyPings {
			ct.early = append(ct.early, earlyPing{p, f.At})
		}
		ct.mu.Unlock()
		return
	}
	ct.mu.Unlock()
	sendPong(c, p, f.At)
}

func sendPong(c *controlwire.Conn, p protocol.Ping, at time.Time) {
	_ = c.SendFunc(controlwire.TypePong, func(now time.Time) ([]byte, error) {
		fr, err := protocol.Marshal(protocol.PongFor(p, at, now))
		return fr.Payload, err
	})
}

func (ct *control) onStart(f controlwire.Frame) {
	ct.mu.Lock()
	dup := ct.seenStart
	ct.seenStart = true
	ct.mu.Unlock()
	if dup {
		ct.order("duplicate_punch_start")
		return
	}
	m, err := protocol.Unmarshal[protocol.PunchStart](f)
	ct.startCh <- startMsg{msg: m, at: f.At, err: err}
}

// accept marks punch_start accepted: pings are answered from now on, the
// early ones first.
func (ct *control) accept(sessionID string) {
	ct.mu.Lock()
	ct.sessionID = sessionID
	ct.accepted = true
	early := ct.early
	ct.early = nil
	ct.mu.Unlock()
	for _, p := range early {
		sendPong(ct.conn, p.ping, p.at)
	}
}

func (ct *control) session() (string, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return ct.sessionID, ct.accepted
}

func (ct *control) onSummary(f controlwire.Frame) {
	ct.mu.Lock()
	sid, ok, dup := ct.sessionID, ct.accepted, ct.seenSummary
	ct.seenSummary = true
	ct.mu.Unlock()
	switch {
	case !ok:
		ct.order("summary_before_start")
		return
	case dup:
		ct.order("duplicate_probe_summary")
		return
	}
	m, err := protocol.Unmarshal[protocol.ProbeSummary](f)
	if err == nil {
		err = protocol.CheckOrigin(m, sid, "")
	}
	if err != nil {
		ct.violation(err)
		return
	}
	ct.mu.Lock()
	ct.round1 = cloneRound(m.Plan.Round1) // prepare normalizes the summary's in place
	ct.mu.Unlock()
	ct.summaryCh <- stamped[protocol.ProbeSummary]{m, f.At}
}

// onGo keeps only rounds above every go seen so far; a smaller or equal
// round is stale and counted. When the mailbox is full the oldest,
// hence smallest, round gives way. Unmarshal has already refused a later go
// without a plan; a round-1 go carries one only as an anchor
// update of the summary's plan, re-aimed predict stages and nothing else
// (detail round1_plan), so every go that reaches startRound has its
// plan where the round says. A go's window_ms must be its plan's, or the
// server and this side would run the round for different windows (detail
// window for every round): Unmarshal checks a go against
// the plan it carries; round 1's plan is the summary's, so its go must
// repeat the summary's window_ms exactly.
func (ct *control) onGo(f controlwire.Frame) {
	ct.mu.Lock()
	sid, summary, round1, confirmed := ct.sessionID, ct.seenSummary, ct.round1, ct.confirmed
	ct.mu.Unlock()
	if !summary {
		ct.order("go_before_summary")
		return
	}
	m, err := protocol.Unmarshal[protocol.PunchGo](f)
	if err == nil {
		err = protocol.CheckOrigin(m, sid, "")
	}
	if err != nil {
		ct.violation(err)
		return
	}
	if m.Round == 1 && m.WindowMs != round1.WindowMs {
		ct.fault(fail(protocol.ReasonProtocolViolation, "window", nil))
		return
	}
	if m.Round == 1 && m.Plan != nil {
		if err := round1.CheckAnchorUpdate(*m.Plan); err != nil {
			ct.violation(err)
			return
		}
	}
	ct.mu.Lock()
	stale := m.Round <= ct.maxGo
	if !stale {
		ct.maxGo = m.Round
	}
	ct.mu.Unlock()
	if stale || confirmed {
		return
	}
	msg := stamped[protocol.PunchGo]{m, f.At}
	for {
		select {
		case ct.goCh <- msg:
			return
		default:
		}
		select {
		case <-ct.goCh:
		default:
		}
	}
}

func (ct *control) onAssist(f controlwire.Frame) {
	ct.mu.Lock()
	sid, ok, confirmed := ct.sessionID, ct.accepted, ct.confirmed
	ct.mu.Unlock()
	if !ok {
		ct.order("assist_before_start")
		return
	}
	m, err := protocol.Unmarshal[protocol.Assist](f)
	if err == nil {
		err = protocol.CheckOrigin(m, sid, "")
	}
	known := m.Kind == protocol.AssistPeerSeen || m.Kind == protocol.AssistPeerTargets || m.Kind == protocol.AssistRefresh
	if err == nil && known {
		err = m.ValidateRelayed()
	}
	if err != nil {
		ct.violation(err)
		return
	}
	if confirmed || !known {
		return // unknown kinds are ignored
	}
	select {
	case ct.assistCh <- stamped[protocol.Assist]{m, f.At}:
	default: // full: the newest is dropped
	}
}

func (ct *control) onAbort(f controlwire.Frame) {
	ct.mu.Lock()
	sid, ok := ct.sessionID, ct.accepted
	ct.mu.Unlock()
	m, err := protocol.Unmarshal[protocol.Abort](f)
	if err == nil && ok {
		err = protocol.CheckOrigin(m, sid, "")
	}
	if err != nil {
		ct.violation(err)
		return
	}
	select {
	case ct.abortCh <- stamped[protocol.Abort]{m, f.At}:
	default:
	}
}

// confirm makes every later control fault, abort and stale frame harmless:
// after local Confirm the session no longer depends on the control link.
func (ct *control) confirm() {
	ct.mu.Lock()
	ct.confirmed = true
	ct.mu.Unlock()
}

// send queues a reliable frame.
func (ct *control) send(m protocol.Message) error {
	fr, err := protocol.Marshal(m)
	if err != nil {
		return err
	}
	return ct.conn.Send(fr)
}

// sendBuilt queues a reliable frame whose payload is built right before it
// is written, so that elapsed_ms covers the queueing too (each message's
// elapsed_ms is an RTT sample). The message is validated once up front.
func (ct *control) sendBuilt(t controlwire.Type, build func(now time.Time) protocol.Message) error {
	if _, err := protocol.Marshal(build(ct.rt.clk.Now())); err != nil {
		return err
	}
	return ct.conn.SendFunc(t, func(now time.Time) ([]byte, error) {
		fr, err := protocol.Marshal(build(now))
		return fr.Payload, err
	})
}

// sendFailure is the failure of a reliable frame that could not be queued:
// the link's own failure when the link stopped, internal otherwise (the
// message did not encode: a bug).
func (ct *control) sendFailure(what string, err error) *failure {
	if dead, _ := ct.dead(); dead {
		return ct.lost()
	}
	return fail(protocol.ReasonInternal, what, err)
}

// lost is the failure of a stopped control link: the server's punch_abort
// when one arrived, the link's own failure otherwise.
func (ct *control) lost() *failure {
	if ab, ok := ct.lateAbort(); ok {
		return abortFailure(ab.msg)
	}
	return ctlCause(ct.conn.Err())
}

// lateAbort lets reading finish after the link stopped and returns the
// punch_abort the server sent, if any. The server ends a session by writing
// punch_abort and closing the link; when a write of this side fails first,
// the link stops before the reader gets to the abort. Reading ends at once
// when the server closed; abortDrain bounds the wait otherwise.
func (ct *control) lateAbort() (stamped[protocol.Abort], bool) {
	ctx, cancel := context.WithCancel(ct.rt.g.Context())
	t := ct.rt.clk.AfterFunc(abortDrain, cancel)
	for {
		if _, err := ct.conn.ReadFrame(ctx); err != nil {
			break
		}
	}
	t.Stop()
	cancel()
	select {
	case ab := <-ct.abortCh:
		return ab, true
	default:
		return stamped[protocol.Abort]{}, false
	}
}

// dead reports whether the control link stopped and why.
func (ct *control) dead() (bool, error) {
	select {
	case <-ct.conn.Done():
		return true, ct.conn.Err()
	default:
		return false, nil
	}
}

// flush waits at most d for the queued frames to be written.
func (ct *control) flush(d time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	t := ct.rt.clk.AfterFunc(d, cancel)
	_ = ct.conn.Flush(ctx)
	t.Stop()
	cancel()
}

// ctlCause maps the reason the control link stopped. A panic of the link's
// reading or writing side is reported by that side's goroutine name
// (panic:ctl-read, panic:ctl-write). The library never closes the caller's
// connection, so net.ErrClosed means the caller closed it to stop the session.
func ctlCause(err error) *failure {
	var pe *PanicError
	switch {
	case errors.As(err, &pe):
		side, _, _ := strings.Cut(pe.Where(), ":")
		return fail(protocol.ReasonInternal, "panic:"+side, err)
	case errors.Is(err, controlwire.ErrReleased):
		return fail(protocol.ReasonInternal, "control_released", err)
	case errors.Is(err, net.ErrClosed):
		return fail(protocol.ReasonCanceled, "control_closed", ErrClosed)
	}
	if r, d, ok := protocol.WireReason(err); ok {
		return fail(r, d, err)
	}
	return fail(protocol.ReasonControlInterrupted, "", err)
}

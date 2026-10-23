package coord

import (
	"errors"
	"time"

	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/internal/wiretype"
	"github.com/djylb/holepunch/protocol"
)

// effects are actions decided under the session mutex and carried out after
// it is released, in this order.
type effects struct {
	// sendErr is each link's first failed send; it is examined outside the
	// mutex, and a full write queue loses the link (stalled).
	sendErr     [2]error
	close       []*link       // lost links to close
	closeHandle bool          // the natprobe handle is no longer needed
	sink        bool          // attach the sandwich sink to the handle
	extend      time.Duration // renew the natprobe handle (sandwich: past the latest punch deadline)
	term        *terminal
}

// end records the session's end; the first one wins.
func (fx *effects) end(t *terminal) {
	if fx.term == nil {
		fx.term = t
	}
}

func (fx *effects) merge(o effects) {
	for r, err := range o.sendErr {
		if fx.sendErr[r] == nil {
			fx.sendErr[r] = err
		}
	}
	fx.close = append(fx.close, o.close...)
	fx.closeHandle = fx.closeHandle || o.closeHandle
	fx.sink = fx.sink || o.sink
	fx.extend = max(fx.extend, o.extend)
	if o.term != nil {
		fx.end(o.term)
	}
}

// apply carries out fx. It must not be called with the mutex held or from a
// controlwire goroutine.
func (s *Session) apply(fx effects) {
	for r, err := range fx.sendErr {
		if err != nil && s.queueFull(err) {
			fx.merge(s.stalled(r))
		}
	}
	for _, l := range fx.close {
		l.close()
	}
	if s.handle != nil {
		if fx.sink {
			s.handle.AttachSandwichSink(s.onSandwich)
		}
		if fx.extend > 0 {
			s.handle.Extend(fx.extend)
		}
		if fx.closeHandle {
			s.handle.Close()
		}
	}
	if fx.term != nil {
		s.finish(*fx.term)
	}
}

// run is the session goroutine: it handles both links' frames and failures,
// and the planning the timer asks for, in one ordered stream, until the
// session ends.
func (s *Session) run() {
	defer s.release()
	for {
		in, down, ok := s.watch()
		if !ok {
			return
		}
		select {
		case <-s.quit:
			return
		case f := <-in[0]:
			s.frame(0, f)
		case f := <-in[1]:
			s.frame(1, f)
		case <-down[0]:
			s.lost(0)
		case <-down[1]:
			s.lost(1)
		case <-s.wake:
		}
		s.doWork()
	}
}

// watch returns the channels of the live links.
func (s *Session) watch() (in [2]chan controlwire.Frame, down [2]<-chan struct{}, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.state == StateClosed {
		return in, down, false
	}
	for r, l := range s.st.links {
		if l != nil && !l.dead {
			in[r], down[r] = l.in, l.conn.Done()
		}
	}
	return in, down, true
}

// frame handles one frame inside a recover boundary: a panic ends the
// session with internal.
func (s *Session) frame(r int, f controlwire.Frame) {
	if err := life.Safe("coord.frame", func() { s.handleFrame(r, f) }); err != nil {
		s.finish(internalTerm(err))
	}
}

// lost handles the end of link r: the frames read before the failure first,
// then the failure.
func (s *Session) lost(r int) {
	s.mu.Lock()
	l := s.st.links[r]
	s.mu.Unlock()
	for drained := false; !drained; {
		select {
		case f := <-l.in:
			s.frame(r, f)
		default:
			drained = true
		}
	}
	loss := s.classifyLink(l.conn.Err())
	var fx effects
	now := s.since(s.c.set.clock.Now())
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		fx = s.linkLostLocked(r, loss, now)
	}()
	s.apply(fx)
}

// stalled loses link r, whose write queue is full, as of the clock's now:
// a punching session re-arms its timer from it, and the last update may be
// a round old (the go of a round its predecessor's deadline ended).
func (s *Session) stalled(r int) effects {
	now := s.since(s.c.set.clock.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.linkLostLocked(r, lossStalled, now)
}

// doWork runs the planning the session asked for.
func (s *Session) doWork() {
	s.mu.Lock()
	w := s.st.work
	s.st.work = work{}
	s.mu.Unlock()
	if w.plan {
		s.planSession()
	}
	if w.evalRound {
		s.nextRound()
	}
	if w.refreshed {
		s.afterRefresh()
	}
}

// linkLostLocked applies the loss of link r:
// before punching it ends the session with peer_offline; while punching it
// marks the side gone — no new round, and control_interrupted at the round's
// deadline unless a confirmation arrives; in confirming an unconfirmed
// side's loss ends the session as a half-confirmed success. A protocol fault
// ends the session in every state but confirming.
func (s *Session) linkLostLocked(r int, loss linkLoss, now time.Duration) effects {
	st := &s.st
	l := st.links[r]
	var fx effects
	if l == nil || l.dead || st.state == StateClosed {
		return fx
	}
	l.dead = true
	fx.close = append(fx.close, l)
	st.updated = now
	role := roleOf(r)
	switch st.state {
	case StateConfirming:
		if !st.confirm.confirmed[r] {
			fx.end(&terminal{})
		}
		return fx
	case StatePunching:
		if loss.kind == lossLink {
			st.gone[r] = true
			st.plan.void() // a next round being planned must not start
			switch {
			case st.gone[1-r]:
				fx.end(goneTerm(role))
			case st.rounds.cur.evaluating:
				// The round already ended: there is nothing left to wait for.
				fx.end(goneTerm(role))
			default:
				st.deadline = min(st.deadline, st.rounds.cur.deadline)
				s.rearmLocked(now)
			}
			return fx
		}
	}
	t := &terminal{code: loss.code, detail: loss.detail, failed: role}
	if loss.kind == lossInternal {
		t.failed = ""
	}
	fx.end(t)
	return fx
}

// goneTerm ends a punch whose side lost its control link.
func goneTerm(role protocol.Role) *terminal {
	return &terminal{code: protocol.ReasonControlInterrupted, failed: role,
		peerCode: protocol.ReasonPeerOffline, peerDetail: detailControlInterrupted}
}

// handleFrame decodes and handles one frame of link r.
func (s *Session) handleFrame(r int, f controlwire.Frame) {
	var fx effects
	if !s.admitFrame(r, f, &fx) {
		s.apply(fx)
		return
	}
	role := roleOf(r)
	m, err := msgframe.Decode(f)
	if err == nil {
		normalize(m)
		err = protocol.CheckOrigin(m, s.id, role)
	}
	if err != nil {
		s.mu.Lock()
		confirming := s.st.state == StateConfirming
		s.mu.Unlock()
		if confirming {
			// While confirming, a malformed frame ends its link like a read
			// error: a half-confirmed session still succeeds.
			s.lostNow(r, err)
			return
		}
		code, detail := msgframe.ReasonOr(err, protocol.ReasonProtocolViolation, detailUnexpected)
		s.apply(effects{term: &terminal{code: code, detail: detail, failed: role,
			notifyFailed: code != protocol.ReasonControlVersionMismatch}})
		return
	}
	if fault := s.faultFor(f.Type); fault != nil {
		if errors.Is(fault, faultinject.ErrCloseConn) {
			s.lostNow(r, fault)
			return
		}
		s.finish(internalTerm(fault))
		return
	}
	now := s.since(f.At)
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		fx = s.messageLocked(r, m, now)
	}()
	s.apply(fx)
}

// faultFor is the injected fault of the frame's handling point, if any.
func (s *Session) faultFor(t wiretype.Type) error {
	switch t {
	case wiretype.ProbeReport:
		return faultinject.Point(fiHandleReport)
	case wiretype.PunchReady:
		return faultinject.Point(fiHandleReady)
	}
	return nil
}

// lostNow treats link r as lost because of err, an error of the session's
// own (a frame it could not decode, an injected fault).
func (s *Session) lostNow(r int, err error) {
	loss := classifyLoss(err)
	var fx effects
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		fx = s.linkLostLocked(r, loss, s.st.updated)
	}()
	s.apply(fx)
}

// admitFrame applies the per-link limits before decoding: the client frame
// rate (control_flood) and the progress quota (dropped and counted).
func (s *Session) admitFrame(r int, f controlwire.Frame, fx *effects) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	l := st.links[r]
	if l == nil || l.dead || st.state == StateClosed {
		return false
	}
	if ok, _ := l.frames.take(f.At, 1); !ok {
		fx.end(&terminal{code: protocol.ReasonProtocolViolation, detail: detailControlFlood, failed: roleOf(r),
			notifyFailed: true})
		return false
	}
	if f.Type == wiretype.Progress {
		if lim := s.c.set.limits.ProgressPerLink; lim >= 0 && l.progress >= lim {
			st.ctr.ProgressDropped++
			return false
		}
		l.progress++
	}
	return true
}

// normalize applies the receiver-side clamps to a message Decode returned
// for a client link, in place. Messages without clamps are left as they are.
func normalize(m protocol.Message) {
	switch m := m.(type) {
	case *protocol.ProbeReport:
		*m, _ = m.Normalize()
	case *protocol.Progress:
		*m, _ = m.Normalize()
	case *protocol.Assist:
		*m, _ = m.Normalize()
	case *protocol.PunchResult:
		*m, _ = m.Normalize()
	}
}

// messageLocked dispatches a decoded message of link r.
func (s *Session) messageLocked(r int, m protocol.Message, now time.Duration) effects {
	st := &s.st
	if st.state == StateClosed || st.links[r] == nil || st.links[r].dead {
		return effects{}
	}
	st.updated = now
	switch m := m.(type) {
	case *protocol.ProbeReport:
		return s.onReportLocked(r, m, now)
	case *protocol.PunchReady:
		return s.onReadyLocked(r, m, now)
	case *protocol.RoundResult:
		return s.onRoundResultLocked(r, m, now)
	case *protocol.PunchResult:
		return s.onPunchResultLocked(r, m, now)
	case *protocol.Assist:
		return s.onAssistLocked(r, m, now)
	case *protocol.Progress:
		s.onProgressLocked(r, m, now)
	case *protocol.Pong:
		s.onPongLocked(r, m, now)
	}
	return effects{}
}

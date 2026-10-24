package coord

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/trunc"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// Standard details.
const (
	detailJoinTimeout        = "join_timeout"
	detailWriteTimeout       = "write_timeout"
	detailStalled            = "stalled"
	detailControlInterrupted = "control_interrupted"
	detailPlannerTimeout     = "planner_timeout"
	detailInsecureControl    = "insecure_control"
	detailTLSHandshake       = "tls_handshake"
	detailBudgetViolation    = "budget_violation"
	detailControlFlood       = "control_flood"
	detailDuplicate          = "duplicate_message"
	detailUnexpected         = "unexpected_message"
	detailNoAdmissible       = "no_admissible_target"
)

// terminal is how a session ends.
type terminal struct {
	code   protocol.Reason // "" on success
	detail string
	failed protocol.Role // the side at fault; "" for the server or the caller
	// notifyFailed also sends the failed side a punch_abort{by: server} (its
	// link still works: a deadline it missed, a message it got wrong);
	// otherwise the failed side's link is lost or already done.
	notifyFailed bool
	// peerCode and peerDetail replace code and detail in the notice to the
	// other side (peer_offline with detail control_interrupted for a lost
	// link).
	peerCode   protocol.Reason
	peerDetail string
	panic      *life.PanicError
}

// cause is the session context's cancellation cause.
func (t terminal) cause() error {
	if t.code == "" {
		return ErrSessionDone
	}
	return &ReasonError{Reason: t.code, Detail: t.detail}
}

// internalTerm is the end for a recovered panic or an injected fault.
func internalTerm(err error) terminal {
	var pe *life.PanicError
	if errors.As(err, &pe) {
		return terminal{code: protocol.ReasonInternal, detail: panicDetail(pe), panic: pe}
	}
	return terminal{code: protocol.ReasonInternal, detail: trunc.String(err.Error(), protocol.MaxDetail)}
}

// panicDetail is "panic:<where>: <value summary>", without a stack.
func panicDetail(pe *life.PanicError) string {
	text := strings.TrimPrefix(pe.Error(), "panic in "+pe.Where()+": ")
	return trunc.String("panic:"+pe.Where()+": "+text, protocol.MaxDetail)
}

// notice is a punch_abort for one link.
type notice struct {
	l   *link
	msg protocol.Abort
}

// feedback is what finish reports to the memories, captured under the lock.
type feedback struct {
	memory   StrategyMemory
	key      StrategyKey
	rounds   []RoundRecord
	winRound int
	traits   []traitsNote
}

type traitsNote struct {
	key   natprobe.TraitsKey
	final protocol.Traits
}

// ending is what finish takes from the session when it closes it.
type ending struct {
	closed     bool // this call closed the session
	t          terminal
	notices    []notice
	res        Result
	fb         feedback
	links      [2]*link
	quota      *quota
	stopParent func() bool
	stopWatch  func() bool
}

// finish ends the session exactly once; every other caller returns at once.
// It closes the session and decides the Result and the notices under the
// lock, then releases the resources step by step, each step in its own
// recover boundary, and finally drops its reference (the last reference
// closes Done and calls OnResult). It must not be called with the session
// mutex held, nor from a controlwire goroutine (it closes the links).
func (s *Session) finish(t terminal) {
	now := s.c.set.clock.Now()
	var e ending
	s.callout("coord.finish", "", func() { s.closeState(t, now, &e) })
	if !e.closed {
		return
	}
	if e.t.panic != nil {
		s.c.noteCallbackPanic(s.id, e.t.panic)
	}
	res := &e.res
	s.step(fiFinishNotify, func() { s.notify(e.notices) })
	s.step(fiFinishConns, func() { s.closeLinks(e.links, &res.Counters) })
	s.step(fiFinishRegistry, func() {
		if s.handle != nil {
			s.handle.Close()
		}
	})
	s.step(fiFinishQuota, func() { s.c.limiter.release(now, e.quota) })
	s.step(fiFinishIndex, func() { s.c.unindex(s) })
	s.step(fiFinishParent, func() {
		if e.stopParent != nil {
			e.stopParent()
		}
	})
	s.step(fiFinishCtx, func() {
		if e.stopWatch != nil {
			e.stopWatch()
		}
		s.group.Fail(e.t.cause())
	})
	s.step(fiFinishMemory, func() { s.reportMemory(e.fb) })
	s.step(fiFinishTraits, func() { s.observeTraits(e.fb, res.Outcome == OutcomeSucceeded) })
	s.step(fiFinishStats, func() { s.c.ctr.record(res) })
	s.result.Store(res)
	s.release()
}

// closeState closes the session under the lock and fills e with what finish
// releases. It closes first — state, generation, quit, timer — and only then
// works out the end, so that a failure while doing so still leaves the
// session closed, with a bare Result and no notices, and every resource to
// finish.
func (s *Session) closeState(t terminal, now time.Time, e *ending) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	if st.state == StateClosed {
		return
	}
	prev := st.state
	st.state = StateClosed
	// From here the session is closed, so the session goroutine must be told
	// whatever happens next.
	defer close(s.quit)
	st.plan.void()
	st.updated = s.since(now)
	*e = ending{
		closed:     true,
		t:          t,
		res:        s.bareResult(t, now),
		links:      st.links,
		quota:      &st.quota,
		stopParent: s.stopParent,
		stopWatch:  s.stopWatch,
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	e.t = s.settleLocked(t, prev)
	e.notices = s.noticesLocked(e.t, prev)
	e.res = s.resultLocked(e.t, now)
	e.fb = s.feedbackLocked(&e.res)
}

// closeLinks closes the links, each in its own recover boundary so that one
// failing close keeps no other link open, and takes their frame counts.
func (s *Session) closeLinks(links [2]*link, ctr *Counters) {
	for i, l := range links {
		if l == nil {
			continue
		}
		s.callout(fiFinishConns, "", func() {
			l.close()
			cs := l.conn.Stats()
			ctr.FramesIn[i], ctr.FramesOut[i] = cs.FramesIn, cs.FramesOut
			ctr.UnknownFrames += cs.Discarded
		})
	}
}

// step runs one step of finish. The step's fault point and its work have a
// recover boundary each: a fault at the point — a panic, or an injected
// error, which stands for the step failing — is reported and the work still
// runs, so that no failure keeps a resource; a panic in the work is reported
// and skips no later step.
func (s *Session) step(point string, work func()) {
	s.callout(point, point, func() {})
	s.callout(point, "", work)
}

// settleLocked adjusts the end to the state it meets: a server shutdown in
// confirming keeps the confirmations, and a half-confirmed success warns
// peer_result_missing.
func (s *Session) settleLocked(t terminal, prev State) terminal {
	st := &s.st
	if prev == StateConfirming && t.code == protocol.ReasonServerShutdown {
		t = terminal{}
	}
	if t.code == "" && st.confirm.confirmed[0] != st.confirm.confirmed[1] {
		st.addWarn(protocol.WarnPeerResultMissing)
	}
	return t
}

// noticesLocked returns the punch_abort notices of the end: none on success;
// none in punching or confirming when the server shuts down; never to a
// lost link, a confirmed side or a side that sent its own failure.
func (s *Session) noticesLocked(t terminal, prev State) []notice {
	st := &s.st
	if t.code == "" || (t.code == protocol.ReasonServerShutdown && (prev == StatePunching || prev == StateConfirming)) {
		return nil
	}
	retry := retryFor(t.code, t.detail, 0)
	var out []notice
	for r, l := range st.links {
		role := roleOf(r)
		if l == nil || l.dead || st.gone[r] || st.confirm.confirmed[r] || (role == t.failed && !t.notifyFailed) {
			continue
		}
		m := protocol.Abort{SessionID: s.id, By: protocol.RoleServer, Reason: t.code, Detail: t.detail}
		if t.failed != "" && t.failed != role {
			m.By = t.failed
			if t.peerCode != "" {
				m.Reason, m.Detail = t.peerCode, t.peerDetail
			}
		}
		if retry.Retryable && retry.After > 0 {
			m.RetryAfterMs = uint32(retry.After / time.Millisecond)
		}
		out = append(out, notice{l: l, msg: m})
	}
	return out
}

// notify writes the notices, all within one absolute deadline, before
// the links are closed.
func (s *Session) notify(notices []notice) {
	if len(notices) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.c.set.limits.AbortTimeout)
	defer cancel()
	for _, n := range notices {
		_ = n.l.send(n.msg)
	}
	for _, n := range notices {
		_ = n.l.conn.Flush(ctx)
	}
}

// bareResult is the part of the Result that only needs the end: all a
// session reports when working out the rest failed.
func (s *Session) bareResult(t terminal, now time.Time) Result {
	res := Result{
		SessionID:  s.id,
		Outcome:    outcomeOf(t.code),
		Reason:     t.code,
		Detail:     t.detail,
		FailedRole: t.failed,
		Labels:     s.labels,
	}
	if res.Reason == "" {
		res.FailedRole = ""
	}
	res.Timing.Created = s.epoch
	res.Timing.Closed = now
	return res
}

// resultLocked builds the Result.
func (s *Session) resultLocked(t terminal, now time.Time) Result {
	st := &s.st
	res := s.bareResult(t, now)
	res.Confirmed = st.confirm.confirmed
	res.Warn = slices.Clone(st.warn)
	res.PairClass = st.plan.cls.PairClass
	res.MemoryHit = st.plan.memHit
	res.Warm = st.plan.warm
	res.Rounds = slices.Clone(st.rounds.records)
	res.Counters = st.ctr
	res.Clients = st.confirm.finals
	if st.plan.hasKey {
		res.StrategyKey = st.plan.memKey.String()
	}
	for r := range 2 {
		res.Attached[r] = st.links[r] != nil
		res.RTT[r], _ = st.rtt[r].min()
		res.ClockOffset[r] = st.offset[r]
		if st.links[r] != nil {
			res.Timing.Attached[r] = s.at(st.links[r].attachAt)
		}
	}
	if st.summarized {
		res.Timing.Summary = s.at(st.summaryAt)
	}
	if st.rounds.round > 0 {
		res.Timing.FirstGo = s.at(st.rounds.firstGoAt)
	}
	if first, ok := st.confirm.firstConfirm(); ok {
		res.Timing.FirstConfirm = s.at(first)
	}
	if st.rounds.round > 0 && !st.rounds.cur.evaluating {
		// The round under way ends with the session.
		res.Rounds = append(res.Rounds, s.recordLocked(st.rounds.cur.classNow(), now))
	}
	for i := range min(st.tlN, timelineCap) {
		res.Timeline = append(res.Timeline, st.timeline[(st.tlN-min(st.tlN, timelineCap)+i)%timelineCap])
	}
	if res.Reason == "" && st.confirm.winRound > 0 {
		res.Winner = &WinnerInfo{Round: st.confirm.winRound, Variant: st.confirm.winVar, Family: st.confirm.winFam, Path: st.confirm.paths}
		for r, f := range st.confirm.finals {
			if f != nil && f.OK {
				res.Winner.ExtraPaths[r] = slices.Clone(f.ExtraPaths)
			}
		}
	}
	streak := s.c.limiter.noteOutcome(s.keys[0], t.code == protocol.ReasonCandidateTimeout)
	res.Retry = retryFor(t.code, t.detail, streak)
	if t.code != "" {
		res.Retry.Advice = st.plan.cls.Advice
	}
	res.Retry.BackgroundOnly = st.plan.bgOnly
	if len(res.Warn) > protocol.MaxWarn {
		res.Warn = res.Warn[:protocol.MaxWarn]
	}
	return res
}

// firstConfirm is the session time of the first confirmation.
func (c *confirmState) firstConfirm() (time.Duration, bool) {
	switch {
	case c.confirmed[0] && c.confirmed[1]:
		return min(c.confirmAt[0], c.confirmAt[1]), true
	case c.confirmed[0]:
		return c.confirmAt[0], true
	case c.confirmed[1]:
		return c.confirmAt[1], true
	}
	return 0, false
}

func (st *sessionState) addWarn(w protocol.Warning) {
	if !slices.Contains(st.warn, w) && len(st.warn) < protocol.MaxWarn {
		st.warn = append(st.warn, w)
	}
}

// feedbackLocked captures the memory feedback of the session: the strategy
// memory learns from finished rounds and the traits memory from the
// merged views corrected by punch_result.traits and confirmed by the
// winning path (peerConfirmed).
func (s *Session) feedbackLocked(res *Result) feedback {
	st := &s.st
	fb := feedback{memory: st.plan.memory, key: st.plan.memKey, rounds: res.Rounds}
	if res.Winner != nil {
		fb.winRound = res.Winner.Round
	}
	if !st.plan.hasKey {
		fb.memory = nil
	}
	if s.c.set.traits == nil || s.c.set.unverified || s.ablate.NoMemory || !st.plan.planned {
		return fb
	}
	for r, v := range st.plan.rawViews {
		for _, fv := range v.Families {
			final := fv.Traits
			if f := st.confirm.finals[r]; f != nil {
				for _, u := range f.Traits {
					if u.Family == fv.Family {
						final = applyTraitsUpdate(final, u)
					}
				}
			}
			if p := st.confirm.finals[1-r]; p != nil && p.Path != nil && p.Path.Family == fv.Family {
				final = peerConfirmed(final, *p.Path)
			}
			if !final.PublicIP.IsValid() {
				continue
			}
			fb.traits = append(fb.traits, traitsNote{
				key: natprobe.TraitsKey{ClientKey: s.keys[r], Family: fv.Family, PublicIP: final.PublicIP,
					LocalIP: primaryLocal(s.reportLocked(r), fv.Family)},
				final: final,
			})
		}
	}
	return fb
}

// primaryLocal is the local IP rep reported for the primary socket of
// family f (the TraitsKey's LocalIP, as natprobe's merge takes it); zero
// without one.
func primaryLocal(rep *protocol.ProbeReport, f protocol.Family) netip.Addr {
	if rep == nil {
		return netip.Addr{}
	}
	for _, fr := range rep.Families {
		if fr.Family != f {
			continue
		}
		for _, sr := range fr.Sockets {
			if sr.Kind == protocol.SocketPrimary {
				return sr.Local.Addr().Unmap()
			}
		}
	}
	return netip.Addr{}
}

// applyTraitsUpdate applies a punch-time correction; a correction of the
// mapping or the filtering from another address natprobe or the peer stands
// for (peer, alt) is cross-IP evidence. A confidence change is none: the
// client compares against the summary's view, which the memory may have
// raised, so it would renew the memory from its own conclusion; a
// confirmation by the winning path is peerConfirmed's. Hairpin is no other
// address, and a STUN server is only a hint: the traits memory must not
// learn a cross-IP mapping from it.
func applyTraitsUpdate(t protocol.Traits, u protocol.TraitsUpdate) protocol.Traits {
	if u.Mapping != nil {
		t.Mapping = *u.Mapping
	}
	if u.MappingConf != nil {
		t.MappingConf = *u.MappingConf
	}
	if u.Filtering != nil {
		t.Filtering = *u.Filtering
	}
	if u.FilteringConf != nil {
		t.FilteringConf = *u.FilteringConf
	}
	if u.PortStep != nil {
		t.PortStep = *u.PortStep
	}
	if u.PortVelocity != nil {
		t.PortVelocity = *u.PortVelocity
	}
	if u.Hairpin != nil {
		t.Hairpin = *u.Hairpin
	}
	if (u.Mapping != nil || u.Filtering != nil) && (u.Source == protocol.TraitsSourcePeer || u.Source == protocol.TraitsSourceAlt) {
		t.CrossIP = true
	}
	return t
}

// peerConfirmed adds the evidence of the winning path to t: the peer reached
// the side over a public path at the very mapping natprobe observed of its
// primary socket (the peer's remote address), so the mapping kept its port
// toward a second IP — an endpoint-independent mapping, cross-IP evidence,
// which a first round that connects at once leaves no punch-time correction
// for. It takes the peer's word, as a peer-sourced correction does, and
// only confirms what natprobe measured itself (EIM): a lying peer can
// renew a conclusion, never make one.
func peerConfirmed(t protocol.Traits, p protocol.PathInfo) protocol.Traits {
	if t.Mapping != protocol.MapEIM || p.Kind != protocol.PathPublic || !t.Observed.IsValid() || netaddr.Canon(p.Remote) != netaddr.Canon(t.Observed) {
		return t
	}
	t.MappingConf, t.CrossIP = protocol.ConfHigh, true
	return t
}

// reportMemory feeds the strategy memory, round by round: the confirmed
// round succeeded, unconfirmed NoContact, OneWay and Blocked rounds failed,
// everything else is neutral and not reported.
func (s *Session) reportMemory(fb feedback) {
	if fb.memory == nil {
		return
	}
	for _, rr := range fb.rounds {
		var mr MemoryResult
		switch {
		case rr.Round == fb.winRound:
			mr = MemSuccess
		case rr.Class == plan.RoundNoContact || rr.Class == plan.RoundOneWay || rr.Class == plan.RoundBlocked:
			mr = MemFailure
		default:
			continue
		}
		if !s.callout("coord.memory", fiMemory, func() { fb.memory.Report(fb.key, rr.Variant, mr) }) {
			return
		}
	}
}

// observeTraits records the final traits of both sides.
func (s *Session) observeTraits(fb feedback, succeeded bool) {
	mem := s.c.set.traits
	for _, n := range fb.traits {
		if !s.callout("coord.traits", "", func() { mem.Observe(n.key, n.final, succeeded) }) {
			return
		}
	}
}

// guard runs fn, work started by a caller or by a goroutine coord does not
// own (a timer or context callback), in a recover boundary: a panic ends the
// session with internal instead of escaping to the caller, or crashing the
// process from a goroutine without one.
func (s *Session) guard(where string, fn func()) {
	if err := life.Safe(where, fn); err != nil {
		s.finish(internalTerm(err))
	}
}

// onParentDone is the parent context's AfterFunc.
func (s *Session) onParentDone() {
	s.guard("coord.parent", func() { s.finish(terminal{code: protocol.ReasonCanceled, detail: "parent"}) })
}

// onGroupDone is the session context's AfterFunc: a panic in a session
// goroutine ends the session with internal, and the coordinator's shutdown
// with server_shutdown. finish's own cancellation finds the session closed.
func (s *Session) onGroupDone() {
	s.guard("coord.context", func() {
		cause := context.Cause(s.group.Context())
		var pe *life.PanicError
		if errors.As(cause, &pe) {
			s.finish(internalTerm(pe))
			return
		}
		s.finish(terminal{code: protocol.ReasonServerShutdown})
	})
}

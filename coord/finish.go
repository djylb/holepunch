package coord

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/natprobe"
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
	detailMergePanic         = "panic:merge"
	detailNoAdmissible       = "no_admissible_target"
	maxDetail                = 256
	maxWarn                  = 8
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
	return terminal{code: protocol.ReasonInternal, detail: truncate(err.Error(), maxDetail)}
}

// panicDetail is "panic:<where>: <value summary>", without a stack.
func panicDetail(pe *life.PanicError) string {
	text := strings.TrimPrefix(pe.Error(), "panic in "+pe.Where()+": ")
	return truncate("panic:"+pe.Where()+": "+text, maxDetail)
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
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
	if err := life.Safe("coord.finish", func() { s.closeState(t, now, &e) }); err != nil {
		s.c.noteCallbackPanic(s.id, err)
	}
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
	st.gen++
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
		if err := life.Safe(fiFinishConns, func() {
			l.close()
			cs := l.conn.Stats()
			ctr.FramesIn[i], ctr.FramesOut[i] = cs.FramesIn, cs.FramesOut
			ctr.UnknownFrames += cs.Discarded
		}); err != nil {
			s.c.noteCallbackPanic(s.id, err)
		}
	}
}

// step runs one step of finish. The step's fault point and its work have a
// recover boundary each: a fault at the point — a panic, or an injected
// error, which stands for the step failing — is reported and the work still
// runs, so that no failure keeps a resource; a panic in the work is reported
// and skips no later step.
func (s *Session) step(point string, work func()) {
	if err := life.Safe(point, func() {
		if err := faultinject.Point(point); err != nil {
			panic(err)
		}
	}); err != nil {
		s.c.noteCallbackPanic(s.id, err)
	}
	if err := life.Safe(point, work); err != nil {
		s.c.noteCallbackPanic(s.id, err)
	}
}

// settleLocked adjusts the end to the state it meets: a server shutdown in
// confirming keeps the confirmations, and a half-confirmed success warns
// peer_result_missing.
func (s *Session) settleLocked(t terminal, prev State) terminal {
	st := &s.st
	if prev == StateConfirming && t.code == protocol.ReasonServerShutdown {
		t = terminal{}
	}
	if t.code == "" && st.confirmed[0] != st.confirmed[1] {
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
		if l == nil || l.dead || st.gone[r] || st.confirmed[r] || (role == t.failed && !t.notifyFailed) {
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
	res.Confirmed = st.confirmed
	res.Warn = slices.Clone(st.warn)
	res.PairClass = st.cls.PairClass
	res.MemoryHit = st.memHit
	res.Rounds = slices.Clone(st.records)
	res.Counters = st.ctr
	res.Clients = st.finals
	if st.hasKey {
		res.StrategyKey = st.memKey.String()
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
	if st.round > 0 {
		res.Timing.FirstGo = s.at(st.firstGoAt)
	}
	if first, ok := st.firstConfirm(); ok {
		res.Timing.FirstConfirm = s.at(first)
	}
	if st.round > 0 && !st.cur.evaluating {
		// The round under way ends with the session.
		res.Rounds = append(res.Rounds, s.recordLocked(st.cur.classNow(), now))
	}
	for i := range min(st.tlN, timelineCap) {
		res.Timeline = append(res.Timeline, st.timeline[(st.tlN-min(st.tlN, timelineCap)+i)%timelineCap])
	}
	if res.Reason == "" && st.winRound > 0 {
		res.Winner = &WinnerInfo{Round: st.winRound, Variant: st.winVar, Family: st.winFam, Path: st.paths}
		for r, f := range st.finals {
			if f != nil && f.OK {
				res.Winner.ExtraPaths[r] = slices.Clone(f.ExtraPaths)
			}
		}
	}
	streak := s.c.limiter.noteOutcome(s.keys[0], t.code == protocol.ReasonCandidateTimeout)
	res.Retry = retryFor(t.code, t.detail, streak)
	if t.code != "" {
		res.Retry.Advice = st.cls.Advice
	}
	res.Retry.BackgroundOnly = st.bgOnly
	if len(res.Warn) > maxWarn {
		res.Warn = res.Warn[:maxWarn]
	}
	return res
}

// firstConfirm is the session time of the first confirmation.
func (st *sessionState) firstConfirm() (time.Duration, bool) {
	switch {
	case st.confirmed[0] && st.confirmed[1]:
		return min(st.confirmAt[0], st.confirmAt[1]), true
	case st.confirmed[0]:
		return st.confirmAt[0], true
	case st.confirmed[1]:
		return st.confirmAt[1], true
	}
	return 0, false
}

func (st *sessionState) addWarn(w protocol.Warning) {
	if !slices.Contains(st.warn, w) && len(st.warn) < maxWarn {
		st.warn = append(st.warn, w)
	}
}

// feedbackLocked captures the memory feedback of the session: the strategy
// memory learns from finished rounds and the traits memory from the
// merged views corrected by punch_result.traits.
func (s *Session) feedbackLocked(res *Result) feedback {
	st := &s.st
	fb := feedback{memory: st.memory, key: st.memKey, rounds: res.Rounds}
	if res.Winner != nil {
		fb.winRound = res.Winner.Round
	}
	if !st.hasKey {
		fb.memory = nil
	}
	if s.c.set.traits == nil || s.c.set.unverified || s.ablate.NoMemory || !st.planned {
		return fb
	}
	for r, v := range st.rawViews {
		for _, fv := range v.Families {
			final := fv.Traits
			if f := st.finals[r]; f != nil {
				for _, u := range f.Traits {
					if u.Family == fv.Family {
						final = applyTraitsUpdate(final, u)
					}
				}
			}
			if !final.PublicIP.IsValid() {
				continue
			}
			fb.traits = append(fb.traits, traitsNote{
				key:   natprobe.TraitsKey{ClientKey: s.keys[r], Family: fv.Family, PublicIP: final.PublicIP},
				final: final,
			})
		}
	}
	return fb
}

// applyTraitsUpdate applies a punch-time correction; a correction of the
// mapping or the filtering from another address natprobe or the peer stands
// for (peer, alt) is cross-IP evidence. Hairpin is no other address, and a
// STUN server is only a hint: the traits memory
// must not learn a cross-IP mapping from it.
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
		case rr.Class == RoundNoContact || rr.Class == RoundOneWay || rr.Class == RoundBlocked:
			mr = MemFailure
		default:
			continue
		}
		if err := life.Safe("coord.memory", func() {
			if faultinject.Point(fiMemory) != nil {
				return
			}
			fb.memory.Report(fb.key, rr.Variant, mr)
		}); err != nil {
			s.c.noteCallbackPanic(s.id, err)
			return
		}
	}
}

// observeTraits records the final traits of both sides.
func (s *Session) observeTraits(fb feedback, succeeded bool) {
	mem := s.c.set.traits
	for _, n := range fb.traits {
		if err := life.Safe("coord.traits", func() { mem.Observe(n.key, n.final, succeeded) }); err != nil {
			s.c.noteCallbackPanic(s.id, err)
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

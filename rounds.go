package holepunch

import (
	"context"
	"slices"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/internal/trunc"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// Round constants.
const (
	maxGoDelay      = protocol.MaxDelayMs * time.Millisecond
	waitSlack       = 2 * time.Second // client waits mirroring a server deadline add 2 s
	confirmGrace    = 500 * time.Millisecond
	roundJoin       = time.Second
	extraStageIndex = 8 // cand stage of peer_targets and follow-up packets (wire stages are 0–7)
	pendingAssists  = 8 // peer_targets assists kept for the next round
)

// Fault-injection point of the stage goroutines.
const fiRoundStage = "round.stage"

// roundRun is one round in flight: its plan, fire time and family goroutines.
type roundRun struct {
	plan     protocol.RoundPlan
	goAt     time.Time // the instant the punch_go frame was read
	fireAt   time.Time // goAt + delay_ms
	firedAt  time.Time
	end      time.Time // fireAt + window
	fired    bool
	ctx      context.Context
	cancel   context.CancelFunc
	fams     []*familyRound
	live     atomic.Int32  // family goroutines still running
	done     chan struct{} // closed when the last one returns
	fatal    atomic.Pointer[protocol.Reason]
	birthday bool
}

func (rt *runtime) currentRound() uint8 {
	if r := rt.curRound.Load(); r != nil {
		return r.plan.Round
	}
	return 1
}

// punchLoop runs the punching phase, from waiting for the first go to the
// handover: it waits for the first go, runs the rounds the server starts —
// preempting a running round when a larger one arrives — reports each with
// round_result, and ends on the handover, a failure or a deadline: the
// handshake timeout for all rounds from the first go, the gap deadline between
// rounds, the 500 ms confirmation grace, and the handover timeout once
// confirmed. A dead control link before Confirm lets the current round run out
// plus 500 ms and starts no new round; after Confirm the control link no longer
// matters.
func (rt *runtime) punchLoop() (*candidate.Action, error) {
	ctx := rt.g.Context()
	st := rt.punch
	timer := rt.clk.NewTimer(time.Hour)
	defer timer.Stop()
	var (
		cur                              *roundRun
		goDeadline                       = rt.readyAt.Add(rt.waits.goWait)
		handshakeDeadline, gapEnd, grace time.Time
		handoverDeadline                 time.Time
		keepalive                        = rt.clk.Now().Add(rt.pace.spread(keepaliveInterval, 0.1))
		gotGo                            bool
		ctlDead                          bool
		ctlFail                          *failure
		confirmHandled                   bool
		handshakeExpired                 bool
		pending                          carried
	)
	defer func() {
		if cur != nil {
			rt.stopRound(cur)
		}
	}()
	ctlDone := rt.ctl.conn.Done()
	if err := faultinject.Point(fiWaitGo); err != nil {
		return nil, err
	}
	for {
		// Once expired, the handshake deadline stays in the past: left in,
		// it would hold the timer at zero and spin until the grace ends.
		next := earliest(whenIf(!gotGo, keepalive), whenIf(!gotGo, goDeadline), whenIf(!handshakeExpired, handshakeDeadline),
			gapEnd, grace, handoverDeadline)
		if cur != nil && cur.ctx.Err() == nil { // a stopped round neither fires nor ends
			if cur.fired {
				next = earliest(next, cur.end)
			} else {
				next = earliest(next, cur.fireAt)
			}
		}
		timer.Reset(max(next.Sub(rt.clk.Now()), 0))
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-rt.pg.Context().Done():
			return nil, context.Cause(rt.pg.Context())
		case <-st.woken():
		case g := <-rt.ctl.goCh:
			// A go read before the local Confirm may still be queued when
			// the nomination goroutine confirms: it starts no round, and
			// round_result{confirmed} reports the round that confirmed.
			if confirmHandled || st.isConfirmed() || ctlDead || handshakeExpired {
				break
			}
			if !gotGo {
				gotGo = true
				handshakeDeadline = g.at.Add(rt.waits.handshake)
				rt.timing.goWait = max(g.at.Sub(rt.readyAt), 0) // an eager go may come before the ready went out
				rt.firstGoAt = g.at
			}
			if cur != nil {
				rt.stopRound(cur) // preempted: no round_result
			}
			gapEnd = time.Time{}
			cur = rt.startRound(g, pending)
			pending = carried{}
		case a := <-rt.ctl.assistCh:
			if !confirmHandled {
				rt.handleAssist(a, cur, &pending)
			}
		case ab := <-rt.ctl.abortCh:
			if st.isConfirmed() {
				rt.addWarn(protocol.WarnAbortAfterConfirm) // after Confirm a server abort is only recorded
				continue
			}
			return nil, rt.punchAbortFailure(ab.msg)
		case f := <-rt.ctl.faultCh:
			if !st.isConfirmed() {
				return nil, f
			}
		case <-ctlDone:
			ctlDone = nil
			if st.isConfirmed() {
				rt.addWarn(protocol.WarnControlLostAfterConfirm) // after Confirm a lost control link is only recorded
				continue
			}
			if ab, ok := rt.ctl.lateAbort(); ok {
				return nil, rt.punchAbortFailure(ab.msg)
			}
			ctlFail = ctlCause(rt.ctl.conn.Err())
			if ctlFail.reason != protocol.ReasonControlInterrupted || !gotGo {
				return nil, ctlFail
			}
			ctlDead = true
			gapEnd = time.Time{}
			if cur != nil && cur.ctx.Err() == nil {
				grace = cur.end.Add(confirmGrace)
			} else {
				grace = rt.clk.Now().Add(confirmGrace)
			}
		case <-timer.C():
		}

		now := rt.clk.Now()
		if st.isConfirmed() && !confirmHandled {
			confirmHandled = true
			// Only the handover is left to wait for. A Confirm can come before
			// the first go; the keepalive, renewed no more, would then spin the
			// loop once passed.
			keepalive, goDeadline, handshakeDeadline, gapEnd, grace = time.Time{}, time.Time{}, time.Time{}, time.Time{}, time.Time{}
			handoverDeadline = st.confirmTime().Add(time.Duration(rt.timeouts.HandoverTimeoutMs) * time.Millisecond)
			rt.reportConfirmed(cur)
			if cur != nil {
				rt.stopRound(cur)
			}
		}
		if a, failed := st.outcome(); a != nil {
			return a, nil
		} else if failed {
			return nil, fail(protocol.ReasonHandoverTimeout, "", nil)
		}
		if confirmHandled {
			if !handoverDeadline.IsZero() && !now.Before(handoverDeadline) {
				return nil, fail(protocol.ReasonHandoverTimeout, "", nil)
			}
			continue
		}
		if cur != nil && !cur.fired && cur.ctx.Err() == nil && !now.Before(cur.fireAt) {
			rt.fire(cur, now)
		}
		if cur != nil && cur.ctx.Err() == nil && (cur.fatal.Load() != nil || cur.fired && !now.Before(cur.end)) {
			rt.endRound(cur, ctlDead)
			if !ctlDead {
				gapEnd = rt.gapDeadline(now, handshakeDeadline)
			}
		}
		if !gotGo && !now.Before(keepalive) {
			rt.sendKeepalive()
			keepalive = now.Add(rt.pace.spread(keepaliveInterval, 0.1))
		}
		switch {
		case !gotGo && !goDeadline.IsZero() && !now.Before(goDeadline):
			return nil, fail(protocol.ReasonControlTimeout, "go_wait", nil)
		case !grace.IsZero() && !now.Before(grace):
			if ctlDead {
				return nil, ctlFail
			}
			return nil, rt.attribute()
		case !handshakeDeadline.IsZero() && !now.Before(handshakeDeadline) && !handshakeExpired:
			handshakeExpired = true
			gapEnd = time.Time{}
			if cur != nil && cur.ctx.Err() == nil {
				rt.stopRound(cur)
			}
			// The handshake timeout ends the punching once: the current
			// round stops and only the confirmation grace is left. A
			// caller's cancellation never gets here: it ends the session at
			// once through ctx.
			grace = now.Add(confirmGrace)
		case !gapEnd.IsZero() && !now.Before(gapEnd):
			return nil, rt.attribute()
		}
	}
}

func whenIf(ok bool, t time.Time) time.Time {
	if ok {
		return t
	}
	return time.Time{}
}

// earliest returns the earliest non-zero time, or a far one when all are
// zero (the loop then only wakes on events: no polling).
func earliest(ts ...time.Time) time.Time {
	var best time.Time
	for _, t := range ts {
		if !t.IsZero() && (best.IsZero() || t.Before(best)) {
			best = t
		}
	}
	if best.IsZero() {
		return farFuture
	}
	return best
}

// farFuture is the wake-up time of a loop with nothing scheduled.
var farFuture = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// gapDeadline is the wait for the next go between rounds: go_wait + 2 s
// after the round_result, within the handshake deadline.
func (rt *runtime) gapDeadline(now, handshakeDeadline time.Time) time.Time {
	d := now.Add(rt.waits.goWait)
	if !handshakeDeadline.IsZero() && handshakeDeadline.Before(d) {
		return handshakeDeadline
	}
	return d
}

func abortFailure(ab protocol.Abort) *failure {
	f := fail(msgframe.AbortReason(ab.By, ab.Reason), trunc.String(ab.Detail, protocol.MaxDetail), nil)
	f.abortedBy = ab.By
	f.retryAfter = time.Duration(ab.RetryAfterMs) * time.Millisecond
	return f
}

// punchAbortFailure is how a punch_abort before the local Confirm ends the
// punching phase. A side whose every write has failed for blockedAfter reported
// round_result{fatal, udp_blocked} and ends with that local reason: the
// server's code — candidate_timeout while only this side is blocked — explains
// the session, not this host. The abort's sender and retry advice are kept
// either way.
func (rt *runtime) punchAbortFailure(ab protocol.Abort) *failure {
	f := abortFailure(ab)
	if !rt.udpBlocked.Load() {
		return f
	}
	local := rt.attribute()
	local.abortedBy, local.retryAfter = f.abortedBy, f.retryAfter
	return local
}

// startRound prepares a round from its punch_go: the plan (round 1's is the
// summary's, the one punch_ready bound sockets for, or that plan re-aimed by
// the go's anchor update; every later go carries its own), the clamps, the
// sockets, the spray seed, the peer_targets carried
// from between rounds and one goroutine per family.
// Firing happens at goAt + delay_ms, measured from the instant the frame was
// read.
func (rt *runtime) startRound(g stamped[protocol.PunchGo], pending carried) *roundRun {
	gm := g.msg
	goPlan := gm.Plan
	if gm.Round == 1 && goPlan == nil {
		goPlan = &rt.summary.Plan.Round1
	}
	rp, _ := rt.clampRound(*goPlan)
	delay := min(time.Duration(gm.DelayMs)*time.Millisecond, maxGoDelay)
	if rt.abl.NoRTTAlign {
		delay = 0
	}
	window := time.Duration(rp.WindowMs) * time.Millisecond
	ctx, cancel := context.WithCancel(rt.pg.Context())
	run := &roundRun{plan: rp, goAt: g.at, fireAt: g.at.Add(delay), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	run.end = run.fireAt.Add(window)
	rt.lastRTT = time.Duration(gm.RTTMs) * time.Millisecond
	rt.roundsRun = append(rt.roundsRun, rp.Clone())
	var fams []protocol.Family
	limits, _ := rp.Budget.Limits()
	ceil := newRoundCeiling(limits, rp.Sides)
	rt.sender.startRound(rt.clk.Now(), int(limits.MaxDistinctPorts))
	for _, side := range rp.Sides {
		w := rt.fam(side.Family).worker
		if w == nil {
			continue
		}
		fr := &familyRound{rt: rt, run: run, w: w, side: side, inject: make(chan []extraTarget, 16)}
		fr.meter = newRoundMeter(side.Family, rp.Round, side, ceil)
		fr.socks, fr.bindFailed = rt.socks.roundSockets(rt.g.Context(), w.primary, side.SocketsBeforeFiring(), roundPurpose(side))
		if side.OpenPerSec > 0 {
			fr.paced, fr.tried = make([]*udpSock, side.Sockets), make([]bool, side.Sockets)
		}
		fr.seed = udpwire.SpraySeed(rt.start.Token, rt.start.Wire.RouteID, rt.codec.Role(), rp.Round, rp.Seed)
		if len(fr.socks) > 1 && hasStage(side, protocol.StageRandom) {
			run.birthday = true
		}
		run.fams = append(run.fams, fr)
		fams = append(fams, side.Family)
	}
	rt.punch.newRound(rp.Round, fams)
	rt.curRound.Store(run)
	run.live.Store(int32(len(run.fams)))
	if len(run.fams) == 0 {
		close(run.done)
	}
	for _, fr := range run.fams {
		var mine []extraTarget
		for _, p := range pending.targets {
			if p.to.Addr().Is4() == (fr.w.fam == protocol.FamilyUDP4) {
				mine = append(mine, p)
			}
		}
		fr.rejected.Store(int32(pending.rejected[fr.w.fam.Index()]))
		if len(mine) > 0 {
			fr.inject <- mine
		}
		if !rt.pg.Go("round:"+string(fr.w.fam), fr.execute) {
			run.exited()
		}
	}
	rt.progress(progressEvent{stage: stageGoReceived, status: protocol.StatusInfo, round: rp.Round})
	return run
}

// clampRound is the round plan p as this side runs it: normalized and
// clamped to the session budget. changed reports that either altered it.
func (rt *runtime) clampRound(p protocol.RoundPlan) (rp protocol.RoundPlan, changed bool) {
	rp, normalized := p.Normalize()
	rp, tightened := rp.ClampTo(rt.sessBudget)
	return rp, normalized || tightened
}

func hasStage(side protocol.FamilySide, k protocol.StageKind) bool {
	return slices.ContainsFunc(side.Stages, func(s protocol.Stage) bool { return s.Kind == k })
}

// fire marks the round's firing instant: phase punching, progress fire.
func (rt *runtime) fire(run *roundRun, now time.Time) {
	run.fired, run.firedAt = true, now
	rt.fired = true
	if run.birthday {
		rt.birthdayRan = true
	}
	for _, fr := range run.fams {
		rt.phases.advanceFamily(fr.w.fam, protocol.PhasePunching, "round_started", now)
	}
	rt.progress(progressEvent{stage: stageFire, status: protocol.StatusInfo, round: run.plan.Round})
}

// exited records that one family goroutine of the round returned.
func (run *roundRun) exited() {
	if run.live.Add(-1) == 0 {
		close(run.done)
	}
}

// stopRound cancels a round and waits for its goroutines, which return
// within one token interval of the cancellation. The bound is real time: it
// guards goroutine scheduling, not a protocol deadline.
func (rt *runtime) stopRound(run *roundRun) {
	run.cancel()
	t := time.NewTimer(roundJoin)
	defer t.Stop()
	select {
	case <-run.done:
	case <-t.C:
	}
}

// endRound stops a round at its window end (or on a fatal local error) and
// reports it, unless the control link is gone.
func (rt *runtime) endRound(run *roundRun, ctlDead bool) {
	rt.stopRound(run)
	status := protocol.RoundWindowEnd
	var code protocol.Reason
	if r := run.fatal.Load(); r != nil {
		status, code = protocol.RoundFatal, *r
	}
	fams := rt.outcomes(run)
	for _, f := range fams {
		if f.BudgetHit && status == protocol.RoundWindowEnd {
			status = protocol.RoundBudgetExhausted
		}
	}
	var sent, recv, ports uint32
	for _, f := range fams {
		sent += f.Sent
		recv += f.Recv
		ports = max(ports, uint32(f.DistinctPorts))
	}
	rt.phases.note(stageRoundEnd)
	rt.progress(progressEvent{stage: stageRoundEnd, status: protocol.StatusInfo, round: run.plan.Round,
		counters: map[string]uint32{"sent": sent, "recv": recv, "distinct_ports": ports}})
	if ctlDead {
		return
	}
	rt.sendRoundResult(run, status, code, fams, nil)
}

// outcomes builds round_result.families[] from the round's evidence.
func (rt *runtime) outcomes(run *roundRun) []protocol.FamilyOutcome {
	var out []protocol.FamilyOutcome
	for _, fr := range run.fams {
		ms := rt.sender.meterStats(fr.meter)
		rs := rt.punch.roundEvidence(fr.w.fam)
		out = append(out, protocol.FamilyOutcome{
			Family: fr.w.fam, Hit: rs.hit, SeenFrom: rs.seenFrom,
			PeerSeenUs: rs.peerSeenUs, Sent: uint32(ms.sent), Recv: uint32(rs.recv),
			DistinctPorts: uint16(min(ms.distinctPorts, 0xFFFF)), ICMPUnreach: uint16(min(rs.icmp, 0xFFFF)),
			BindFailed: uint16(min(fr.bindFailed+int(fr.lateFailed.Load()), 0xFFFF)), BudgetHit: ms.budgetHit, Drift: rs.drift,
			Halted:   fr.halted.Load(),
			Rejected: uint16(min(fr.rejected.Load(), 0xFFFF)), Remap: rs.remap,
		})
	}
	return out
}

// sendRoundResult writes round_result; elapsed_ms runs from the go's read.
func (rt *runtime) sendRoundResult(run *roundRun, status protocol.RoundStatus, code protocol.Reason, fams []protocol.FamilyOutcome, path *protocol.PathInfo) {
	rr := protocol.RoundResult{SessionID: rt.start.SessionID, Role: rt.role, Round: run.plan.Round, Status: status, Reason: code, Families: fams, Path: path}
	if run.fired {
		rr.FireSkewMs = int16(max(min(run.firedAt.Sub(run.fireAt)/time.Millisecond, 32767), -32768))
	}
	_ = sendElapsed(rt.ctl, rr, run.goAt, func(r *protocol.RoundResult, ms uint32) { r.ElapsedMs = ms })
}

// reportConfirmed writes round_result{confirmed, path} at once: the
// server's signal to stop new rounds and wind down.
func (rt *runtime) reportConfirmed(cur *roundRun) {
	path := rt.punch.path()
	run := cur
	if run == nil {
		run = &roundRun{plan: protocol.RoundPlan{Round: path.Round}, goAt: rt.punch.confirmTime()}
	}
	rt.sendRoundResult(run, protocol.RoundConfirmed, "", rt.outcomes(run), &path)
}

// sleepUntil waits for t on the session clock, or for ctx.
func (rt *runtime) sleepUntil(ctx context.Context, t time.Time) error {
	return rt.sleep(ctx, t.Sub(rt.clk.Now()))
}

// sleep waits for d on the session clock, or for ctx.
func (rt *runtime) sleep(ctx context.Context, d time.Duration) error { return sleepOn(ctx, rt.clk, d) }

// sleepOn waits for d on clk, or for ctx.
func sleepOn(ctx context.Context, clk clock.Clock, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := clk.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-t.C():
		return nil
	}
}

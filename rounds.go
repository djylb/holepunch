package holepunch

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// Round constants.
const (
	maxGoDelay      = 2 * time.Second
	waitSlack       = 2 * time.Second // client waits mirroring a server deadline add 2 s
	confirmGrace    = 500 * time.Millisecond
	roundJoin       = time.Second
	extraStageIndex = 8 // cand stage of peer_targets and follow-up packets (wire stages are 0–7)
	maxCandIndex    = 0x0FFF
	maxRoundExtras  = 64 // peer_targets targets per family and round
	pendingAssists  = 8  // peer_targets assists kept for the next round
)

// Fault-injection point of the stage goroutines.
const fiRoundStage = "round.stage"

// sendItem is one initiated packet of a round's schedule.
type sendItem struct {
	due   time.Time
	sock  *udpSock
	to    netip.AddrPort
	cand  uint16
	stage txStage
	hops  int
	quota sendQuota // quotaPlan or quotaTargets
	// slot is a paced socket of the round (FamilySide.OpenPerSec), opened
	// when its first item is due; sock is nil until then. 0 for none.
	slot int
}

// extraTarget is a target pushed by peer_targets: sent at once
// from the primary socket, targetPackets times, on the round's peer_targets
// quota. window marks a port of the assist's port window, which the
// round sends in the order of its spray seed (scatterWindows).
type extraTarget struct {
	to     netip.AddrPort
	kind   candidate.Kind
	window bool
}

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

// familyRound executes one family's side of a round (roundExecutor).
type familyRound struct {
	rt         *runtime
	run        *roundRun
	w          *worker
	side       protocol.FamilySide
	meter      *roundMeter
	socks      []*udpSock
	bindFailed int
	// lateFailed counts the round's sockets the round goroutine could not
	// bind — fresh and paced ones — while round_result may
	// be built, so it is atomic.
	lateFailed atomic.Int32
	// paced are the round's paced sockets by slot (OpenPerSec),
	// opened by the round goroutine; tried marks the slots it attempted.
	// Only that goroutine touches them.
	paced, owned []*udpSock
	tried        []bool
	bindRun      int         // consecutive paced bind failures
	writeFails   []time.Time // recent send failures of a background round
	halted       atomic.Bool // stopped initiating on a failure spike (round_result.halted)
	seed         [8]byte
	inject       chan []extraTarget
	extras       atomic.Int32 // peer_targets targets scheduled this round
	rejected     atomic.Int32 // targets admission refused this round (round_result.rejected)
	budgetSaid   atomic.Bool
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
		case <-st.wake:
		case g := <-rt.ctl.goCh:
			// A go read before the local Confirm may still be queued when
			// the nomination goroutine confirms: it starts no round, and
			// round_result{confirmed} reports the round that confirmed.
			if confirmHandled || st.confirmed.Load() || ctlDead || handshakeExpired {
				break
			}
			if !gotGo {
				gotGo = true
				handshakeDeadline = g.at.Add(rt.waits.handshake)
				rt.timing.goWait = g.at.Sub(rt.readyAt)
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
			if st.confirmed.Load() {
				rt.addWarn(warnAbortAfterConfirm) // after Confirm a server abort is only recorded
				continue
			}
			return nil, rt.punchAbortFailure(ab.msg)
		case f := <-rt.ctl.faultCh:
			if !st.confirmed.Load() {
				return nil, f
			}
		case <-ctlDone:
			ctlDone = nil
			if st.confirmed.Load() {
				rt.addWarn(warnControlLostAfterConfirm) // after Confirm a lost control link is only recorded
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
		if st.confirmed.Load() && !confirmHandled {
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
		if cur != nil && cur.ctx.Err() == nil && cur.fatal.Load() != nil {
			rt.endRound(cur, ctlDead)
			if !ctlDead {
				gapEnd = rt.gapDeadline(now, handshakeDeadline)
			}
		}
		if cur != nil && cur.fired && cur.ctx.Err() == nil && !now.Before(cur.end) {
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
	f := fail(protocol.AbortReason(ab.By, ab.Code), truncDetail(ab.Detail), nil)
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
	rp, _ := goPlan.Normalize()
	rp, _ = rp.ClampTo(rt.sessBudget)
	delay := min(time.Duration(gm.DelayMs)*time.Millisecond, maxGoDelay)
	if rt.abl.NoRTTAlign {
		delay = 0
	}
	window := time.Duration(rp.WindowMs) * time.Millisecond
	ctx, cancel := context.WithCancel(rt.pg.Context())
	run := &roundRun{plan: rp, goAt: g.at, fireAt: g.at.Add(delay), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	run.end = run.fireAt.Add(window)
	rt.lastRTT = time.Duration(gm.RTTMs) * time.Millisecond
	rt.roundsRun = append(rt.roundsRun, cloneRound(rp))
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
		fr.socks, fr.bindFailed = rt.socks.roundSockets(rt.g.Context(), w.primary, socketsBeforeFiring(side), roundPurpose(side))
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
		fr.rejected.Store(int32(pending.rejected[famIndex(fr.w.fam)]))
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
	st := rt.punch
	var out []protocol.FamilyOutcome
	for _, fr := range run.fams {
		rt.sender.mu.Lock()
		sent, hit, ports := fr.meter.sent, fr.meter.budgetHit, fr.meter.distinctPorts()
		rt.sender.mu.Unlock()
		st.mu.Lock()
		rs := st.statsFor(fr.w.fam)
		o := protocol.FamilyOutcome{
			Family: fr.w.fam, Hit: rs.hit, SeenFrom: append([]netip.AddrPort(nil), rs.seenFrom...),
			PeerSeenUs: rs.peerSeenUs, Sent: uint32(sent), Recv: uint32(rs.recv),
			DistinctPorts: uint16(min(ports, 0xFFFF)), ICMPUnreach: uint16(min(rs.icmp, 0xFFFF)),
			BindFailed: uint16(min(fr.bindFailed+int(fr.lateFailed.Load()), 0xFFFF)), BudgetHit: hit, Drift: rs.drift,
			Halted:   fr.halted.Load(),
			Rejected: uint16(min(fr.rejected.Load(), 0xFFFF)), Remap: cloneRemap(rs.remap),
		}
		st.mu.Unlock()
		out = append(out, o)
	}
	return out
}

// sendRoundResult writes round_result; elapsed_ms runs from the go's read.
func (rt *runtime) sendRoundResult(run *roundRun, status protocol.RoundStatus, code protocol.Reason, fams []protocol.FamilyOutcome, path *protocol.PathInfo) {
	rr := protocol.RoundResult{SessionID: rt.start.SessionID, Role: rt.role, Round: run.plan.Round, Status: status, Code: code, Families: fams, Path: path}
	if run.fired {
		rr.FireSkewMs = int16(max(min(run.firedAt.Sub(run.fireAt)/time.Millisecond, 32767), -32768))
	}
	goAt := run.goAt
	_ = rt.ctl.sendBuilt(controlwire.TypeRoundResult, func(now time.Time) protocol.Message {
		r := rr
		r.ElapsedMs = elapsedMs(goAt, now)
		return r
	})
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

// execute is a family's round goroutine: it builds the round's schedule —
// direct stages on every round socket, predict and random targets spread over
// them — waits for the fire instant and sends through the gate until the
// round is stopped. Direct packets keep their offsets; spraying fills the
// gaps at the rate the buckets allow. Once a valid peer packet arrived,
// spraying stops and only answered targets get more packets. A grant spent
// ends the planned stages (budget_hit) but not the round: pushed targets
// have their own quota and are still sent. A packet the run guard
// holds back (runs.go) waits until another packet has left, which breaks or
// moves the run, and is then tried again before anything else: it is
// overdue, and the next packet may close the gap it needs.
func (fr *familyRound) execute(context.Context) {
	defer fr.run.exited()
	ctx := fr.run.ctx // derived from the punching group's: canceled by the round's end too
	rt := fr.rt
	if err := faultinject.Point(fiRoundStage); err != nil {
		return
	}
	// Fresh sockets are bound before the fire time, paced ones while the
	// round runs; both are released when the round ends, unless the peer
	// reached one: its pairs are candidates.
	fresh := fr.bindFresh(ctx)
	fr.owned = append(fr.owned, fresh...)
	defer fr.releaseOwned()
	direct, spray := fr.schedule(fresh)
	// The sandwich helper is new every round, bound before the fire time and
	// closed when the round ends: a socket that probed both observers in an
	// earlier round would reuse those mappings and bracket nothing.
	var helper *udpSock
	if fr.side.Sandwich && rt.sandwichOK() && len(fr.w.fs.observers) > int(nat.SandwichAfter) && len(direct)+len(spray) > 0 {
		if helper = rt.socks.sandwichHelper(ctx, fr.w.primary); helper != nil {
			defer rt.socks.release(helper)
		}
	}
	if rt.sleepUntil(ctx, fr.run.fireAt) != nil {
		return
	}
	before, after := helper != nil, helper != nil // the probes around the round's first punch
	reobserveAt := fr.reobserveAt()               // zero once done, or when the round does not re-observe
	var held, again []sendItem                    // held back by the run guard; to try again now
	for ctx.Err() == nil {
		select {
		case more := <-fr.inject:
			direct = append(fr.extraItems(more, rt.clk.Now()), direct...)
		default:
		}
		if fr.halted.Load() {
			// A halted round initiates nothing more; it still answers
			// through the read loops until it ends.
			direct, spray, held, again = nil, nil, nil, nil
			fr.waitUntil(ctx, farFuture)
			continue
		}
		now := rt.clk.Now()
		if !reobserveAt.IsZero() && !now.Before(reobserveAt) {
			fr.reobserve(ctx)
			reobserveAt = time.Time{}
			continue
		}
		converged := rt.punch.converged.Load()
		var it sendItem
		switch {
		case len(again) > 0:
			it, again = again[0], again[1:]
		case len(direct) > 0 && !direct[0].due.After(now):
			it, direct = direct[0], direct[1:]
		case !converged && len(spray) > 0 && !spray[0].due.After(now):
			it, spray = spray[0], spray[1:]
		default:
			wake := farFuture
			if len(direct) > 0 {
				wake = direct[0].due
			}
			if !converged && len(spray) > 0 && spray[0].due.Before(wake) {
				wake = spray[0].due
			}
			if !reobserveAt.IsZero() && reobserveAt.Before(wake) {
				wake = reobserveAt
			}
			fr.waitUntil(ctx, wake)
			continue
		}
		if it.slot > 0 {
			// A paced socket opens when its first packet is due; none opens
			// once the peer heard us, or after a halt.
			if it.sock = fr.pacedSocket(ctx, it.slot); it.sock == nil {
				continue
			}
		}
		if converged && !rt.punch.isHit(it.to) && !fr.keepAfterContact(it) {
			continue
		}
		if it.hops > 0 && rt.punch.isHit(it.to) {
			it.hops = 0 // an answered target gets normal TTL (receiver_full)
		}
		if before {
			fr.sandwichProbe(ctx, helper, nat.SandwichBefore)
			before = false
		}
		h := udpwire.Header{Type: udpwire.TPunch, Round: fr.run.plan.Round, Cand: it.cand}
		err := rt.sender.Send(ctx, it.sock, it.to, &h, nil,
			sendOpt{class: classInitiate, stage: it.stage, hops: it.hops, round: fr.meter, quota: it.quota})
		if errors.Is(err, errRun) {
			held = append(held, it)
			continue
		}
		if after {
			fr.sandwichProbe(ctx, helper, nat.SandwichAfter)
			after = false
		}
		if it.hops > 0 && it.sock.noLowTTL.Load() {
			rt.lowTTLDegraded(fr.w)
		}
		switch {
		case err == nil:
			again, held = append(again, held...), held[:0]
		case errors.Is(err, errBudget) && it.quota == quotaTargets:
		case errors.Is(err, errBudget):
			if !fr.budgetSaid.Swap(true) {
				rt.progress(progressEvent{stage: stageBudgetExhausted, status: protocol.StatusInfo, family: fr.w.fam, round: fr.run.plan.Round})
			}
			planned := func(it sendItem) bool { return it.quota == quotaPlan }
			direct, held, again = slices.DeleteFunc(direct, planned), slices.DeleteFunc(held, planned), slices.DeleteFunc(again, planned)
			spray = nil
		case errors.Is(err, errStopped):
			return
		case errors.Is(err, errUnreachable):
			direct = dropTarget(direct, it.to)
			spray = dropTarget(spray, it.to)
			held, again = dropTarget(held, it.to), dropTarget(again, it.to)
		case errors.Is(err, errRejected):
			// The gate's target limits refused it: nothing was written,
			// so it is no write failure.
		default:
			if rt.sender.writeBlocked(rt.clk.Now()) {
				r := protocol.ReasonUDPBlocked
				fr.run.fatal.CompareAndSwap(nil, &r)
				rt.udpBlocked.Store(true)
				rt.punch.notify()
				return
			}
			fr.writeSpike(rt.clk.Now())
		}
	}
}

// keepAfterContact reports whether a session that may keep extra paths
// still sends a planned packet once the peer was heard: a Direct packet of
// the family's primary socket, so that the other families and kinds of
// network get their chance to carry the peer's packets before the
// nomination picks the extra paths. Spraying stops
// as always, and Confirm stops everything.
func (fr *familyRound) keepAfterContact(it sendItem) bool {
	return fr.rt.opts.MaxPaths > 1 && it.stage == txDirect && it.slot == 0 && it.sock == fr.w.primary
}

// Failure spikes that halt a background round: this many paced
// sockets failing to bind in a row, or this many send failures within
// spikeWindow.
const (
	haltBindRun  = 8
	haltWrites   = 8
	spikeWindow  = time.Second
	pacedPurpose = PurposeBirthday
)

// heardBack reports whether the peer heard us: a success packet came, or
// the server said the peer saw us.
func (st *punchState) heardBack() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.anyHit || st.peerSeen
}

// background reports whether the round is the slow birthday of a
// Background session, the one a failure spike halts.
func (fr *familyRound) background() bool { return fr.run.plan.Budget == protocol.BudgetBackground }

// socketsBeforeFiring is how many of a side's sockets the round binds
// before firing: all of them, or only the primary when they are paced.
func socketsBeforeFiring(side protocol.FamilySide) int {
	if side.OpenPerSec > 0 {
		return 1
	}
	return int(max(side.Sockets, 1))
}

// pacedSocket returns the paced socket of slot, binding it on first use on
// the primary's IP; nil once the peer heard us, after a halt, or when the
// bind failed — counted in bind_failed, and a run of haltBindRun failures
// in a background round halts it. A socket the session's socket budget or
// index space refuses is no such failure: it says nothing about the host,
// and the sockets already open keep sending. Hearing the peer is not
// enough: after a one-way round the birthday aims these sockets at the
// source heard, and only a reply from one of them can reach the peer.
func (fr *familyRound) pacedSocket(ctx context.Context, slot int) *udpSock {
	if slot >= len(fr.paced) {
		return nil
	}
	if s := fr.paced[slot]; s != nil || fr.tried[slot] {
		return s
	}
	if fr.rt.punch.heardBack() || fr.halted.Load() {
		return nil
	}
	fr.tried[slot] = true
	rt := fr.rt
	s, err := rt.socks.pacedSocket(ctx, fr.w.primary, pacedPurpose)
	if err != nil {
		fr.lateFailed.Add(1)
		if errors.Is(err, errNoSockets) {
			return nil
		}
		if fr.bindRun++; fr.bindRun >= haltBindRun && fr.background() {
			fr.halted.Store(true)
		}
		return nil
	}
	fr.bindRun = 0
	fr.paced[slot] = s
	fr.owned = append(fr.owned, s)
	for si, st := range fr.side.Stages {
		if st.Kind != protocol.StageDirect {
			continue
		}
		for ti, t := range st.Targets {
			rt.punch.planTarget(s.id, uint16(si<<12|min(ti, maxCandIndex)), netaddr.Canon(t), candidate.KindObserved)
		}
	}
	return s
}

// writeSpike notes a send failure of a background round and halts it at
// haltWrites failures within spikeWindow.
func (fr *familyRound) writeSpike(now time.Time) {
	if !fr.background() {
		return
	}
	fr.writeFails = append(slices.DeleteFunc(fr.writeFails, func(t time.Time) bool { return now.Sub(t) > spikeWindow }), now)
	if len(fr.writeFails) >= haltWrites {
		fr.halted.Store(true)
	}
}

func dropTarget(items []sendItem, to netip.AddrPort) []sendItem {
	return slices.DeleteFunc(items, func(it sendItem) bool { return it.to == to })
}

// waitUntil sleeps until t, an injected target or the end of the round.
func (fr *familyRound) waitUntil(ctx context.Context, t time.Time) {
	rt := fr.rt
	tm := rt.clk.NewTimer(max(t.Sub(rt.clk.Now()), 0))
	defer tm.Stop()
	select {
	case <-ctx.Done():
	case <-tm.C():
	case more := <-fr.inject:
		// put it back for the loop, which prepends it with fresh due times
		select {
		case fr.inject <- more:
		default:
		}
	}
}

// schedule expands the side's stages into its direct and spray items; the
// items of a fresh stage go out from the bound fresh sockets, by the index
// of their draw (nil where the bind failed).
func (fr *familyRound) schedule(fresh []*udpSock) (direct, spray []sendItem) {
	rt := fr.rt
	side, w := fr.side, fr.w
	delay := time.Duration(side.SendDelayMs) * time.Millisecond
	if rt.abl.NoRoleAssign || side.Role == protocol.SideReplyOnly {
		delay = 0
	}
	for si, st := range side.Stages {
		start := fr.run.fireAt.Add(max(time.Duration(st.AtMs)*time.Millisecond, delay))
		var hops []int
		if w.lowTTL && st.TTL > 0 && !rt.abl.NoRoleAssign {
			hops = rt.hopCycle(int(st.TTL))
		}
		if side.Role == protocol.SideReplyOnly {
			continue
		}
		switch st.Kind {
		case protocol.StageDirect:
			direct = append(direct, fr.directItems(si, st, start, hops)...)
		case protocol.StagePredict, protocol.StageRandom:
			if rt.abl.NoPrediction || w.unverified {
				fr.reject(1)
				continue
			}
			spray = append(spray, fr.sprayItems(si, st, start, hops)...)
		case protocol.StageFresh:
			direct = append(direct, fr.freshItems(si, st, start, fresh)...)
		case protocol.StageFreshPeer:
			if rt.abl.NoPrediction || w.unverified {
				fr.reject(1)
				continue
			}
			direct = append(direct, fr.freshPeerItems(si, st, start)...)
		}
	}
	slices.SortStableFunc(direct, func(a, b sendItem) int { return a.due.Compare(b.due) })
	return direct, spray
}

// reject counts n targets of this round that admission refused: in the
// session's counters and in round_result.rejected, which tells the server
// when neither side has anything to send to.
func (fr *familyRound) reject(n int) {
	fr.rt.rejectTargets(fr.w, n)
	fr.rejected.Add(int32(n))
}

func (rt *runtime) rejectTargets(w *worker, n int) {
	w.fs.cnt.targetRejected.Add(int64(n))
	w.fs.cnt.drops[dropTargetRejected].Add(int64(n))
}

// directItems repeats each admitted target on every round socket at the
// stage's offsets, the k-th repeat with the k-th hop of a low-TTL
// stage; a LAN target, or a target of an unverified family, is sent from the
// primary socket only, at most its per-round cap.
func (fr *familyRound) directItems(si int, st protocol.Stage, start time.Time, hops []int) []sendItem {
	rt, w := fr.rt, fr.w
	var out []sendItem
	for ti, t := range st.Targets {
		t = netaddr.Canon(t)
		ok, per := w.admit(rt, t, protocol.StageDirect)
		if !ok {
			fr.reject(1)
			continue
		}
		cand := uint16(si<<12 | min(ti, maxCandIndex))
		reps := max(int(st.Repeats), 1)
		socks := fr.socks
		if per > 0 {
			reps = min(reps, per)
			socks = socks[:1]
		}
		kind := candidate.KindObserved
		switch {
		case w.overlay[t.Addr()]:
			kind = candidate.KindOverlay
		case w.lan[t.Addr()]:
			kind = candidate.KindLAN
		}
		offsets := plan.DirectOffsets(fr.seed, si, ti, reps)
		if fr.paced != nil {
			offsets = fr.spread(start, reps)
		}
		for _, s := range socks {
			rt.punch.planTarget(s.id, cand, t, kind)
			for k, off := range offsets {
				out = append(out, sendItem{due: start.Add(off), sock: s, to: t, cand: cand, stage: txDirect, hops: hopAt(hops, k)})
			}
		}
		if per == 0 {
			out = append(out, fr.pacedItems(t, cand, reps, start, hops)...)
		}
	}
	return out
}

// pacedItems sends a Direct target from the round's paced sockets
// (FamilySide.OpenPerSec): slot j opens j/OpenPerSec after firing —
// or at the stage's start, when later — and sends its repeats spread over
// the rest of the window, which keeps its mapping alive and answers the
// peer's late sprays.
func (fr *familyRound) pacedItems(t netip.AddrPort, cand uint16, reps int, start time.Time, hops []int) []sendItem {
	var out []sendItem
	for j := 1; j < len(fr.paced); j++ {
		open := fr.run.fireAt.Add(time.Duration(j) * time.Second / time.Duration(max(fr.side.OpenPerSec, 1)))
		if open.Before(start) {
			open = start
		}
		for k, off := range fr.spread(open, reps) {
			out = append(out, sendItem{due: open.Add(off), slot: j, to: t, cand: cand, stage: txBirthday, hops: hopAt(hops, k)})
		}
	}
	return out
}

// spread returns reps offsets from from, evenly over the rest of the
// round's window: the first at once.
func (fr *familyRound) spread(from time.Time, reps int) []time.Duration {
	rest := max(fr.run.end.Sub(from), 0)
	out := make([]time.Duration, reps)
	for k := range out {
		out[k] = rest * time.Duration(k) / time.Duration(reps)
	}
	return out
}

// sprayItems expands a predict or random stage with the spray seed —
// a paired predict stage with the initiator's — excluding ports
// already sent to the IP, and spreads the targets over the round's sockets;
// the i-th target takes the i-th hop of a low-TTL stage.
func (fr *familyRound) sprayItems(si int, st protocol.Stage, start time.Time, hops []int) []sendItem {
	rt, w := fr.rt, fr.w
	ip := st.IP.Unmap()
	if ok, _ := w.admit(rt, netip.AddrPortFrom(ip, 1024), st.Kind); !ok {
		fr.reject(1)
		return nil
	}
	sentPorts := rt.sender.sentPorts(ip)
	in := plan.ExpandInput{
		Seed: fr.seed, StageIndex: si, Allow: w.allow,
		Exclude: func(p uint16) bool { _, ok := sentPorts[p]; return ok },
	}
	if st.Pair {
		// Both sides order a paired stage by the initiator's spray seed of the
		// round, so that their mappings target each other in pairs.
		in.PairSeed = fr.pairSeed()
		in.Responder = rt.codec.Role() == udpwire.RoleResponder
	}
	targets := plan.ExpandStage(st, in)
	stage, kind := txPredict, candidate.KindPredicted
	if st.Kind == protocol.StageRandom {
		stage, kind = txRandom, candidate.KindRandom
		if len(fr.socks) > 1 {
			stage, kind = txBirthday, candidate.KindBirthday
		}
	}
	out := make([]sendItem, 0, len(targets))
	for i, t := range targets {
		if i > maxCandIndex {
			break
		}
		t = netaddr.Canon(t)
		s := fr.socks[i%len(fr.socks)]
		cand := uint16(si<<12 | i)
		rt.punch.planTarget(s.id, cand, t, kind)
		out = append(out, sendItem{due: start, sock: s, to: t, cand: cand, stage: stage, hops: hopAt(hops, i)})
	}
	return out
}

// pairSeed is the initiator's spray seed of the round, which both sides draw a
// paired stage's order and the fresh sockets' ports from.
func (fr *familyRound) pairSeed() [8]byte {
	rt := fr.rt
	return udpwire.SpraySeed(rt.start.Token, rt.start.Wire.RouteID, udpwire.RoleInitiator, fr.run.plan.Round, fr.run.plan.Seed)
}

// bindFresh binds the round's fresh sockets on the primary's IP at
// the ports both sides draw from the pair seed, by the index of the draw;
// a port this host cannot bind — taken, privileged, past the socket budget
// — is skipped (nil) and counted in round_result.bind_failed. A side
// without a fresh stage, a reply-only one, an unverified family and the
// NoPrediction ablation bind none.
func (fr *familyRound) bindFresh(ctx context.Context) []*udpSock {
	rt, w := fr.rt, fr.w
	i := slices.IndexFunc(fr.side.Stages, func(st protocol.Stage) bool { return st.Kind == protocol.StageFresh })
	if i < 0 || fr.side.Role == protocol.SideReplyOnly || rt.abl.NoPrediction || w.unverified {
		return nil
	}
	ports := plan.FreshPorts(fr.pairSeed(), int(fr.side.Stages[i].Count))
	out := make([]*udpSock, len(ports))
	for k, port := range ports {
		if ctx.Err() != nil {
			break
		}
		s, err := rt.socks.freshSocket(ctx, w.primary, port)
		if err != nil {
			fr.lateFailed.Add(1)
			continue
		}
		out[k] = s
	}
	return out
}

// releaseOwned closes the round's own sockets — fresh and paced — that
// never heard the peer; one that did holds candidate pairs and stays to
// the session's end.
func (fr *familyRound) releaseOwned() {
	for _, s := range fr.owned {
		if s != nil && !fr.rt.punch.heardOn(s.local) {
			fr.rt.socks.release(s)
		}
	}
}

// freshItems sends a fresh stage from the bound fresh sockets: socket k
// sends Repeats packets to each admitted target, or to the stage's IP and
// the k-th drawn port when the peer binds fresh sockets too — the two k-th
// sockets pair up.
func (fr *familyRound) freshItems(si int, st protocol.Stage, start time.Time, fresh []*udpSock) []sendItem {
	rt, w := fr.rt, fr.w
	var targets []netip.AddrPort
	for _, t := range st.Targets {
		t = netaddr.Canon(t)
		if ok, _ := w.admit(rt, t, protocol.StageDirect); !ok {
			fr.reject(1)
			continue
		}
		targets = append(targets, t)
	}
	var ports []uint16
	if st.IP.IsValid() {
		if ok, _ := w.admit(rt, netip.AddrPortFrom(st.IP.Unmap(), 1024), protocol.StageFresh); !ok {
			fr.reject(1)
			return nil
		}
		ports = plan.FreshPorts(fr.pairSeed(), len(fresh))
	}
	var out []sendItem
	for k, s := range fresh {
		if s == nil || k > maxCandIndex {
			continue
		}
		to, kind := targets, candidate.KindObserved
		if ports != nil {
			to, kind = []netip.AddrPort{netip.AddrPortFrom(st.IP.Unmap(), ports[k])}, candidate.KindPredicted
		}
		cand := uint16(si<<12 | k)
		for ti, t := range to {
			rt.punch.planTarget(s.id, cand, t, kind)
			for _, off := range plan.DirectOffsets(fr.seed, si, k*len(to)+ti, int(max(st.Repeats, 1))) {
				out = append(out, sendItem{due: start.Add(off), sock: s, to: t, cand: cand, stage: txFresh})
			}
		}
	}
	return out
}

// freshPeerItems aims a fresh_peer stage at the peer's fresh sockets: from the
// primary socket, Repeats packets to the stage's IP and each drawn port.
func (fr *familyRound) freshPeerItems(si int, st protocol.Stage, start time.Time) []sendItem {
	rt, w := fr.rt, fr.w
	ip := st.IP.Unmap()
	if ok, _ := w.admit(rt, netip.AddrPortFrom(ip, 1024), protocol.StageFreshPeer); !ok {
		fr.reject(1)
		return nil
	}
	s := fr.socks[0]
	var out []sendItem
	for k, port := range plan.FreshPorts(fr.pairSeed(), int(st.Count)) {
		if k > maxCandIndex {
			break
		}
		t := netip.AddrPortFrom(ip, port)
		cand := uint16(si<<12 | k)
		rt.punch.planTarget(s.id, cand, t, candidate.KindPredicted)
		for _, off := range plan.DirectOffsets(fr.seed, si, k, int(max(st.Repeats, 1))) {
			out = append(out, sendItem{due: start.Add(off), sock: s, to: t, cand: cand, stage: txFresh})
		}
	}
	return out
}

// extraItems schedules peer_targets from the primary socket, now and at the
// Direct offsets after it, on the round's peer_targets quota: at most
// maxRoundExtras targets a round, targetPackets packets each. The
// window ports go after the explicit targets, in the order of the round's
// spray seed (scatterWindows), and a batch beyond the quota loses its last
// ones: some window ports, drawn by that order, before any explicit target.
func (fr *familyRound) extraItems(targets []extraTarget, now time.Time) []sendItem {
	rt := fr.rt
	base := int(fr.extras.Load())
	targets = scatterWindows(fr.seed, base, targets)
	if over := len(targets) - max(maxRoundExtras-base, 0); over > 0 {
		targets = targets[:len(targets)-over]
		fr.w.fs.cnt.drops[dropBudget].Add(int64(over))
	}
	var out []sendItem
	fr.extras.Add(int32(len(targets)))
	for i, t := range targets {
		cand := uint16(extraStageIndex<<12 | min(base+i, maxCandIndex))
		rt.punch.planTarget(fr.socks[0].id, cand, t.to, t.kind)
		for _, off := range plan.DirectOffsets(fr.seed, extraStageIndex, base+i, targetPackets) {
			out = append(out, sendItem{due: now.Add(off), sock: fr.socks[0], to: t.to, cand: cand, stage: txDirect, quota: quotaTargets})
		}
	}
	slices.SortStableFunc(out, func(a, b sendItem) int { return a.due.Compare(b.due) })
	return out
}

// scatterWindows returns targets with the explicit targets first, in their
// order, and then the window ports of each IP in the order of the round's
// spray seed (plan.ScatterPorts): in Lo..Hi order
// a window would leave as the same run of adjacent ports in every session.
// index, the first peer_targets index of the batch, selects the seed's
// sub-stream, so that every batch of a round is scattered differently. The
// send gate's run guard (runs.go) still holds back a port that would extend
// a run.
func scatterWindows(seed [8]byte, index int, targets []extraTarget) []extraTarget {
	out := make([]extraTarget, 0, len(targets))
	var ips []netip.Addr
	ports := map[netip.Addr][]uint16{}
	kinds := map[netip.AddrPort]candidate.Kind{}
	for _, t := range targets {
		if !t.window {
			out = append(out, t)
			continue
		}
		ip := t.to.Addr()
		if _, ok := ports[ip]; !ok {
			ips = append(ips, ip)
		}
		ports[ip] = append(ports[ip], t.to.Port())
		kinds[t.to] = t.kind
	}
	for i, ip := range ips {
		for _, p := range plan.ScatterPorts(seed, index+i, ports[ip]) {
			to := netip.AddrPortFrom(ip, p)
			out = append(out, extraTarget{to: to, kind: kinds[to], window: true})
		}
	}
	return out
}

// sandwichProbe sends the sandwich probe of phase `phase` from the round's
// helper socket: the one before the round's first punch to observer 0, the
// one after it to observer 1, so that the two new
// mappings bracket the punch's.
func (fr *familyRound) sandwichProbe(ctx context.Context, helper *udpSock, phase uint8) {
	rt := fr.rt
	obs := fr.w.fs.observers[phase]
	h := udpwire.Header{Type: udpwire.TProbe, Cand: udpwire.NoCand, Aux: uint16(obs.ID)}
	t := udpwire.TLVs{}
	t.Sandwich.Round, t.Sandwich.Phase, t.Sandwich.Set = fr.run.plan.Round, phase, true
	_ = rt.sender.Send(ctx, helper, netaddr.Canon(obs.Addr), &h, &t, sendOpt{class: classProbe, stage: txProbe})
}

// hopCycle is the hop sequence of a low-TTL stage whose preferred hop is h: the
// hops the session allows — the server's low_ttl_hops intersected with
// Options.Policy's, protocol.Tighten — in their order, starting at h, or at the
// allowed hop nearest h (the smaller on a tie) when h is not one of them.
func (rt *runtime) hopCycle(h int) []int {
	hs := rt.policy.LowTTLHops
	if len(hs) == 0 {
		return nil
	}
	dist := func(v int) int { return max(v-h, h-v) }
	start := 0
	for i, v := range hs {
		if d, best := dist(v), dist(hs[start]); d < best || d == best && v < hs[start] {
			start = i
		}
	}
	return append(slices.Clone(hs[start:]), hs[:start]...)
}

// hopAt is the hop of the k-th packet of a stage cycling through hops, or 0
// (normal TTL) for a stage without low TTL.
func hopAt(hops []int, k int) int {
	if len(hops) == 0 {
		return 0
	}
	return hops[k%len(hops)]
}

// lowTTLDegraded reports, once per family, that a socket refused the low TTL:
// the family sends with normal TTL from now on.
func (rt *runtime) lowTTLDegraded(w *worker) {
	if w.lowTTLOff.Swap(true) {
		return
	}
	rt.addWarn(protocol.WarnLowTTLUnsupported)
	rt.progress(progressEvent{stage: stageLowTTLUnsupported, status: protocol.StatusInfo, family: w.fam})
}

// sleepUntil waits for t on the session clock, or for ctx.
func (rt *runtime) sleepUntil(ctx context.Context, t time.Time) error {
	return rt.sleep(ctx, t.Sub(rt.clk.Now()))
}

// sleep waits for d on the session clock, or for ctx.
func (rt *runtime) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := rt.clk.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-t.C():
		return nil
	}
}

package holepunch

import (
	"context"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

// The prepare phase: probe_summary to punch_ready.

// Summary handling bounds.
const (
	prepareLimit  = 2 * time.Second
	clockSkewWarn = 300 * time.Second
)

// prepare handles probe_summary, from the summary wait to the go wait: it
// applies the tighter timeouts
// and the session budget, builds a worker per shared family, pre-binds the
// first round's sockets, admits its targets and writes punch_ready — or
// punch_result{no_common_family} when no family is left.
func (rt *runtime) prepare(sum stamped[protocol.ProbeSummary]) error {
	s, clamped := sum.msg.Normalize()
	rt.summary, rt.summaryAt = s, sum.at
	rt.timing.summaryWait = sum.at.Sub(rt.startAt) - rt.timing.probe
	rt.timeouts = s.Timeouts.Within(rt.start.Timeouts)
	rt.computeWaits()
	rt.transport = s.Transport
	var startBudget, localBudget protocol.Budget
	if rt.start.Policy != nil {
		startBudget = rt.start.Policy.Budget
	}
	if rt.opts.Policy != nil {
		localBudget = rt.opts.Policy.Budget
	}
	rt.sessBudget = protocol.TightenBudget(startBudget, s.Plan.Budget, localBudget)
	rt.sender.setBudget(rt.sessBudget)
	rt.socks.setLimit(int(rt.sessBudget.MaxSockets))
	rt.phases.note(stageSummaryReceived)
	rt.progress(progressEvent{stage: stageSummaryReceived, status: protocol.StatusInfo})

	for _, f := range s.Pair.SharedFamilies {
		if s.Pair.Unverified[f] {
			rt.addWarn(protocol.WarnUnverifiedTargets)
		}
	}
	if off, lim := s.Pair.ClockOffsetMs[rt.role], clockSkewWarn.Milliseconds(); off > lim || off < -lim {
		rt.addWarn(protocol.WarnClockSkew)
	}
	for _, f := range s.Pair.SharedFamilies {
		fs := rt.fam(f)
		if fs.primary == nil || !fs.probed && !s.Pair.Unverified[f] {
			continue
		}
		fs.worker = newWorker(rt, fs, &s)
		rt.workers = append(rt.workers, fs.worker)
	}
	if len(rt.workers) == 0 {
		return fail(protocol.ReasonNoCommonFamily, "", nil)
	}

	r1, changed := rt.clampRound(s.Plan.Round1)
	clamped = clamped || changed
	rt.pg = life.New(rt.g.Context())
	rt.startPunching()

	var fams []protocol.FamilyReady
	for _, side := range r1.Sides {
		w := rt.fam(side.Family).worker
		if w == nil {
			continue
		}
		rejected := rt.countRejected(w, side)
		socks, _ := rt.socks.roundSockets(rt.g.Context(), w.primary, socketsBeforeFiring(side), roundPurpose(side))
		fr := protocol.FamilyReady{Family: side.Family, Sockets: uint16(len(socks)), Clamped: clamped, Rejected: uint16(min(rejected, 0xFFFF))}
		if w.fs.mapping != nil {
			fr.PortMap = w.fs.mapping.takeReport()
		}
		fams = append(fams, fr)
	}
	if len(fams) == 0 {
		return fail(protocol.ReasonNoCommonFamily, "round1", nil)
	}
	for _, w := range rt.workers {
		if s.Pair.SamePublicIP[w.fam] && w.fs.prober.Load() != nil {
			rt.startHairpin(w)
		}
	}
	now := rt.clk.Now()
	if now.Sub(sum.at) > prepareLimit {
		return fail(protocol.ReasonInternal, "prepare_timeout", nil)
	}
	for _, w := range rt.workers {
		rt.phases.advanceFamily(w.fam, protocol.PhasePlanned, "summary_received", now)
	}
	ready := protocol.PunchReady{SessionID: rt.start.SessionID, Role: rt.role, Families: fams}
	if err := sendElapsed(rt.ctl, ready, sum.at, func(r *protocol.PunchReady, ms uint32) { r.ElapsedMs = ms }); err != nil {
		return rt.ctl.sendFailure("punch_ready", err)
	}
	rt.readyAt = rt.clk.Now()
	rt.phases.advance(protocol.PhaseReady, stageReadySent, rt.readyAt)
	rt.progress(progressEvent{stage: stageReadySent, status: protocol.StatusInfo})
	return nil
}

// countRejected counts the targets of a side that admission refuses.
func (rt *runtime) countRejected(w *worker, side protocol.FamilySide) int {
	n := 0
	for _, st := range side.Stages {
		n += w.admitStage(rt, side, st).rejected
	}
	return n
}

// roundPurpose names the extra sockets of a side: warmup when they pre-open
// mappings with a low TTL, birthday otherwise.
func roundPurpose(side protocol.FamilySide) string {
	for _, st := range side.Stages {
		if st.TTL > 0 {
			return PurposeWarmup
		}
	}
	return PurposeBirthday
}

// sandwichOK reports whether this session negotiated the sandwich feature
// and may run it.
func (rt *runtime) sandwichOK() bool {
	if rt.abl.NoSandwich {
		return false
	}
	return slices.Contains(rt.features, protocol.FeatureSandwich)
}

// startHairpin runs the hairpin self-test of a family behind the same public
// IP as its peer. It runs in the punching group, so the handover
// ends it before the winning socket changes hands.
func (rt *runtime) startHairpin(w *worker) {
	pr := w.fs.prober.Load()
	rt.pg.Go("hairpin:"+string(w.fam), func(ctx context.Context) {
		v := pr.Hairpin(ctx)
		w.hairpinOK.Store(v == protocol.TriTrue)
		status := protocol.StatusOK
		if v != protocol.TriTrue {
			status = protocol.StatusFail
		}
		rt.progress(progressEvent{stage: stageHairpinResult, status: status, detail: v.String(), family: w.fam})
	})
}

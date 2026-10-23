package holepunch

import (
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/trunc"
	"github.com/djylb/holepunch/protocol"
)

// writeResult queues punch_result and flushes it for at most 200 ms.
// A control_version_mismatch writes nothing.
func (rt *runtime) writeResult(f *failure, failPhase Phase) {
	if f != nil && f.reason == protocol.ReasonControlVersionMismatch {
		return
	}
	if dead, _ := rt.ctl.dead(); dead || faultinject.Point(fiResultWrite) != nil {
		return
	}
	pr := protocol.PunchResult{
		SessionID: rt.start.SessionID, Role: rt.role, OK: f == nil, Phase: protocol.PhaseDone,
		Stats: rt.wireStats(), Timing: rt.wireTiming(), Traits: rt.corrections(), Warn: rt.warnings(),
	}
	if len(pr.Traits) > 0 {
		rt.progress(progressEvent{stage: stageTraitsCorrected, status: protocol.StatusInfo})
	}
	if f != nil {
		pr.Reason, pr.Phase, pr.Detail = f.reason, failPhase, trunc.String(f.detail, protocol.MaxDetail)
	} else {
		p := rt.primaryPath
		pr.Path, pr.ExtraPaths = &p, rt.extraPaths
	}
	if rt.ctl.send(pr) == nil {
		rt.ctl.flush(resultFlush)
	}
}

func (rt *runtime) wireStats() protocol.Stats {
	c := rt.counters()
	s := protocol.Stats{Sent: uint32(c.TxPackets), Recv: uint32(c.RxVerified), Replies: uint32(c.TxByStage[txStageNames[txReply]]),
		Rounds: uint8(min(len(rt.roundsRun), 255)), Drops: map[string]uint32{}}
	for k, v := range c.Drops {
		s.Drops[k] = uint32(v)
	}
	s.Hits = uint8(min(rt.punch.hits(), 255))
	_, _, pct := rt.sender.usage()
	s.BudgetHit = pct >= 100
	return s
}

func (rt *runtime) wireTiming() protocol.Timing {
	ms := func(d time.Duration) uint32 { return uint32(max(d, 0) / time.Millisecond) }
	t := rt.publicTiming()
	return protocol.Timing{ProbeMs: ms(t.Probe), SummaryWaitMs: ms(t.SummaryWait), GoWaitMs: ms(t.GoWait), PunchMs: ms(t.Punch), HandoverMs: ms(t.Handover)}
}

func (rt *runtime) publicTiming() Timing {
	t := Timing{Probe: rt.timing.probe, SummaryWait: rt.timing.summaryWait, GoWait: rt.timing.goWait,
		Handover: rt.timing.handover, Total: rt.timing.total}
	if !rt.firstGoAt.IsZero() {
		end := rt.clk.Now()
		if rt.punch.isConfirmed() {
			end = rt.punch.confirmTime()
		}
		t.Punch = end.Sub(rt.firstGoAt)
	}
	return t
}

// corrections are the punch-time corrections of this side's traits
// (punch_result.traits): the table reclassified with the peer_seen and
// hairpin evidence, against the summary's view.
func (rt *runtime) corrections() []protocol.TraitsUpdate {
	var out []protocol.TraitsUpdate
	for _, w := range rt.workers {
		tab := w.fs.table()
		if tab == nil {
			continue
		}
		src := protocol.TraitsSourceHairpin
		if rt.traitsSource[w.fam.Index()].Load() {
			src = protocol.TraitsSourcePeer
		}
		if u, ok := nat.Correction(w.selfTraits, tab.Classify(), src); ok {
			u.Family = w.fam
			out = append(out, u)
		}
	}
	return out
}

// counters is the session total.
func (rt *runtime) counters() Counters {
	var parts []Counters
	for _, fs := range rt.fams {
		parts = append(parts, fs.cnt.snapshot())
	}
	c := sumCounters(parts...)
	if rt.sender != nil {
		c.DistinctTargets, c.PeakPPS, c.BudgetUsedPct = rt.sender.usage()
	}
	cs := rt.ctl.conn.Stats()
	c.ControlFramesIn, c.ControlFramesOut = int(cs.FramesIn), int(cs.FramesOut)
	c.ProgressDropped = int(rt.cnt.progressDropped.Load())
	c.CallbackPanics = int(rt.cnt.callbackPanics.Load())
	c.LeakedGoroutines = rt.g.Stats().Leaked
	if rt.pg != nil {
		c.LeakedGoroutines += rt.pg.Stats().Leaked
	}
	return c
}

// diagnostics assembles the session's Diagnostics. A session that failed
// before punch_start was read has none; finish does not call it then.
func (rt *runtime) diagnostics(win *candidate.Action, f *failure, failPhase Phase) Diagnostics {
	phase, timeline, last := rt.phases.snapshot()
	d := Diagnostics{
		SessionID: rt.start.SessionID, Role: rt.role, Phase: phase, LastEvent: last, Timeline: timeline,
		Counters: rt.counters(), Timing: rt.publicTiming(), RTT: rt.lastRTT,
	}
	if d.Counters.LeakedGoroutines > 0 {
		rt.addWarn(protocol.WarnGoroutineJoinTimeout)
	}
	d.Warn = rt.warnings()
	if f != nil {
		d.Reason, d.Phase = f.reason, failPhase
	}
	if rt.summaryAt.IsZero() {
		return d
	}
	p := rt.summary.Plan.Clone()
	d.Plan = &p
	for _, r := range rt.roundsRun {
		d.Rounds = append(d.Rounds, r.Clone())
	}
	for _, w := range rt.workers {
		self := w.selfTraits
		if tab := w.fs.table(); tab != nil {
			if _, ok := nat.Correction(w.selfTraits, tab.Classify(), protocol.TraitsSourcePeer); ok {
				self = tab.Classify()
			}
		}
		d.Self = append(d.Self, self)
		d.Peer = append(d.Peer, w.peerTraits)
		fd := FamilyDiagnostics{Family: w.fam, Strategy: rt.strategy(w), Counters: w.fs.cnt.snapshot(),
			Candidates: rt.nom.candidates(w.fam, rt.punch.planned(w.fam)), Hints: familyHints(self, w.peerTraits)}
		if win != nil && f == nil {
			fd.Confirmed = confirmedRemote(win, rt.extraPaths, w.fam)
		}
		d.Families = append(d.Families, fd)
	}
	if win != nil && f == nil {
		p := rt.primaryPath
		d.Path, d.ExtraPaths = &p, slices.Clone(rt.extraPaths)
	}
	return d
}

// strategy is the diagnostic name "<pair_class>/<last variant>".
func (rt *runtime) strategy(w *worker) string {
	s := rt.summary.Plan.PairClass
	for i := len(rt.roundsRun) - 1; i >= 0; i-- {
		r := rt.roundsRun[i]
		if slices.ContainsFunc(r.Sides, func(side protocol.FamilySide) bool { return side.Family == w.fam }) {
			s += "/" + r.Variant
			break
		}
	}
	if w.lowTTLOff.Load() || !w.lowTTL {
		s += ";lowttl=unavailable"
	}
	return s
}

// addWarn records a warning once (at most eight are kept).
func (rt *runtime) addWarn(w protocol.Warning) {
	rt.warnMu.Lock()
	defer rt.warnMu.Unlock()
	for _, x := range rt.warn {
		if x == w {
			return
		}
	}
	if len(rt.warn) < protocol.MaxWarn {
		rt.warn = append(rt.warn, w)
	}
}

func (rt *runtime) warnings() []protocol.Warning {
	rt.warnMu.Lock()
	defer rt.warnMu.Unlock()
	return slices.Clone(rt.warn)
}

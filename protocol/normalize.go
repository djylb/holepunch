package protocol

import (
	"slices"
)

// Receiver-side clamps (the per-field ranges of the control messages).
// Every Normalize is idempotent and returns the normalized copy and whether a
// clamp changed a value that was set (filling a zero timeout with its default
// is not a clamp); clamps of a plan are reported in
// punch_ready.families[].clamped and round_result. The receiver is never
// written, nor anything it shares: a slice, map or pointed-to value that
// changes is copied first, and a truncated list keeps no spare capacity, so
// that appending to the copy cannot write the receiver's elements either.
const (
	maxDelayMs       = 2000
	maxSendDelayMs   = 3000
	maxRoundsMax     = 6
	maxStages        = 8
	maxStageTargets  = 16
	maxSteps         = 3
	maxSpanCount     = 4096
	maxRepeats       = 8
	minLowTTL        = 2
	maxLowTTL        = 64
	maxSideSockets   = 256
	maxAssistTargets = 16
	maxSiblings      = 2
	maxProgressMap   = 16
	maxAssistMeta    = 8
	maxDropKeys      = 16
)

// Normalize clamps the wire range and the timeouts, the sibling count and the
// policy (budget to CeilingBudget, low-TTL hops to [2,32]).
func (m PunchStart) Normalize() (PunchStart, bool) {
	var c bool
	m.Wire, c = m.Wire.Normalize()
	c = normalizeTimeouts(&m.Timeouts) || c
	if m.Probe.Siblings > maxSiblings {
		m.Probe.Siblings, c = maxSiblings, true
	}
	if m.Policy != nil {
		p := *m.Policy
		c = clampBudget(&p.Budget) || c
		if len(p.LowTTLHops) > 0 {
			if h := normalizeHops(p.LowTTLHops); !slices.Equal(h, p.LowTTLHops) {
				p.LowTTLHops, c = h, true
			}
		}
		m.Policy = &p
	}
	return m, c
}

// Normalize implements the clamps of ping (none).
func (m Ping) Normalize() (Ping, bool) { return m, false }

// Normalize implements the clamps of pong (none).
func (m Pong) Normalize() (Pong, bool) { return m, false }

// Normalize clamps caps.max_sockets to 256.
func (m ProbeReport) Normalize() (ProbeReport, bool) {
	if m.Caps.MaxSockets > maxSideSockets {
		m.Caps.MaxSockets = maxSideSockets
		return m, true
	}
	return m, false
}

// Normalize clamps the timeouts and the plan.
func (m ProbeSummary) Normalize() (ProbeSummary, bool) {
	c := normalizeTimeouts(&m.Timeouts)
	var pc bool
	m.Plan, pc = m.Plan.Normalize()
	return m, pc || c
}

// Normalize implements the clamps of punch_ready (none).
func (m PunchReady) Normalize() (PunchReady, bool) { return m, false }

// Normalize clamps delay_ms to 2000, window_ms to the longest window of
// the plan's class — 10000, or 45000 for a background round; round 1 has
// no plan and is never a background round — and the plan.
func (m PunchGo) Normalize() (PunchGo, bool) {
	c := false
	if m.DelayMs > maxDelayMs {
		m.DelayMs, c = maxDelayMs, true
	}
	limit := uint16(maxWindowMs)
	if m.Plan != nil {
		limit = m.Plan.Budget.MaxWindowMs()
	}
	if m.WindowMs > limit {
		m.WindowMs, c = limit, true
	}
	if m.Plan != nil {
		p, pc := m.Plan.Normalize()
		m.Plan, c = &p, pc || c
	}
	return m, c
}

// Normalize truncates counters and meta to 16 keys (smallest keys kept).
func (m Progress) Normalize() (Progress, bool) {
	var c, mc bool
	m.Counters, c = truncateMap(m.Counters, maxProgressMap)
	m.Meta, mc = truncateMap(m.Meta, maxProgressMap)
	return m, mc || c
}

// Normalize truncates targets to 16, the window to 64 ports and meta to 8
// keys.
func (m Assist) Normalize() (Assist, bool) {
	c := false
	if len(m.Targets) > maxAssistTargets {
		m.Targets, c = m.Targets[:maxAssistTargets:maxAssistTargets], true
	}
	if w := m.Window; w != nil && w.Hi > w.Lo && w.Hi-w.Lo > maxPortWindowWidth {
		win := *w
		win.Hi = win.Lo + maxPortWindowWidth
		m.Window, c = &win, true
	}
	var mc bool
	m.Meta, mc = truncateMap(m.Meta, maxAssistMeta)
	return m, mc || c
}

// Normalize implements the clamps of punch_abort (none).
func (m Abort) Normalize() (Abort, bool) { return m, false }

// Normalize implements the clamps of round_result (none).
func (m RoundResult) Normalize() (RoundResult, bool) { return m, false }

// Normalize truncates stats.drops to 16 keys.
func (m PunchResult) Normalize() (PunchResult, bool) {
	var c bool
	m.Stats.Drops, c = truncateMap(m.Stats.Drops, maxDropKeys)
	return m, c
}

// Normalize clamps rounds_max to 6, the session budget to CeilingBudget and
// the first round.
func (p PlanSpec) Normalize() (PlanSpec, bool) {
	c := false
	if p.RoundsMax > maxRoundsMax {
		p.RoundsMax, c = maxRoundsMax, true
	}
	c = clampBudget(&p.Budget) || c
	var rc bool
	p.Round1, rc = p.Round1.Normalize()
	return p, rc || c
}

// Normalize clamps a round to the protocol limits and to the ceiling of
// its BudgetClass: window_ms <= 10000; per side send_delay_ms <= 3000,
// sockets <= min(256, class), max_packets <= min(40000, class), max_pps <=
// min(1500, class), max_new_per_sec <= 256, max_distinct_ports <= class, at
// most 8 stages; per stage at most 16 targets and 3 steps, span and count <=
// 4096, repeats <= 8, ttl in {0} ∪ [2,64].
func (r RoundPlan) Normalize() (RoundPlan, bool) {
	c := false
	if w := r.Budget.MaxWindowMs(); r.WindowMs > w {
		r.WindowMs, c = w, true
	}
	limits, ok := r.Budget.Limits()
	if !ok {
		limits = ClassLimits{MaxPackets: CeilingBudget().MaxPackets, MaxPPS: CeilingBudget().MaxPPS, MaxDistinctPorts: CeilingBudget().MaxDistinctTargets, MaxSockets: maxSideSockets}
	}
	r.Sides = slices.Clone(r.Sides)
	for i := range r.Sides {
		var sc bool
		r.Sides[i], sc = r.Sides[i].normalize(limits)
		c = sc || c
	}
	return r, c
}

func (s FamilySide) normalize(l ClassLimits) (FamilySide, bool) {
	c := clampTo(&s.SendDelayMs, maxSendDelayMs)
	c = clampTo(&s.Sockets, min(maxSideSockets, l.MaxSockets)) || c
	c = clampTo(&s.MaxPackets, min(CeilingBudget().MaxPackets, l.MaxPackets)) || c
	c = clampTo(&s.MaxPPS, min(CeilingBudget().MaxPPS, l.MaxPPS)) || c
	c = clampTo(&s.MaxNewPerSec, CeilingBudget().MaxNewPerSec) || c
	c = clampTo(&s.MaxDistinctPorts, l.MaxDistinctPorts) || c
	c = clampTo(&s.OpenPerSec, CeilingBudget().MaxNewPerSec) || c
	if len(s.Stages) > maxStages {
		s.Stages, c = s.Stages[:maxStages], true
	}
	s.Stages = slices.Clone(s.Stages)
	for i := range s.Stages {
		var sc bool
		s.Stages[i], sc = s.Stages[i].normalize()
		c = sc || c
	}
	out, fc := s.clampFresh(min(maxSideSockets, int(l.MaxSockets)))
	return out, fc || c
}

// clampFresh keeps the side's sockets with its fresh sockets within limit:
// the fresh stage gives up sockets first; with no room left for even one
// fresh socket the side's own sockets make it. A limit of 1 leaves one
// socket of each, the least a side with a fresh stage runs with.
func (s FamilySide) clampFresh(limit int) (FamilySide, bool) {
	for i, st := range s.Stages {
		if st.Kind != StageFresh || int(s.Sockets)+int(st.Count) <= limit {
			continue
		}
		sockets := s.Sockets
		if int(sockets) >= limit {
			sockets = uint16(max(limit-1, 1))
		}
		count := uint16(max(limit-int(sockets), 1))
		if sockets == s.Sockets && count == st.Count {
			return s, false
		}
		s.Sockets, st.Count = sockets, count
		s.Stages = slices.Clone(s.Stages)
		s.Stages[i] = st
		return s, true
	}
	return s, false
}

func (s Stage) normalize() (Stage, bool) {
	c := false
	if len(s.Targets) > maxStageTargets {
		s.Targets, c = s.Targets[:maxStageTargets:maxStageTargets], true
	}
	if len(s.Steps) > maxSteps {
		s.Steps, c = s.Steps[:maxSteps:maxSteps], true
	}
	c = clampTo(&s.Span, maxSpanCount) || c
	c = clampTo(&s.Count, maxSpanCount) || c
	c = clampTo(&s.Repeats, maxRepeats) || c
	switch {
	case s.TTL == 1:
		s.TTL, c = minLowTTL, true
	case s.TTL > maxLowTTL:
		s.TTL, c = maxLowTTL, true
	}
	return s, c
}

// ClampTo limits every side of the round to the session budget b (zero fields
// of b do not limit): sockets, max_packets, max_pps and max_new_per_sec. It
// is the "only tighter" step between summary.plan.budget (or the merged
// policy) and each round's FamilySide.
func (r RoundPlan) ClampTo(b Budget) (RoundPlan, bool) {
	c := false
	r.Sides = slices.Clone(r.Sides)
	for i := range r.Sides {
		s := r.Sides[i]
		if b.MaxSockets != 0 {
			c = clampTo(&s.Sockets, b.MaxSockets) || c
			var fc bool
			s, fc = s.clampFresh(int(b.MaxSockets))
			c = fc || c
		}
		if b.MaxPackets != 0 {
			c = clampTo(&s.MaxPackets, b.MaxPackets) || c
		}
		if b.MaxPPS != 0 {
			c = clampTo(&s.MaxPPS, b.MaxPPS) || c
		}
		if b.MaxNewPerSec != 0 {
			c = clampTo(&s.MaxNewPerSec, b.MaxNewPerSec) || c
		}
		r.Sides[i] = s
	}
	return r, c
}

// ---- helpers ----

func clampTo[T uint8 | uint16 | uint32](v *T, hi T) bool {
	if *v > hi {
		*v = hi
		return true
	}
	return false
}

// clampBudget caps each set field at CeilingBudget (zero stays unset).
func clampBudget(b *Budget) bool {
	ceil := CeilingBudget()
	c := clampTo(&b.MaxPackets, ceil.MaxPackets)
	c = clampTo(&b.MaxPPS, ceil.MaxPPS) || c
	c = clampTo(&b.MaxDistinctTargets, ceil.MaxDistinctTargets) || c
	c = clampTo(&b.MaxSockets, ceil.MaxSockets) || c
	return clampTo(&b.MaxNewPerSec, ceil.MaxNewPerSec) || c
}

// normalizeTimeouts fills defaults and clamps; only a changed non-zero field
// counts as a clamp.
func normalizeTimeouts(t *Timeouts) bool {
	n := t.Normalize()
	c := t.ProbeTimeoutMs != 0 && t.ProbeTimeoutMs != n.ProbeTimeoutMs ||
		t.SummaryWaitMs != 0 && t.SummaryWaitMs != n.SummaryWaitMs ||
		t.GoWaitMs != 0 && t.GoWaitMs != n.GoWaitMs ||
		t.HandshakeTimeoutMs != 0 && t.HandshakeTimeoutMs != n.HandshakeTimeoutMs ||
		t.HandoverTimeoutMs != 0 && t.HandoverTimeoutMs != n.HandoverTimeoutMs ||
		t.TransportTimeoutMs != 0 && t.TransportTimeoutMs != n.TransportTimeoutMs ||
		t.MaxRounds != 0 && t.MaxRounds != n.MaxRounds
	*t = n
	return c
}

// truncateMap returns m cut to its n smallest keys, so that every receiver
// keeps the same ones, and whether keys were dropped. A map that is cut is a
// new map; m is not written.
func truncateMap[V any](m map[string]V, n int) (map[string]V, bool) {
	if len(m) <= n {
		return m, false
	}
	out := make(map[string]V, n)
	for _, k := range keptKeys(m, n) {
		out[k] = m[k]
	}
	return out, true
}

// keptKeys returns the n smallest keys of m in order (all of them when m has
// at most n).
func keptKeys[V any](m map[string]V, n int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys[:min(n, len(keys))]
}

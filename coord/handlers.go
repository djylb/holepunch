package coord

import (
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/trunc"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// violation is a protocol_violation by side r, notified to r as well.
func violation(r int, detail string) *terminal {
	return &terminal{code: protocol.ReasonProtocolViolation, detail: detail, failed: roleOf(r), notifyFailed: true}
}

// onReportLocked handles a probe_report: accepted once per side in binding
// (the first side may probe before the second attaches) and probing, ignored
// once confirming, a violation otherwise. A warm side (ProbeSpec.Warm) may
// send an early report first, once, and its final report then also later,
// while summarized or punching, when the session was planned on the early
// one: it refines the plan (refine). A report gives an RTT sample (since
// punch_start went out, less elapsed_ms). When each side has a report the
// session can be planned on — the final one, or an early one not found
// cold — the session goroutine plans the session.
func (s *Session) onReportLocked(r int, m *protocol.ProbeReport, now time.Duration) effects {
	st := &s.st
	var fx effects
	late := false
	switch st.state {
	case StateBinding, StateProbing:
	case StateSummarized, StatePunching:
		if m.Early || st.early[r] == nil || st.reports[r] != nil {
			fx.end(violation(r, detailUnexpected))
			return fx
		}
		late = true
	case StateConfirming:
		return fx
	default:
		fx.end(violation(r, detailUnexpected))
		return fx
	}
	switch {
	case m.Early && !s.starts[r].Probe.Warm:
		fx.end(violation(r, detailUnexpected))
		return fx
	case m.Early && (st.early[r] != nil || st.reports[r] != nil), !m.Early && st.reports[r] != nil:
		fx.end(violation(r, detailDuplicate))
		return fx
	}
	l := st.links[r]
	if sent, ok := sentAt(&l.markStart); ok {
		st.rtt[r].add(now - sent - ms(m.ElapsedMs))
	}
	first := st.early[r] == nil && st.reports[r] == nil
	if m.Early {
		st.early[r] = m
	} else {
		st.reports[r] = m
	}
	if late || st.plan.warm[r] == WarmHit {
		st.work.refine[r] = true
		return fx
	}
	if first {
		st.sand.echoed[r] = s.starts[r].Control.Has(protocol.FeatureSandwich) && m.Control.Has(protocol.FeatureSandwich)
		s.c.emit(Event{Kind: EvReported, At: s.at(now), SessionID: s.id, Role: roleOf(r), Labels: s.labels})
	}
	if !s.plannableLocked(1 - r) {
		if first {
			l.ping.schedule(waitReport, now)
		}
		s.rearmLocked(now)
		return fx
	}
	s.cancelPingsLocked(waitReport)
	s.beginPlanLocked()
	s.rearmLocked(now)
	return fx
}

// plannableLocked reports whether side r has a report the session can be
// planned on: its final report, or an early one the merge did not find
// cold.
func (s *Session) plannableLocked(r int) bool {
	st := &s.st
	return st.reports[r] != nil || st.early[r] != nil && st.plan.warm[r] != WarmCold
}

// reportLocked is side r's latest report: the final one, else the early
// one, else nil.
func (s *Session) reportLocked(r int) *protocol.ProbeReport {
	if s.st.reports[r] != nil {
		return s.st.reports[r]
	}
	return s.st.early[r]
}

// beginPlanLocked asks for the session plan when both sides have a report to
// plan on and no planning ran or runs.
func (s *Session) beginPlanLocked() {
	st := &s.st
	if st.state == StateProbing && !st.plan.planning && !st.plan.planned && s.plannableLocked(0) && s.plannableLocked(1) {
		st.plan.begin(&st.work.plan)
	}
}

// onReadyLocked handles a punch_ready: accepted once per side in summarized,
// or once punching after an eager go (eagerGoLocked), ignored otherwise
// later, a violation before. It gives an RTT sample (since the summary went
// out, less elapsed_ms) and carries, maybe, a port mapping that finished
// after the report. When both are in while summarized, the first round
// starts.
func (s *Session) onReadyLocked(r int, m *protocol.PunchReady, now time.Duration) effects {
	st := &s.st
	var fx effects
	switch st.state {
	case StateSummarized:
		if st.ready[r] {
			fx.end(violation(r, detailDuplicate))
			return fx
		}
	case StatePunching, StateConfirming:
		if st.ready[r] {
			return fx
		}
	default:
		fx.end(violation(r, detailUnexpected))
		return fx
	}
	l := st.links[r]
	if sent, ok := sentAt(&l.markSummary); ok {
		st.rtt[r].add(now - sent - ms(m.ElapsedMs))
	}
	st.ready[r] = true
	for _, f := range m.Families {
		l.readyFams = append(l.readyFams, f.Family)
		if f.PortMap != nil {
			s.latePortMapLocked(r, f.Family, *f.PortMap, now)
		}
	}
	if st.state != StateSummarized {
		return fx // an eager go started round 1 already
	}
	if !st.ready[1-r] {
		l.ping.schedule(waitReady, now)
		s.rearmLocked(now)
		return fx
	}
	s.cancelPingsLocked(waitReady)
	if rf := &st.refresh; rf.k == 1 && (rf.pending || rf.ready) {
		// Round 1's anchor refresh is not back yet: its end sends the go
		// (reanchorRound1Locked).
		s.rearmLocked(now)
		return fx
	}
	fx.merge(s.startRoundLocked(now))
	return fx
}

// latePortMapLocked admits a port mapping side r reported in punch_ready. A
// private or shared address of a peer behind the same public IP is an
// upstream-LAN candidate: it joins the candidates that go out with every go. A
// mapping on one of r's verified IPs is queued for the peer as
// peer_targets{source: portmap}, at most one per family, sent after the next
// go; later rounds aim at it as well.
func (s *Session) latePortMapLocked(r int, fam protocol.Family, pm protocol.PortMapReport, now time.Duration) {
	st := &s.st
	ext := pm.External
	if netaddr.Private(ext.Addr()) {
		if st.adm.pair.SamePublicIP[fam] && fam.UsableTarget(ext) {
			st.adm.addUpstream(r, fam, ext)
		}
		if s.admitTargetLocked(r, fam, ext, now) {
			s.addPlannerEndpointLocked(r, fam, protocol.Endpoint{Addr: ext, Source: protocol.EndpointPortmap})
		}
		return
	}
	p := 1 - r
	if len(st.rounds.portmap[p]) >= maxQueuedAssists || slices.ContainsFunc(st.rounds.portmap[p], func(a protocol.Assist) bool { return a.Family == fam }) ||
		!s.admitTargetLocked(r, fam, ext, now) {
		return
	}
	st.rounds.portmap[p] = append(st.rounds.portmap[p], protocol.Assist{Family: fam, Targets: []netip.AddrPort{ext}, Source: protocol.TargetsPortmap})
	s.addPlannerEndpointLocked(r, fam, protocol.Endpoint{Addr: ext, Source: protocol.EndpointPortmap, Verified: true})
}

// onPongLocked takes the RTT sample of a pong (P_k = t_recv − t_flushed −
// hold) and, from the smallest sample, the client's clock offset (diagnostic
// only). Pongs of unknown or answered pings are ignored.
func (s *Session) onPongLocked(r int, m *protocol.Pong, now time.Duration) {
	st := &s.st
	l := st.links[r]
	seq := int(m.Seq)
	if seq > int(l.ping.sent) || l.ping.answered[seq] {
		return
	}
	l.ping.answered[seq] = true
	sent, ok := sentAt(&l.markPing[seq])
	if !ok {
		return
	}
	sample := now - sent - time.Duration(m.HoldUs)*time.Microsecond
	if !st.rtt[r].add(sample) {
		return
	}
	if st.offsetRTT[r] != 0 && sample >= st.offsetRTT[r] {
		return
	}
	st.offsetRTT[r] = sample
	st.offset[r] = time.UnixMilli(m.ClientUnixMs).Sub(s.at(sent + sample/2))
	if st.offset[r] > clockSkewWarn || st.offset[r] < -clockSkewWarn {
		st.addWarn(protocol.WarnClockSkew)
	}
}

// onProgressLocked records a progress report in the timeline. Progress is
// telemetry only: it never drives a state, a plan or a memory.
func (s *Session) onProgressLocked(r int, m *protocol.Progress, now time.Duration) {
	st := &s.st
	st.timeline[st.tlN%timelineCap] = StageMark{Role: roleOf(r), Stage: m.Stage, Status: m.Status,
		Round: int(m.Round), OffsetMs: now.Milliseconds()}
	st.tlN++
	st.lastStage[r] = m.Stage
	if s.c.cfg.ObserveProgress {
		s.c.emit(Event{Kind: EvProgress, At: s.at(now), SessionID: s.id, Role: roleOf(r), Round: int(m.Round),
			Labels: s.labels, Data: ProgressData{Stage: m.Stage, Status: m.Status, Round: int(m.Round)}})
	}
}

// onPunchResultLocked handles a client's terminal report. ok:true counts as
// a confirmation (when round_result{confirmed} was lost) and ends the session
// once both sides confirmed and reported. ok:false aborts the other side with
// punch_abort{by: r, code} — unless r is the unconfirmed side of a confirmed
// path, which is only recorded (the session still ends as a half-confirmed
// success).
func (s *Session) onPunchResultLocked(r int, m *protocol.PunchResult, now time.Duration) effects {
	st := &s.st
	var fx effects
	st.confirm.finals[r] = &ClientFinal{
		OK: m.OK, Reason: m.Reason, Phase: m.Phase, Detail: m.Detail, Path: clonePath(m.Path), ExtraPaths: slices.Clone(m.ExtraPaths), Stats: m.Stats,
		Timing: m.Timing, Traits: slices.Clone(m.Traits), Warn: slices.Clone(m.Warn),
	}
	if m.OK {
		if st.state != StatePunching && st.state != StateConfirming {
			fx.end(violation(r, detailUnexpected))
			return fx
		}
		st.confirm.okResult[r] = true
		if !st.confirm.confirmed[r] {
			fx.merge(s.confirmLocked(r, m.Path, now))
		}
		if st.confirm.confirmed[0] && st.confirm.confirmed[1] && st.confirm.okResult[0] && st.confirm.okResult[1] {
			fx.end(&terminal{})
		}
		return fx
	}
	if st.state == StateConfirming && !st.confirm.confirmed[r] && st.confirm.confirmed[1-r] {
		return fx
	}
	t := &terminal{code: m.Reason, detail: trunc.String(m.Detail, protocol.MaxDetail), failed: roleOf(r)}
	if s.ablate.NoEarlyAbort {
		// Ablation: the peer is not told; the session runs to its stage
		// deadline and ends with this code there.
		if st.deferred == nil {
			st.deferred = t
		}
		return fx
	}
	fx.end(t)
	return fx
}

// confirmLocked records side r's confirmation (round_result{confirmed} or
// punch_result{ok}). The first one stops the rounds, the relay and the
// natprobe handle and waits ConfirmLinger for the other side; the second
// waits ResultGrace for the punch_result frames.
func (s *Session) confirmLocked(r int, path *protocol.PathInfo, now time.Duration) effects {
	st := &s.st
	var fx effects
	if st.confirm.confirmed[r] {
		return fx
	}
	st.confirm.confirmed[r] = true
	st.confirm.confirmAt[r] = now
	if path != nil {
		st.confirm.paths[r] = clonePath(path)
	}
	ev := Event{Kind: EvConfirmed, At: s.at(now), SessionID: s.id, Role: roleOf(r), Round: st.rounds.round, Labels: s.labels}
	if path != nil {
		ev.Data = *path
	}
	s.c.emit(ev)
	if !st.confirm.confirmed[1-r] {
		st.state = StateConfirming
		st.plan.void() // a next round being planned is void
		st.confirm.winRound, st.confirm.winVar = st.rounds.round, st.rounds.cur.variant
		if path != nil {
			st.confirm.winFam = path.Family
		}
		if st.rounds.round > 0 && !st.rounds.cur.evaluating {
			st.rounds.cur.evaluating = true
			st.rounds.records = append(st.rounds.records, s.recordLocked(plan.RoundConfirmed, s.at(now)))
		} else if n := len(st.rounds.records); n > 0 && st.rounds.records[n-1].Round == st.rounds.round {
			st.rounds.records[n-1].Class = plan.RoundConfirmed
		}
		s.cancelPingsLocked(waitReady)
		fx.closeHandle = true
		if s.ttl.linger < 0 {
			fx.end(&terminal{})
			return fx
		}
		st.deadline = now + s.ttl.linger
	} else {
		if s.ttl.grace < 0 {
			fx.end(&terminal{})
			return fx
		}
		st.deadline = min(st.deadline, now+s.ttl.grace)
	}
	s.rearmLocked(now)
	return fx
}

func clonePath(p *protocol.PathInfo) *protocol.PathInfo {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

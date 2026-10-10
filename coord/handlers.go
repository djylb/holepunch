package coord

import (
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// violation is a protocol_violation by side r, notified to r as well.
func violation(r int, detail string) *terminal {
	return &terminal{code: protocol.ReasonProtocolViolation, detail: detail, failed: roleOf(r), notifyFailed: true}
}

// onReportLocked handles a probe_report: accepted once per side in binding
// (the first side may probe before the second attaches) and probing, ignored
// once confirming, a violation otherwise. The report gives an RTT sample
// (since punch_start went out, less elapsed_ms). When both are in, the
// session goroutine plans the session.
func (s *Session) onReportLocked(r int, m *protocol.ProbeReport, now time.Duration) effects {
	st := &s.st
	var fx effects
	switch st.state {
	case StateBinding, StateProbing:
		if st.reports[r] != nil {
			fx.end(violation(r, detailDuplicate))
			return fx
		}
	case StateConfirming:
		return fx
	default:
		fx.end(violation(r, detailUnexpected))
		return fx
	}
	l := st.links[r]
	if sent, ok := sentAt(&l.markStart); ok {
		st.rtt[r].add(now - sent - ms(m.ElapsedMs))
	}
	st.reports[r] = m
	st.echoed[r] = s.starts[r].Control.Has(protocol.FeatureSandwich) && m.Control.Has(protocol.FeatureSandwich)
	s.c.emit(Event{Kind: EvReported, At: s.at(now), SessionID: s.id, Role: roleOf(r), Labels: s.labels})
	if st.reports[1-r] == nil {
		l.ping.schedule(waitReport, now)
		s.rearmLocked(now)
		return fx
	}
	s.cancelPingsLocked(waitReport)
	if st.state == StateProbing {
		st.planning = true
		st.work.plan = true
	}
	s.rearmLocked(now)
	return fx
}

// onReadyLocked handles a punch_ready: accepted once per side in summarized,
// ignored later, a violation before. It gives an RTT sample (since the
// summary went out, less elapsed_ms) and carries, maybe, a port mapping
// that finished after the report. When both are in, the first round starts.
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
		return fx
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
	if isLAN(ext.Addr()) {
		if st.pair.SamePublicIP[fam] && usableAddr(ext, fam) {
			st.addUpstream(r, fam, ext)
		}
		if s.admitTargetLocked(r, fam, ext, now) {
			s.addPlannerEndpointLocked(r, fam, protocol.Endpoint{Addr: ext, Source: protocol.EndpointPortmap})
		}
		return
	}
	p := 1 - r
	if len(st.portmap[p]) >= maxQueuedAssists || slices.ContainsFunc(st.portmap[p], func(a protocol.Assist) bool { return a.Family == fam }) ||
		!s.admitTargetLocked(r, fam, ext, now) {
		return
	}
	st.portmap[p] = append(st.portmap[p], protocol.Assist{Family: fam, Targets: []netip.AddrPort{ext}, Source: protocol.TargetsPortmap})
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
	st.finals[r] = &ClientFinal{
		OK: m.OK, Code: m.Code, Phase: m.Phase, Detail: m.Detail, Path: clonePath(m.Path), ExtraPaths: slices.Clone(m.ExtraPaths), Stats: m.Stats,
		Timing: m.Timing, Traits: slices.Clone(m.Traits), Warn: slices.Clone(m.Warn),
	}
	if m.OK {
		if st.state != StatePunching && st.state != StateConfirming {
			fx.end(violation(r, detailUnexpected))
			return fx
		}
		st.okResult[r] = true
		if !st.confirmed[r] {
			fx.merge(s.confirmLocked(r, m.Path, now))
		}
		if st.confirmed[0] && st.confirmed[1] && st.okResult[0] && st.okResult[1] {
			fx.end(&terminal{})
		}
		return fx
	}
	if st.state == StateConfirming && !st.confirmed[r] && st.confirmed[1-r] {
		return fx
	}
	t := &terminal{code: m.Code, detail: truncate(m.Detail, maxDetail), failed: roleOf(r)}
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
	if st.confirmed[r] {
		return fx
	}
	st.confirmed[r] = true
	st.confirmAt[r] = now
	if path != nil {
		st.paths[r] = clonePath(path)
	}
	ev := Event{Kind: EvConfirmed, At: s.at(now), SessionID: s.id, Role: roleOf(r), Round: st.round, Labels: s.labels}
	if path != nil {
		ev.Data = *path
	}
	s.c.emit(ev)
	if !st.confirmed[1-r] {
		st.state = StateConfirming
		st.gen++ // a next round being planned is void
		st.winRound, st.winVar = st.round, st.cur.variant
		if path != nil {
			st.winFam = path.Family
		}
		if st.round > 0 && !st.cur.evaluating {
			st.cur.evaluating = true
			st.records = append(st.records, s.recordLocked(RoundConfirmed, s.at(now)))
		} else if n := len(st.records); n > 0 && st.records[n-1].Round == st.round {
			st.records[n-1].Class = RoundConfirmed
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

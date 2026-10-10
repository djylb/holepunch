package probe

import (
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// The probing state machine. A runState
// belongs to the goroutine in Run: step does what is due at an instant,
// handle consumes one delivered packet and nextWake says when to step next,
// so tests can also drive the machine with explicit times.

// altPhase is the progress of the change-IP test: first the unsolicited
// reply from the second IP, then the solicited probes to it, so that
// contacting the second IP first cannot make ADF look like EIF.
type altPhase uint8

const (
	altUnsolicited altPhase = iota
	altSolicited
	altDone
)

type runState struct {
	p        *Prober
	codec    *udpwire.Codec
	table    *nat.ObsTable
	t0       time.Time
	deadline time.Duration
	rtt0     time.Duration
	minRTT   time.Duration
	clock    protocol.ClockSample

	main    []*target // the mappingDone set
	all     []*target // every target that may be retransmitted
	obs0    *target   // the main target with the lowest observer id
	alts    []nat.Observer
	altTgts []*target
	second  []*target
	topUp   *target
	recs    []*probeRec
	stash   []stashed
	stun    []*stunTarget

	firstSend     time.Duration
	mappingDoneAt time.Duration // < 0 until mappingDone
	secondTried   bool
	secondFirst   time.Duration
	altPhase      altPhase
	altFirst      time.Duration
	extraQuotaOut bool // QUOTA_EXHAUSTED on the ack of a WANT_EXTRA probe
	started       bool
	budget        int // probes to the server left
	stunBudget    int // STUN requests left

	batchOK, batchFail int         // sends to the server in the current step
	batchForeign       bool        // the current step sent a STUN or LAN probe from the primary socket
	failStreak         int         // consecutive steps whose sends to the server all failed
	batches            []batchICMP // ICMP count after each step that sent
	counters           Counters
	buf                []byte
}

// batchICMP is the primary socket's ICMP count right after a step that sent,
// and whether that step also sent to a destination other than the main
// observers of the scope.
type batchICMP struct {
	icmp    uint32
	foreign bool
}

func (s *runState) elapsed() time.Duration { return s.p.clk.Now().Sub(s.t0) }

// rtt is the measured minimum RTT, or RTT0 before the first answer.
func (s *runState) rtt() time.Duration {
	if s.minRTT > 0 {
		return s.minRTT
	}
	return s.rtt0
}

// t1 = clamp(1.5·RTT + 20 ms, 80 ms, 400 ms).
func (s *runState) t1() time.Duration {
	return min(max(s.rtt()*3/2+t1Base, minT1), maxT1)
}

// extraWait = clamp(RTT/2 + 60 ms, 80 ms, 250 ms).
func (s *runState) extraWait() time.Duration {
	return min(max(s.rtt()/2+extraWaitBase, minExtraWait), maxExtraWait)
}

// backoff is the delay before retransmission k+1 after k sends: T1·2^(k−1).
func (s *runState) backoff(k int) time.Duration { return s.t1() << (k - 1) }

// step does everything due at now and reports whether probing is over.
func (s *runState) step(now time.Duration) (Result, bool) {
	s.batchOK, s.batchFail, s.batchForeign = 0, 0, false
	if !s.started {
		s.started = true
		s.firstSend = now
		for _, tg := range s.all {
			s.send(tg, now)
		}
		for _, st := range s.stun {
			s.sendSTUN(st, now)
		}
	}
	s.expire(now)
	for _, tg := range s.all {
		if !tg.acked && tg.sends > 0 && tg.sends < tg.max && now >= tg.last+s.backoff(tg.sends) {
			s.send(tg, now)
		}
	}
	for _, st := range s.stun {
		if !st.done && st.sends < maxOtherSends && now >= st.last+s.t1() {
			s.sendSTUN(st, now)
		}
	}
	s.maybeOpenSecond(now)
	mappingDone := s.mappingDone(now)
	if mappingDone && s.mappingDoneAt < 0 {
		s.mappingDoneAt = now
	}
	s.maybeTopUp(now, mappingDone)
	s.maybeSolicitAlt(now, mappingDone)
	if r, stop := s.endBatch(); stop {
		return r, true
	}
	if now >= s.deadline || (mappingDone && s.filteringDone(now) && s.secondDone(now) && s.altDone(now) && s.stunDone(now)) {
		return s.finish("", ""), true
	}
	return Result{}, false
}

// endBatch applies the early udp_blocked rules, but only
// while no main observer has answered, so a single observer that keeps
// failing cannot fail the family: every send of two consecutive rounds
// failed, or ICMP unreachable followed each of the last two rounds.
//
// The ICMP count is per socket, not per destination. A STUN server or a LAN
// observer probed from the primary socket can answer with ICMP while the
// natprobe observers are merely slow (udp_blocked needs ICMP while every
// observer is silent), so the ICMP rule only applies when neither of the two
// rounds sent such a probe; the hard limit still ends a blocked family.
func (s *runState) endBatch() (Result, bool) {
	if s.batchOK+s.batchFail > 0 || s.batchForeign {
		s.batches = append(s.batches, batchICMP{icmp: s.p.icmp.Load(), foreign: s.batchForeign})
	}
	if s.batchOK+s.batchFail > 0 {
		if s.batchOK == 0 {
			s.failStreak++
		} else {
			s.failStreak = 0
		}
	}
	if s.mainAcked() > 0 {
		return Result{}, false
	}
	if s.failStreak >= blockedStreaks {
		return s.finish(protocol.ReasonUDPBlocked, "send_failed"), true
	}
	if n := len(s.batches); n >= blockedStreaks {
		prev, last := s.batches[n-2], s.batches[n-1]
		if !prev.foreign && !last.foreign && s.p.icmp.Load() > last.icmp && last.icmp > prev.icmp {
			return s.finish(protocol.ReasonUDPBlocked, "icmp_unreachable"), true
		}
	}
	return Result{}, false
}

// serverICMP reports whether ICMP unreachable arrived after a step that
// probed the server only: after a step that also probed a STUN server or a
// LAN observer from the primary socket, it may be theirs.
func (s *runState) serverICMP() bool {
	for i, b := range s.batches {
		after := s.p.icmp.Load()
		if i+1 < len(s.batches) {
			after = s.batches[i+1].icmp
		}
		if !b.foreign && after > b.icmp {
			return true
		}
	}
	return false
}

func (s *runState) mainAcked() int {
	n := 0
	for _, tg := range s.main {
		if tg.acked {
			n++
		}
	}
	return n
}

// mappingDone: every main observer answered, which covers a lone
// observer; or ≥ 2 answered and 3·T1 passed since the first send.
func (s *runState) mappingDone(now time.Duration) bool {
	acked, n := s.mainAcked(), len(s.main)
	return acked == n || (acked >= 2 && now >= s.firstSend+mappingRounds*s.t1())
}

// filteringDone: an extra arrived; or ≥ 2 declarations were
// all waited out; or a single declaration was waited out and the top-up
// settled; or nothing was declared at all (the server sends no extra, or
// its quota ran out), which leaves the filtering unknown.
func (s *runState) filteringDone(now time.Duration) bool {
	declared, settled, seen, requested := 0, 0, 0, false
	for _, r := range s.recs {
		requested = requested || r.want == wantExtra
		if r.extraDeclared {
			declared++
			if r.extraSettled {
				settled++
			}
		}
		if r.extraSeen {
			seen++
		}
	}
	switch {
	case !requested || seen > 0:
		return true
	case declared >= 2:
		return settled == declared
	case declared == 1:
		return settled == 1 && s.topUpSettled(now)
	}
	return true
}

// topUpPossible: observer 0 can still be asked for an extra.
func (s *runState) topUpPossible() bool {
	return s.obs0 != nil && !s.extraQuotaOut && s.p.spec.Probe.ExtraReply && s.budget > 0
}

func (s *runState) topUpSettled(now time.Duration) bool {
	if s.topUp == nil {
		return !s.topUpPossible()
	}
	return s.topUp.acked || s.topUp.sends == 0 || now >= s.topUp.last+settleRounds*s.t1()
}

// maybeTopUp sends the single WANT_EXTRA top-up to observer 0 when the mapping
// is done with exactly one declaration and no extra seen: one lost
// extra must not decide PDF on its own.
func (s *runState) maybeTopUp(now time.Duration, mappingDone bool) {
	if !mappingDone || s.topUp != nil || !s.topUpPossible() {
		return
	}
	declared, seen := 0, 0
	for _, r := range s.recs {
		if r.extraDeclared {
			declared++
		}
		if r.extraSeen {
			seen++
		}
	}
	if declared != 1 || seen != 0 {
		return
	}
	s.topUp = &target{kind: kindTopUp, sock: s.p.primary, sockID: s.p.primaryID, obs: s.obs0.obs, key: s.obs0.key, want: wantExtra, max: 1}
	s.send(s.topUp, now)
}

// maybeOpenSecond opens the second socket once the primary looks APDM (two
// answers with the same IP and different ports) and probes every main
// observer from it.
func (s *runState) maybeOpenSecond(now time.Duration) {
	if s.secondTried || !s.p.spec.Probe.SecondSocket || s.p.openSecond == nil || !s.apdmSuspected() {
		return
	}
	s.secondTried = true
	var h SocketHandle
	var oerr error
	if perr := life.Safe("probe/open-second", func() { h, oerr = s.p.openSecond() }); perr != nil || oerr != nil {
		return
	}
	m, ok := socketMeta(h, s.p.spec.Family, protocol.SocketSecond)
	if !ok || m.ID != nat.SocketID(s.p.spec.Family, nat.IndexSecond) || !s.table.AddSocket(m) {
		return
	}
	s.secondFirst = now
	for _, mt := range s.main {
		tg := &target{kind: kindSecond, sock: h, sockID: m.ID, obs: mt.obs, max: maxOtherSends,
			key: nat.PointKey{Socket: m.ID, Source: nat.SourceServer, Observer: mt.obs.ID}}
		s.second = append(s.second, tg)
		s.all = append(s.all, tg)
		s.send(tg, now)
	}
}

func (s *runState) apdmSuspected() bool {
	var first netip.AddrPort
	for _, tg := range s.main {
		if !tg.observed.IsValid() {
			continue
		}
		if !first.IsValid() {
			first = tg.observed
			continue
		}
		if tg.observed.Addr() == first.Addr() && tg.observed.Port() != first.Port() {
			return true
		}
	}
	return false
}

func (s *runState) secondDone(now time.Duration) bool {
	for _, tg := range s.second {
		if !tg.acked {
			return now >= s.secondFirst+settleRounds*s.t1()
		}
	}
	return true
}

// unsolicitedSettled: the change-IP test of observer 0 is over (the first
// half of altDone).
func (s *runState) unsolicitedSettled(mappingDone bool) bool {
	declared, settled := false, true
	for _, r := range s.recs {
		if r.tg != s.obs0 || r.want != wantAlt {
			continue
		}
		if r.altSeen {
			return true
		}
		if r.altDeclared {
			declared = true
			settled = settled && r.altSettled
		}
	}
	switch {
	case declared:
		return settled
	case s.obs0.acked:
		return true // answered without ALT_SENT: no alt quota, no change-IP evidence
	}
	return mappingDone
}

// maybeSolicitAlt probes the alt group once the unsolicited test settled.
func (s *runState) maybeSolicitAlt(now time.Duration, mappingDone bool) {
	if s.altPhase != altUnsolicited || !s.unsolicitedSettled(mappingDone) {
		return
	}
	s.altPhase, s.altFirst = altSolicited, now
	for _, o := range s.alts {
		tg := &target{kind: kindAlt, sock: s.p.primary, sockID: s.p.primaryID, obs: o, max: maxOtherSends,
			key: nat.PointKey{Socket: s.p.primaryID, Source: nat.SourceServerAlt, Observer: o.ID}}
		s.altTgts = append(s.altTgts, tg)
		s.all = append(s.all, tg)
		s.send(tg, now)
	}
}

func (s *runState) altDone(now time.Duration) bool {
	switch s.altPhase {
	case altUnsolicited:
		return false
	case altDone:
		return true
	case altSolicited:
		// Done once every alt target answered or the settle wait ran out.
	}
	for _, tg := range s.altTgts {
		if !tg.acked {
			return now >= s.altFirst+settleRounds*s.t1()
		}
	}
	return true
}

// stunDone reports whether STUN lets probing finish: every STUN server
// answered, or stunWait passed since mappingDone.
func (s *runState) stunDone(now time.Duration) bool {
	for _, st := range s.stun {
		if !st.done {
			return s.mappingDoneAt >= 0 && now >= s.mappingDoneAt+s.stunWait()
		}
	}
	return true
}

// stunWait is how long STUN may hold DONE back after mappingDone: stunGrace,
// so that a slow or unreachable STUN server never holds probing up; but up to
// stunLANGrace while a LAN-observed family (the server saw only private
// addresses) has no STUN answer yet, since a STUN answer is the only public
// address it can report. The hard limit bounds both.
func (s *runState) stunWait() time.Duration {
	if slices.ContainsFunc(s.stun, func(st *stunTarget) bool { return st.done }) || !s.table.LANObserved() {
		return stunGrace
	}
	return stunLANGrace
}

// expire settles the declarations whose wait ran out, as negative filtering
// evidence, and drops stale stashed extras.
func (s *runState) expire(now time.Duration) {
	for _, r := range s.recs {
		if r.extraDeclared && !r.extraSettled && now >= r.extraDue {
			r.extraSettled = true
			s.table.AddFilter(nat.FilterEvidence{Socket: r.tg.sockID, Observer: r.tg.obs.ID, ExtraDeclared: 1})
		}
		if r.altDeclared && !r.altSettled && now >= r.altDue {
			r.altSettled = true
			s.table.AddFilter(nat.FilterEvidence{Socket: r.tg.sockID, Observer: r.tg.obs.ID, AltDeclared: 1})
		}
	}
	kept := s.stash[:0]
	for _, x := range s.stash {
		if now < x.at+stashTTL {
			kept = append(kept, x)
		}
	}
	s.stash = kept
}

// nextWake returns the earliest future instant at which step has work, or
// the deadline.
func (s *runState) nextWake(now time.Duration) time.Duration {
	next := s.deadline
	at := func(t time.Duration) {
		if t > now && t < next {
			next = t
		}
	}
	for _, tg := range s.all {
		if !tg.acked && tg.sends > 0 && tg.sends < tg.max {
			at(tg.last + s.backoff(tg.sends))
		}
	}
	for _, r := range s.recs {
		if r.extraDeclared && !r.extraSettled {
			at(r.extraDue)
		}
		if r.altDeclared && !r.altSettled {
			at(r.altDue)
		}
	}
	for _, x := range s.stash {
		at(x.at + stashTTL)
	}
	for _, st := range s.stun {
		if !st.done && st.sends < maxOtherSends {
			at(st.last + s.t1())
		}
	}
	at(s.firstSend + mappingRounds*s.t1())
	if len(s.second) > 0 {
		at(s.secondFirst + settleRounds*s.t1())
	}
	if s.altPhase == altSolicited {
		at(s.altFirst + settleRounds*s.t1())
	}
	if s.topUp != nil && s.topUp.sends > 0 {
		at(s.topUp.last + settleRounds*s.t1())
	}
	if s.mappingDoneAt >= 0 {
		at(s.mappingDoneAt + s.stunWait())
	}
	return next
}

// finish classifies the table and builds the result. Without any answer
// from a main observer the family fails: udp_blocked when sends to the
// server failed (or, next, ICMP answered them), probe_timeout otherwise. A
// STUN server that failed, stayed silent or answered with ICMP changes
// nothing.
func (s *runState) finish(failure protocol.Reason, detail string) Result {
	tr := s.table.Classify()
	if failure == "" && s.mainAcked() == 0 {
		switch {
		case s.counters.SendErrors > 0:
			failure, detail = protocol.ReasonUDPBlocked, "send_failed"
		case s.serverICMP():
			failure, detail = protocol.ReasonUDPBlocked, "icmp_unreachable"
		default:
			failure = protocol.ReasonProbeTimeout
		}
	}
	s.p.observed = tr.Observed
	c := s.counters
	c.Dropped = s.p.dropped.Load()
	c.ICMP = s.p.icmp.Load()
	return Result{Table: s.table, Traits: tr, Clock: s.clock, Sent: c, Failure: failure, Detail: detail}
}

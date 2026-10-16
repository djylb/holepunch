package coord

import (
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/protocol"
)

// Round rules.
const (
	minRoundBudget = 60  // BudgetLeft below this ends the punch (packet_budget_exceeded)
	auditTolerance = 1.1 // a side may send granted × 1.1
	auditStrikes   = 2   // consecutive violations end the session
	icmpBlocked    = 50  // icmp_unreach of a round marking the path blocked
	maxSeenFrom    = 8   // evidence: peer sources kept per side
	maxMappings    = 16  // planner input: punch-time mappings kept per side
	recentWindow   = 10 * time.Second
)

// decision is a planner's round decision; after a panic the default planner
// took over and classified the pair again.
type decision struct {
	dec      RoundDecision
	cls      Classification
	planner  Planner
	switched bool
	ok       bool
}

// decide runs the planner's Round outside the lock. A panicking planner is
// replaced by the default one (which classifies the pair again from the same
// input); a panicking default planner fails the decision.
func (s *Session) decide(p Planner, cin ClassifyInput, in RoundInput) decision {
	d := decision{planner: p, cls: in.Class}
	err := life.Safe("coord.plan", func() {
		if err := faultinject.Point(fiPlan); err != nil {
			panic(err)
		}
		d.dec = p.Round(in)
	})
	if err == nil {
		d.ok = true
		return d
	}
	s.c.noteCallbackPanic(s.id, err)
	if _, isDefault := p.(plan.DefaultPlanner); isDefault {
		return d
	}
	def := plan.DefaultPlanner{}
	if life.Safe("coord.plan.default", func() {
		d.cls = def.Classify(cin)
		in.Class, in.Order, in.MemoryPromoted = d.cls, nil, false
		d.dec = def.Round(in)
		if d.cls.Reject != "" {
			d.dec = RoundDecision{Stop: d.cls.Reject}
		}
	}) != nil {
		return d
	}
	d.planner, d.switched, d.ok = def, true, true
	return d
}

// takeDecisionLocked adopts the planner switch of a decision.
func (s *Session) takeDecisionLocked(d decision) bool {
	if !d.ok {
		return false
	}
	if d.switched {
		st := &s.st
		st.planner, st.cls = d.planner, d.cls
		st.order, st.promoted = slices.Clone(d.cls.Ladder), false
	}
	return true
}

// roundInputLocked is the planner input of round k at session time now.
func (s *Session) roundInputLocked(k int, now time.Duration) RoundInput {
	st := &s.st
	a := align([2]*rttEstimator{&st.rtt[0], &st.rtt[1]}, s.ablate.NoRTTAlign)
	// The planner runs outside the lock and may write its input: what it
	// shares with the session state is copied.
	in := RoundInput{
		Round:             k,
		Class:             cloneClassification(st.cls),
		Order:             slices.Clone(st.order),
		Prev:              slices.Clone(st.prev),
		Evidence:          cloneEvidence(st.ev),
		RTT:               a.rtt,
		Remaining:         s.remainingLocked(now),
		D:                 a.d,
		BudgetLeft:        [2]int{s.budgetLeftLocked(0, now), s.budgetLeftLocked(1, now)},
		Recent10sDistinct: s.recentDistinctLocked(now),
		Gone:              st.gone,
		RescueUsed:        st.rescueUsed || s.ablate.NoRounds,
		Views:             [2]protocol.PeerView{clonePeerView(st.pviews[0]), clonePeerView(st.pviews[1])},
		Policy:            clonePolicy(*s.starts[0].Policy),
		AllowExtreme:      s.c.cfg.Budget.AllowExtreme,
		MaxRounds:         int(s.to.MaxRounds),
		HandshakeMs:       s.to.HandshakeTimeoutMs,
		SandwichOK:        st.sandwich,
		MemoryPromoted:    st.promoted && k == 1,
		FireAt:            s.fireAtLocked(a, now),
		Mappings:          [2][]MappingSample{slices.Clone(st.mappings[0]), slices.Clone(st.mappings[1])},
	}
	return in
}

// fireAtLocked is when the round planned now is expected to fire, on the
// FireAt axis: (now + D) − the registration, as its go leaves now
// and fires D later. The first round's go also waits for the summaries to
// reach both sides and their ready to come back, about one round trip of the
// slower side — what is left of it once the summaries are out (an anchor
// refresh plans round 1 again then).
func (s *Session) fireAtLocked(a alignment, now time.Duration) time.Duration {
	at := now + a.d - s.regAt
	if st := &s.st; st.round == 0 {
		wait := max(a.rtt[0], a.rtt[1])
		if st.summarized {
			wait = max(st.summaryAt+wait-now, 0)
		}
		at += wait
	}
	return at
}

// addMappingLocked records addr as one of side r's external mappings, seen
// by its peer in round k, at that round's fire time on the FireAt axis (the
// planner's estimate). A mapping keeps its first sighting; past
// maxMappings the oldest goes.
func (s *Session) addMappingLocked(r, k int, addr netip.AddrPort) {
	if !addr.IsValid() || addr.Port() == 0 {
		return
	}
	list := &s.st.mappings[r]
	if slices.ContainsFunc(*list, func(m MappingSample) bool { return m.Addr == addr }) {
		return
	}
	if len(*list) >= maxMappings {
		*list = slices.Delete(*list, 0, 1)
	}
	*list = append(*list, MappingSample{Addr: addr, At: s.st.fireAt[k] - s.regAt, Round: k})
}

// remainingLocked is punchDeadline − now; before the first go the whole
// handshake budget is ahead.
func (s *Session) remainingLocked(now time.Duration) time.Duration {
	if s.st.round == 0 {
		return ms(s.to.HandshakeTimeoutMs) + s.ttl.punchSlack
	}
	return s.st.punchDeadline - now
}

// budgetLeftLocked is how many packets side r may still be granted: the
// session budget minus the grants, and the client key's quota.
func (s *Session) budgetLeftLocked(r int, now time.Duration) int {
	left := int(s.budget.MaxPackets) - s.st.granted[r]
	if k := s.c.limiter.packetsLeft(s.at(now), r, s.keys[r]); k >= 0 {
		left = min(left, k)
	}
	return max(left, 0)
}

// recentDistinctLocked sums the distinct ports granted to each side in the
// rounds started within the last 10 s (a sliding window).
func (s *Session) recentDistinctLocked(now time.Duration) [2]int {
	var out [2]int
	for _, rr := range s.st.records {
		if s.since(rr.StartedAt) < now-recentWindow {
			continue
		}
		for r := range out {
			out[r] += s.st.recentPorts[rr.Round][r]
		}
	}
	return out
}

func cloneEvidence(e Evidence) Evidence {
	for r := range e.SeenFrom {
		e.SeenFrom[r] = slices.Clone(e.SeenFrom[r])
	}
	return e
}

// startRoundLocked writes the go frames of the prepared round to both sides
// in one critical section, each with its own delay so that both fire D after
// the write, and arms the round deadline.
func (s *Session) startRoundLocked(now time.Duration) effects {
	st := &s.st
	cur := &st.cur
	var fx effects
	a := align([2]*rttEstimator{&st.rtt[0], &st.rtt[1]}, s.ablate.NoRTTAlign)
	cur.align = a
	cur.goAt = now
	st.round = cur.n
	st.fireAt[cur.n] = now + a.d
	if cur.n == 1 {
		st.state = StatePunching
		st.firstGoAt = now
		st.punchDeadline = now + ms(s.to.HandshakeTimeoutMs) + s.ttl.punchSlack
	}
	push := s.goPushLocked()
	for r, l := range st.links {
		if l == nil || l.dead || st.gone[r] {
			continue
		}
		pl := cur.plans[r]
		g := protocol.PunchGo{
			SessionID: s.id,
			Round:     uint8(cur.n),
			DelayMs:   uint16(a.delay[r] / time.Millisecond),
			WindowMs:  pl.WindowMs,
			Final:     pl.Final,
			RTTMs:     uint16(min(a.rtt[r], 65535*time.Millisecond) / time.Millisecond),
		}
		if cur.n > 1 || cur.reanchored[r] {
			// Round 1's plan travels in the summary; a round-1 go carries
			// it again only re-aimed by an anchor refresh.
			g.Plan = &pl
		}
		fx.merge(s.sendMarkedLocked(r, g, &l.markGo[cur.n]))
	}
	cur.deadline = now + a.d + cur.window + max(a.rtt[0], a.rtt[1]) + roundTailSlack
	st.deadline = min(cur.deadline, st.punchDeadline)
	for r := range push {
		for _, t := range push[r] {
			if s.sendTargetsLocked(r, t, now) == nil && t.Source == protocol.TargetsDrift {
				for _, a := range t.Targets {
					s.adoptDriftLocked(1-r, t.Family, a, cur.n-1)
				}
			}
		}
	}
	s.rearmLocked(now)
	s.c.emit(Event{Kind: EvGo, At: s.at(now), SessionID: s.id, Round: cur.n, Labels: s.labels, Data: GoData{
		Delay: a.delay, RTT: a.rtt, Variant: cur.name, Budget: cur.class, Granted: cur.granted,
		Rescue: cur.rescue, Sandwich: sandwichFamilies(cur),
	}})
	return fx
}

// goPushLocked collects the peer_targets that follow the go to each side,
// in the order the per-round limit (TargetsPerRound) keeps them: the peer's
// upstream-LAN candidates, every round while both sides leave through the
// same public IP, then the port mappings and the drifted
// mappings queued since the last go.
func (s *Session) goPushLocked() [2][]protocol.Assist {
	st := &s.st
	var push [2][]protocol.Assist
	for r := range push {
		for _, f := range st.pair.SharedFamilies {
			if t := st.upstream[1-r][f]; len(t) > 0 && st.pair.SamePublicIP[f] {
				push[r] = append(push[r], protocol.Assist{Family: f, Targets: slices.Clone(t), Source: protocol.TargetsPortmap})
			}
		}
		push[r] = append(append(push[r], st.portmap[r]...), st.pending[r]...)
	}
	st.portmap, st.pending = [2][]protocol.Assist{}, [2][]protocol.Assist{}
	return push
}

// onRoundResultLocked handles a round_result. A confirmation is taken in
// punching and confirming; other results only count in punching: for the
// current round (once per side) they end the round when both are in, a late
// one (the previous round, or the current one after its deadline) only adds
// evidence. Every result is audited against the grant.
func (s *Session) onRoundResultLocked(r int, m *protocol.RoundResult, now time.Duration) effects {
	st := &s.st
	var fx effects
	switch st.state {
	case StatePunching:
	case StateConfirming:
		if m.Status == protocol.RoundConfirmed {
			fx.merge(s.confirmLocked(r, m.Path, now))
		}
		return fx
	default:
		fx.end(violation(r, detailUnexpected))
		return fx
	}
	k := int(m.Round)
	switch {
	case k > st.round:
		fx.end(violation(r, "round"))
		return fx
	case k < st.round-1:
		return fx
	}
	s.addEvidenceLocked(r, m)
	current := k == st.round && !st.cur.evaluating && st.cur.results[r] == nil
	if current {
		st.cur.results[r] = m
		if sent, ok := sentAt(&st.links[r].markGo[k]); ok {
			st.rtt[r].add(now - sent - ms(m.ElapsedMs))
		}
		if term := s.auditLocked(r, m); term != nil {
			fx.end(term)
			return fx
		}
	}
	if m.Status == protocol.RoundConfirmed {
		fx.merge(s.confirmLocked(r, m.Path, now))
		return fx
	}
	if st.ev.Fatal[0] == protocol.ReasonUDPBlocked && st.ev.Fatal[1] == protocol.ReasonUDPBlocked {
		fx.end(&terminal{code: protocol.ReasonUDPBlocked})
		return fx
	}
	if current && st.cur.results[1-r] != nil {
		fx.merge(s.endRoundLocked(now))
	}
	return fx
}

// addEvidenceLocked accumulates a round result into the cross-round evidence.
func (s *Session) addEvidenceLocked(r int, m *protocol.RoundResult) {
	ev := &s.st.ev
	var bindFailed uint16
	for _, f := range m.Families {
		ev.Hit[r] = ev.Hit[r] || f.Hit
		ev.PeerSeenUs[r] = ev.PeerSeenUs[r] || f.PeerSeenUs
		ev.Drift[r] = ev.Drift[r] || f.Drift
		ev.BudgetHit[r] = ev.BudgetHit[r] || f.BudgetHit
		ev.Sent[r] += f.Sent
		ev.ICMPUnreach[r] = uint16(min(int(ev.ICMPUnreach[r])+int(f.ICMPUnreach), 0xffff))
		bindFailed += f.BindFailed
		for _, a := range f.SeenFrom {
			addSeen(&ev.SeenFrom[r], a)
			s.addMappingLocked(1-r, int(m.Round), a)
		}
	}
	ev.BindFailed[r] = bindFailed
	for _, f := range m.Families {
		if f.Remap != nil {
			echo := *f.Remap
			s.st.remaps[r][famIndex(f.Family)] = &echo
		}
	}
	if m.Status == protocol.RoundFatal {
		ev.Fatal[r] = m.Code
	}
	if m.Status != protocol.RoundFatal || sentOf(m) > 0 {
		ev.Fired[r] = true
	}
}

func addSeen(list *[]netip.AddrPort, a netip.AddrPort) {
	if !a.IsValid() || slices.Contains(*list, a) || len(*list) >= maxSeenFrom {
		return
	}
	*list = append(*list, a)
}

func sentOf(m *protocol.RoundResult) int {
	n := 0
	for _, f := range m.Families {
		n += int(f.Sent)
	}
	return n
}

// auditLocked compares what side r sent with its grant. Packets
// beyond the grant are first taken as the pushed targets' and paid from the
// side's push credit, whichever round the client sent them in; more
// than granted × 1.1 beyond that halves the side's later grants, twice in a
// row is a protocol violation.
func (s *Session) auditLocked(r int, m *protocol.RoundResult) *terminal {
	st := &s.st
	granted, sent := st.cur.granted[r], sentOf(m)
	paid := min(max(sent-granted, 0), st.credit[r])
	st.credit[r] -= paid
	sent -= paid
	if granted <= 0 || float64(sent) <= float64(granted)*auditTolerance {
		st.strikes[r] = 0
		return nil
	}
	st.ctr.BudgetViolation++
	st.halve[r] = true
	st.strikes[r]++
	if st.strikes[r] >= auditStrikes {
		return violation(r, detailBudgetViolation)
	}
	return nil
}

// roundClass reads a round from both results.
func roundClass(res [2]*protocol.RoundResult) RoundClass {
	if res[0] == nil || res[1] == nil {
		return RoundNoReport
	}
	var seen [2]bool
	hitBoth := false
	blocked := false
	for r, m := range res {
		for _, f := range m.Families {
			seen[r] = seen[r] || f.Hit || len(f.SeenFrom) > 0
			blocked = blocked || f.ICMPUnreach >= icmpBlocked
			if f.Hit && r == 0 {
				for _, g := range res[1].Families {
					hitBoth = hitBoth || g.Family == f.Family && g.Hit
				}
			}
		}
		blocked = blocked || m.Status == protocol.RoundFatal && m.Code == protocol.ReasonUDPBlocked
	}
	switch {
	case hitBoth || seen[0] && seen[1]:
		// Both directions carried packets: the confirmation was lost.
		return RoundConfirmLost
	case seen[0] != seen[1]:
		return RoundOneWay
	case blocked:
		return RoundBlocked
	}
	return RoundNoContact
}

// familyNoContact reports whether both results of a round show family fam
// without any contact — no hit, no peer source — and without a blocked
// path or a fatal write failure (FamilyRound.NoContact). A missing
// result says nothing.
func familyNoContact(res [2]*protocol.RoundResult, fam protocol.Family) bool {
	for _, m := range res {
		if m == nil || m.Status == protocol.RoundFatal {
			return false
		}
		for _, f := range m.Families {
			if f.Family == fam && (f.Hit || len(f.SeenFrom) > 0 || f.ICMPUnreach >= icmpBlocked) {
				return false
			}
		}
	}
	return true
}

// familyHeard reports, by role, whether a side heard its peer in family
// fam during a round: a hit or a peer source in its result
// (FamilyRound.Heard).
func familyHeard(res [2]*protocol.RoundResult, fam protocol.Family) [2]bool {
	var out [2]bool
	for r, m := range res {
		if m == nil {
			continue
		}
		for _, f := range m.Families {
			out[r] = out[r] || f.Family == fam && (f.Hit || len(f.SeenFrom) > 0)
		}
	}
	return out
}

// classNow is the class of the round under way as far as its results go.
func (c *roundState) classNow() RoundClass { return roundClass(c.results) }

// recordLocked describes the round under way, ended now with class.
func (s *Session) recordLocked(class RoundClass, now time.Time) RoundRecord {
	cur := &s.st.cur
	rec := RoundRecord{
		Round:     cur.n,
		Variant:   cur.variant,
		Budget:    cur.class,
		Rescue:    cur.rescue,
		Class:     class,
		Granted:   cur.granted,
		StartedAt: s.at(cur.goAt),
		Duration:  max(now.Sub(s.at(cur.goAt)), 0),
	}
	for r, m := range cur.results {
		if m != nil {
			rec.Sent[r] = sentOf(m)
		}
	}
	return rec
}

// endRoundLocked ends the round under way (both results in, or its deadline)
// and applies the coordinator's stop rules before the planner is asked for
// the next round on the session goroutine.
func (s *Session) endRoundLocked(now time.Duration) effects {
	st := &s.st
	cur := &st.cur
	var fx effects
	cur.evaluating = true
	class := cur.classNow()
	st.records = append(st.records, s.recordLocked(class, s.at(now)))
	st.prev = append(st.prev, s.outcomeLocked(class))
	rec := st.records[len(st.records)-1]
	s.c.emit(Event{Kind: EvRoundEnded, At: s.at(now), SessionID: s.id, Round: cur.n, Labels: s.labels,
		Data: RoundEndedData{Class: class, Sent: rec.Sent, Hit: st.ev.Hit}})
	if noAdmissibleTarget(cur.results) {
		// Neither client may send to anything the round aimed at: later
		// rounds aim at the same addresses.
		s.planEndLocked(&fx, &terminal{code: protocol.ReasonCandidateTimeout, detail: detailNoAdmissible}, now)
		return fx
	}
	if term := s.stopRulesLocked(class, now); term != nil {
		if term.code == protocol.ReasonControlInterrupted {
			fx.end(term) // a lost link, not a planning decision
		} else {
			s.planEndLocked(&fx, term, now)
		}
		return fx
	}
	st.planning = true
	st.work.evalRound = true
	st.deadline = st.punchDeadline
	s.rearmLocked(now)
	s.kick()
	return fx
}

// noAdmissibleTarget reports whether both sides' results of a round show
// nothing sent and targets refused by admission.
func noAdmissibleTarget(res [2]*protocol.RoundResult) bool {
	for _, m := range res {
		if m == nil || sentOf(m) > 0 {
			return false
		}
		rejected := 0
		for _, f := range m.Families {
			rejected += int(f.Rejected)
		}
		if rejected == 0 {
			return false
		}
	}
	return true
}

// outcomeLocked is the planner's summary of the round under way, ended with
// class: the granted class, the decision's families with the mappings
// each side made in them (mappedLocked), whether they saw any
// contact and which side heard the other, and the round's
// own seen_from and hits, not the cumulative evidence.
func (s *Session) outcomeLocked(class RoundClass) RoundOutcome {
	cur := &s.st.cur
	out := RoundOutcome{Round: cur.n, Variant: cur.variant, Class: class, Rescue: cur.rescue, Budget: cur.class,
		Families: slices.Clone(cur.families)}
	for i := range out.Families {
		for r := range 2 {
			out.Families[i].Mapped[r] = s.mappedLocked(r, out.Families[i].Family)
		}
		out.Families[i].NoContact = familyNoContact(cur.results, out.Families[i].Family)
		out.Families[i].Heard = familyHeard(cur.results, out.Families[i].Family)
	}
	for r, m := range cur.results {
		if m == nil {
			continue
		}
		for _, f := range m.Families {
			out.Hit[r] = out.Hit[r] || f.Hit
			for _, a := range f.SeenFrom {
				addSeen(&out.SeenFrom[r], a)
			}
		}
	}
	return out
}

// sandwichProbes is what a side's sandwich probes map in a round: its helper
// socket is new every round, so both probes are new mappings.
const sandwichProbes = 2

// sandwichFamilies lists, by role, the families whose sandwich probe runs
// in the round (GoData.Sandwich).
func sandwichFamilies(cur *roundState) [2][]protocol.Family {
	var out [2][]protocol.Family
	for r := range out {
		for _, fs := range cur.plans[r].Sides {
			if cur.sandwich[r][famIndex(fs.Family)] {
				out[r] = append(out[r], fs.Family)
			}
		}
	}
	return out
}

// mappedLocked is how many new external mappings side r made in family fam
// during the round under way on an endpoint-dependent NAT (FamilyRound.Mapped):
// its granted plan's new (socket, destination) pairs — Direct targets on the
// round sockets that never sent to them, by the side's ledger, minus the
// sockets it failed to bind; spray ports no more than the distinct ports it
// reported sending — the peer_targets ports it was sent, the sandwich probes,
// and the re-observation probe when it found a new mapping (round_result
// remap), and the two new sockets of an anchor refresh before the round. It
// records the round's Direct targets in the ledger, so it runs once per round.
func (s *Session) mappedLocked(r int, fam protocol.Family) int {
	st := &s.st
	cur := &st.cur
	fi := famIndex(fam)
	n := cur.pushed[r][fi]
	var res *protocol.FamilyOutcome
	if m := cur.results[r]; m != nil {
		for i := range m.Families {
			if m.Families[i].Family == fam {
				res = &m.Families[i]
			}
		}
	}
	if res != nil && res.Remap != nil {
		n++
	}
	if st.refresh.k == cur.n && st.refresh.asked[r][fi] {
		n += refreshProbes // the anchor refresh's two new sockets before the round
	}
	i := slices.IndexFunc(cur.plans[r].Sides, func(fs protocol.FamilySide) bool { return fs.Family == fam })
	if i < 0 || cur.plans[r].Sides[i].Role == protocol.SideReplyOnly {
		return n
	}
	fs := cur.plans[r].Sides[i]
	if res != nil {
		fs.Sockets = uint16(max(int(fs.Sockets)-int(res.BindFailed), 1))
	}
	if st.directSent[r][fi] == nil {
		st.directSent[r][fi] = map[netip.AddrPort]int{}
	}
	sent := st.directSent[r][fi]
	direct, spray := plan.SideMappings(fs, func(t netip.AddrPort) int { return sent[t] })
	if res != nil {
		spray = min(spray, reportedSpray(fs, res))
	}
	for _, sg := range fs.Stages {
		if sg.Kind == protocol.StageDirect {
			for _, t := range sg.Targets {
				sent[t] = max(sent[t], int(fs.Sockets))
			}
		}
	}
	n += direct + spray
	if cur.sandwich[r][fi] {
		n += sandwichProbes
	}
	return n
}

// reportedSpray is how many spray ports a family side's round_result says it
// sent: the distinct ports of its planned packets to the spray IP less its
// Direct targets there. A side stops spraying at the first peer packet, so the
// grant alone would count mappings it never made.
func reportedSpray(fs protocol.FamilySide, res *protocol.FamilyOutcome) int {
	var ip netip.Addr
	for _, sg := range fs.Stages {
		if sg.Kind == protocol.StagePredict || sg.Kind == protocol.StageRandom || sg.Kind == protocol.StageFreshPeer {
			ip = sg.IP
		}
	}
	var direct []netip.AddrPort
	for _, sg := range fs.Stages {
		for _, t := range sg.Targets {
			if sg.Kind == protocol.StageDirect && t.Addr() == ip && !slices.Contains(direct, t) {
				direct = append(direct, t)
			}
		}
	}
	return max(int(res.DistinctPorts)-len(direct), 0)
}

// stopRulesLocked are the coordinator's stop rules, checked before the
// planner: a lost control link, too little time left, the last round
// (announced final, or max_rounds reached with no rescue to come), or too
// little budget.
func (s *Session) stopRulesLocked(class RoundClass, now time.Duration) *terminal {
	st := &s.st
	for r, g := range st.gone {
		if g {
			return goneTerm(roleOf(r))
		}
	}
	a := align([2]*rttEstimator{&st.rtt[0], &st.rtt[1]}, s.ablate.NoRTTAlign)
	rescueNext := class == RoundOneWay && !st.rescueUsed && !s.ablate.NoRounds
	switch {
	case s.remainingLocked(now) < minWindow+a.d,
		st.cur.final,
		st.nonRescue >= int(s.to.MaxRounds) && !rescueNext:
		return s.stopTermLocked("", "")
	}
	for r := range 2 {
		if s.budgetLeftLocked(r, now) < minRoundBudget {
			return &terminal{code: protocol.ReasonPacketBudgetExceeded}
		}
	}
	return nil
}

// stopTermLocked is the end of an unconfirmed punch: the planner's stop
// reason and detail, or the attribution from both sides' evidence (plan.Attribute;
// hard_symmetric_random only when both sides are RND, or when natprobe
// measured the pair as one only the two cheap rounds can open and they ran
// — whether the planner ended the ladder or max_rounds did).
func (s *Session) stopTermLocked(reason protocol.Reason, stopDetail string) *terminal {
	st := &s.st
	code, detail := plan.AttributeDetail(st.ev)
	if reason == "" {
		reason = plan.TerminalReason(st.ev, st.bothRND() || st.seqRndVerdict())
	}
	if reason != code {
		detail = ""
	}
	if stopDetail != "" {
		detail = stopDetail
	}
	return plannerEnd(reason, detail)
}

// seqRndVerdict reports whether the primary family is a seq_x_rnd pair
// natprobe measured as one no rung after the two cheap ones can open, and
// both of them ran (plan.SeqRndVerdict).
func (st *sessionState) seqRndVerdict() bool {
	return st.cls.PairClass == plan.PairSeqRnd && len(st.cls.Families) > 0 && st.nonRescue >= plan.CheapRounds &&
		plan.SeqRndVerdict(st.cin.Measured, st.cls.Families[0])
}

// bothRND reports whether both sides of the primary family are RND.
func (st *sessionState) bothRND() bool {
	if len(st.cls.Families) == 0 {
		return false
	}
	for _, v := range st.views {
		fv, ok := familyView(v, st.cls.Families[0])
		if !ok || plan.CategoryOf(fv.Traits) != plan.CatRND {
			return false
		}
	}
	return true
}

// nextRound runs on the session goroutine after a round ended: it asks the
// planner for the next round outside the lock and starts it if the session
// is still waiting for it.
func (s *Session) nextRound() {
	drift := s.observeDrift()
	var (
		in  RoundInput
		cin ClassifyInput
		p   Planner
		gen uint64
		ok  bool
	)
	now := s.since(s.c.set.clock.Now())
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		st := &s.st
		if st.state != StatePunching || !st.cur.evaluating || !st.planning {
			return
		}
		s.takeDriftLocked(drift)
		in, cin, p, gen, ok = s.roundInputLocked(st.cur.n+1, now), st.cin, st.planner, st.gen, true
	}()
	if !ok {
		return
	}
	d := s.decide(p, cin, in)
	nowT := s.c.set.clock.Now()
	var fx effects
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		st := &s.st
		k := st.cur.n + 1
		if st.gen == gen && st.state == StatePunching && st.planning && k <= maxRound &&
			s.beginRefreshLocked(k, gen, d, cin, in, s.since(nowT)) {
			return // the round waits for its anchor refresh
		}
		fx = s.applyRoundLocked(gen, k, d, nowT)
	}()
	s.apply(fx)
}

// applyRoundLocked starts round k with decision d, or ends the session as
// d says, unless the session moved on since the round's planning began
// (gen).
func (s *Session) applyRoundLocked(gen uint64, k int, d decision, nowT time.Time) effects {
	st := &s.st
	var fx effects
	if st.gen != gen || st.state != StatePunching || !st.planning || k != st.cur.n+1 {
		return fx
	}
	st.planning = false
	now := s.since(nowT)
	switch {
	case !s.takeDecisionLocked(d):
		fx.end(&terminal{code: protocol.ReasonInternal, detail: "panic:planner"})
	case d.dec.Stop != "":
		s.planEndLocked(&fx, s.stopTermLocked(d.dec.Stop, d.dec.StopDetail), now)
	case k > maxRound:
		s.planEndLocked(&fx, s.stopTermLocked("", ""), now)
	default:
		if term := s.prepareRoundLocked(k, d.dec, now); term != nil {
			s.planEndLocked(&fx, term, now)
			return fx
		}
		fx.merge(s.startRoundLocked(now))
	}
	return fx
}

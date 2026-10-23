package coord

import (
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/ablation"
	engine "github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// fired is an outcome of a round in which the side fired and saw nothing.
func fired(sent uint32) simclient.Outcome {
	return simclient.Outcome{Family: protocol.FamilyUDP4, Sent: sent}
}

// endRound sends both window_end results of round k and waits for the next
// go (or the end of the session).
func (p *pair) endRound(k uint8, out [2]simclient.Outcome) [2]*protocol.PunchGo {
	p.r.t.Helper()
	for i := range 2 {
		p.windowEnd(i, k, out[i])
	}
	var gos [2]*protocol.PunchGo
	for i := range 2 {
		m, _, err := p.cl[i].Next(ctx(p.r.t))
		if err != nil {
			return gos
		}
		g, ok := m.(*protocol.PunchGo)
		if !ok {
			return gos
		}
		gos[i] = g
	}
	return gos
}

// TestRoundsAdvance: NoContact rounds climb the ladder, each later go
// carries its plan, and the budget class rises at most one step a round.
func TestRoundsAdvance(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	prev := protocol.BudgetLight
	for k := uint8(1); k < 4; k++ {
		gos := p.endRound(k, [2]simclient.Outcome{fired(3), fired(3)})
		if gos[0] == nil {
			break
		}
		if gos[0].Round != k+1 || gos[0].Plan == nil || gos[1].Plan.Seed != gos[0].Plan.Seed {
			t.Fatalf("round %d go %+v", k+1, gos[0])
		}
		if c := gos[0].Plan.Budget; c.Rank() > prev.Rank()+1 {
			t.Fatalf("class %s after %s", c, prev)
		}
		prev = gos[0].Plan.Budget
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	res := r.wait(p.s)
	for _, rr := range res.Rounds[:len(res.Rounds)-1] {
		if rr.Class != plan.RoundNoContact {
			t.Fatalf("rounds %+v", res.Rounds)
		}
	}
	if st := r.c.Stats(); st.RoundsByClass[plan.RoundNoContact] == 0 {
		t.Fatalf("stats %+v", st)
	}
}

// TestRescueRound: a one-way round is followed by the session's single
// rescue round, which does not count against max_rounds; a punch that stays
// one-way ends with one_way_udp_only and the direction.
func TestRescueRound(t *testing.T) {
	r := newRig(t)
	to := protocol.Timeouts{MaxRounds: 1}
	p := r.pair(SessionOptions{Timeouts: &to})
	p.punching()
	heard := simclient.Outcome{Family: protocol.FamilyUDP4, Sent: 3, SeenFrom: []netip.AddrPort{pubR}}
	gos := p.endRound(1, [2]simclient.Outcome{heard, fired(3)})
	if gos[0] == nil || !gos[0].Plan.Rescue || gos[0].Round != 2 {
		t.Fatalf("rescue go %+v", gos[0])
	}
	if !gos[0].Final {
		t.Fatal("the rescue round after the last ladder round is final")
	}
	p.endRound(2, [2]simclient.Outcome{heard, fired(3)})
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonOneWayUDPOnly || res.Detail != "initiator_hears_responder" || res.Outcome != OutcomeFailed {
		t.Fatalf("result %+v", res)
	}
	if len(res.Rounds) != 2 || !res.Rounds[1].Rescue || res.Rounds[0].Class != plan.RoundOneWay {
		t.Fatalf("rounds %+v", res.Rounds)
	}
}

// TestMaxRounds: max_rounds ends the punch with the attribution.
func TestMaxRounds(t *testing.T) {
	r := newRig(t)
	to := protocol.Timeouts{MaxRounds: 2}
	p := r.pair(SessionOptions{Timeouts: &to})
	gos := p.punching()
	if gos[0].Final {
		t.Fatal("round 1 of 2 is final")
	}
	gos2 := p.endRound(1, [2]simclient.Outcome{fired(3), fired(3)})
	if gos2[0] == nil || gos2[0].Final {
		t.Fatalf("round 2 (a rescue round may follow) %+v", gos2[0])
	}
	p.endRound(2, [2]simclient.Outcome{fired(3), fired(3)})
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonCandidateTimeout || res.Outcome != OutcomeFailed || len(res.Rounds) != 2 {
		t.Fatalf("result %+v", res)
	}
	if !res.Retry.Retryable || res.Retry.After != time.Second {
		t.Fatalf("retry %+v", res.Retry)
	}
}

// TestBudgetAudit: a side that sends more than granted × 1.1 gets half the
// grant next round; a second violation in a row is a protocol violation.
func TestBudgetAudit(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	g1 := grantOf(p, 0)
	gos := p.endRound(1, [2]simclient.Outcome{fired(uint32(g1) * 2), fired(1)})
	if gos[0] == nil {
		t.Fatal("no round 2")
	}
	if g2 := maxPackets(gos[0].Plan); g2 > g1 {
		t.Fatalf("round 2 grant %d after violating %d", g2, g1)
	}
	g2 := grantOf(p, 0)
	p.windowEnd(1, 2, fired(1))
	p.windowEnd(0, 2, fired(uint32(g2)*2+1))
	if a := expectAbort(t, p.cl[1]); a.Reason != protocol.ReasonProtocolViolation || a.Detail != detailBudgetViolation {
		t.Fatalf("abort %+v", a)
	}
	res := r.wait(p.s)
	if res.Detail != detailBudgetViolation || res.Counters.BudgetViolation != 2 || res.FailedRole != protocol.RoleInitiator {
		t.Fatalf("result %+v", res)
	}
}

func grantOf(p *pair, r int) int {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()
	return p.s.st.rounds.cur.granted[r]
}

func maxPackets(rp *protocol.RoundPlan) int {
	n := 0
	for _, s := range rp.Sides {
		n += int(s.MaxPackets)
	}
	return n
}

// TestUDPBlockedBoth: both sides reporting udp_blocked end the punch at once.
func TestUDPBlockedBoth(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	for i := range 2 {
		rr := simclient.RoundEnd(p.s.ID(), roleOf(i), 1, protocol.RoundFatal)
		rr.Reason = protocol.ReasonUDPBlocked
		send(t, p.cl[i], &rr)
	}
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonUDPBlocked || res.Outcome != OutcomeFailed || res.Retry.Retryable {
		t.Fatalf("result %+v", res)
	}
}

// TestPacketBudgetExceeded: a session budget too small for another round
// (under 60 packets left) ends the punch with packet_budget_exceeded.
func TestPacketBudgetExceeded(t *testing.T) {
	r := newRig(t)
	pol := &protocol.Policy{Budget: protocol.Budget{MaxPackets: 64}} // under 60 left after any round-1 grant
	p := r.pair(SessionOptions{Policy: pol})
	p.punching()
	p.endRound(1, [2]simclient.Outcome{fired(3), fired(3)})
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonPacketBudgetExceeded || res.Retry.After != time.Minute {
		t.Fatalf("result %+v", res)
	}
}

// TestRoundClassTable checks the reading of a round.
func TestRoundClassTable(t *testing.T) {
	rr := func(st protocol.RoundStatus, fos ...protocol.FamilyOutcome) *protocol.RoundResult {
		return &protocol.RoundResult{Status: st, Families: fos}
	}
	u4 := protocol.FamilyUDP4
	hit := protocol.FamilyOutcome{Family: u4, Hit: true}
	seen := protocol.FamilyOutcome{Family: u4, SeenFrom: []netip.AddrPort{pubI}}
	none := protocol.FamilyOutcome{Family: u4, Sent: 3}
	icmp := protocol.FamilyOutcome{Family: u4, ICMPUnreach: 50}
	blockedFatal := rr(protocol.RoundFatal, none)
	blockedFatal.Reason = protocol.ReasonUDPBlocked
	cases := []struct {
		name string
		a, b *protocol.RoundResult
		want plan.RoundClass
	}{
		{"missing", rr(protocol.RoundWindowEnd, hit), nil, plan.RoundNoReport},
		{"both hit", rr(protocol.RoundWindowEnd, hit), rr(protocol.RoundWindowEnd, hit), plan.RoundConfirmLost},
		{"both seen", rr(protocol.RoundWindowEnd, seen), rr(protocol.RoundWindowEnd, seen), plan.RoundConfirmLost},
		{"one way", rr(protocol.RoundWindowEnd, seen), rr(protocol.RoundWindowEnd, none), plan.RoundOneWay},
		{"icmp", rr(protocol.RoundWindowEnd, icmp), rr(protocol.RoundWindowEnd, none), plan.RoundBlocked},
		{"udp blocked", blockedFatal, rr(protocol.RoundWindowEnd, none), plan.RoundBlocked},
		{"nothing", rr(protocol.RoundWindowEnd, none), rr(protocol.RoundBudgetExhausted, none), plan.RoundNoContact},
	}
	for _, c := range cases {
		if got := roundClass([2]*protocol.RoundResult{c.a, c.b}); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// The attribution uses both sides' evidence.
	ev := plan.Evidence{Sent: [2]uint32{5, 5}, Fired: [2]bool{true, true}, ICMPUnreach: [2]uint16{60, 0}}
	if code, detail := engine.AttributeDetail(ev); code != protocol.ReasonCandidateTimeout || detail != "icmp_unreachable" {
		t.Fatalf("attribution %s %s", code, detail)
	}
}

// TestRoundsShareDeadline: the rounds share one handshake deadline. When a
// round ends — here at its own deadline, neither side having reported — the
// next one starts only if 700 ms + D are left before the punch deadline, and
// its window fits in what is left.
//
// The fake clock is moved exactly to an instant where the session decides
// and stays there until the decision is out: in the timer callback when too
// little is left, on the session goroutine (planning) otherwise. Moving it
// further in the same advance would race that goroutine's reading of the
// clock, and the decision would depend on the scheduling.
func TestRoundsShareDeadline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		slack time.Duration // TTLConfig.PunchSlack, which sets what is left at round 1's end
		next  bool
	}{
		{name: "enough left", next: true}, // the default 1 s slack
		{name: "too little left", slack: 300 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, func(c *Config) { c.TTL.PunchSlack = tc.slack })
			to := protocol.Timeouts{HandshakeTimeoutMs: 2000}
			p := r.pair(SessionOptions{Timeouts: &to})
			p.punching()
			end, punchEnd, d := roundTimes(p.s)
			left := punchEnd - end
			if enough := left >= minWindow+d; enough != tc.next {
				t.Fatalf("%v left at round 1's end with D %v: the case needs another round %v", left, d, tc.next)
			}
			r.clk.AdvanceTo(p.s.at(end))
			if !tc.next {
				if res := r.wait(p.s); len(res.Rounds) != 1 {
					t.Fatalf("rounds %+v", res.Rounds)
				}
				return
			}
			for i := range 2 {
				g := expect[protocol.PunchGo](t, p.cl[i])
				if g.Round != 2 || time.Duration(g.WindowMs)*time.Millisecond > left-d {
					t.Fatalf("%s: go %+v with %v left", roleOf(i), g, left)
				}
			}
			// Round 2 cannot leave room for a third one, so the session ends
			// in a timer callback and the clock can go to the punch deadline
			// at once.
			end2, _, d2 := roundTimes(p.s)
			if punchEnd-min(end2, punchEnd) >= minWindow+d2 {
				t.Fatalf("round 2 ends at %v, %v before the punch deadline", end2, punchEnd-end2)
			}
			r.clk.AdvanceTo(p.s.at(punchEnd))
			if res := r.wait(p.s); len(res.Rounds) != 2 {
				t.Fatalf("rounds %+v", res.Rounds)
			}
		})
	}
}

// roundTimes returns, on session time, the deadline of the round under way
// and the punch deadline, and the round's D.
func roundTimes(s *Session) (end, punchEnd, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.rounds.cur.deadline, s.st.rounds.punchDeadline, s.st.rounds.cur.align.d
}

// recordingPlanner is the default planner, recording what it is asked and
// what it answers.
type recordingPlanner struct {
	mu   sync.Mutex
	ins  []plan.RoundInput
	outs []plan.RoundDecision
}

func (p *recordingPlanner) Classify(in plan.ClassifyInput) plan.Classification {
	return engine.DefaultPlanner{}.Classify(in)
}

func (p *recordingPlanner) Round(in plan.RoundInput) plan.RoundDecision {
	d := engine.DefaultPlanner{}.Round(in)
	p.mu.Lock()
	p.ins, p.outs = append(p.ins, in), append(p.outs, d)
	p.mu.Unlock()
	return d
}

func (p *recordingPlanner) round(k int) (plan.RoundInput, plan.RoundDecision) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ins[k-1], p.outs[k-1]
}

// TestRoundInputEvidence: the planner gets the expected fire time on the
// registration axis, the mappings each side's peer saw while punching (at
// the fire time of their round), and the previous round's families, own
// seen_from and hits.
func TestRoundInputEvidence(t *testing.T) {
	rp := &recordingPlanner{}
	r := newRig(t, func(c *Config) { c.Planner = rp })
	p := r.pair(SessionOptions{})
	p.punching()
	in1, dec1 := rp.round(1)
	if in1.FireAt < in1.D || len(in1.Mappings[0])+len(in1.Mappings[1]) != 0 {
		t.Fatalf("round 1 input: fire_at %v, D %v, mappings %+v", in1.FireAt, in1.D, in1.Mappings)
	}
	p.s.mu.Lock()
	fire1 := p.s.st.rounds.fireAt[1] - p.s.regAt
	p.s.mu.Unlock()

	// The responder heard the initiator at pubI (peer_seen) and the
	// initiator heard the responder at pubR (round_result).
	send(t, p.cl[1], peerSeen(p, 1, 1, pubI))
	expect[protocol.Assist](t, p.cl[0])
	heard := simclient.Outcome{Family: protocol.FamilyUDP4, Sent: 3, SeenFrom: []netip.AddrPort{pubR, pubR}}
	p.endRound(1, [2]simclient.Outcome{heard, fired(3)})
	in2, _ := rp.round(2)
	want := [2][]plan.MappingSample{{{Addr: pubI, At: fire1, Round: 1}}, {{Addr: pubR, At: fire1, Round: 1}}}
	if !reflect.DeepEqual(in2.Mappings, want) {
		t.Fatalf("mappings %+v, want %+v", in2.Mappings, want)
	}
	if now := p.s.since(r.clk.Now()); in2.FireAt != now+in2.D-p.s.regAt {
		t.Fatalf("fire_at %v at %v with D %v", in2.FireAt, now, in2.D)
	}
	prev := in2.Prev[0]
	if !slices.Equal(prev.SeenFrom[0], []netip.AddrPort{pubR}) || prev.SeenFrom[1] != nil || prev.Hit != [2]bool{} {
		t.Fatalf("outcome evidence %+v", prev)
	}
	// The outcome's families are the decision's, with the mappings each
	// side made — here one Direct target from one socket each —
	// and who heard whom: the initiator heard the responder.
	got := slices.Clone(prev.Families)
	for i := range got {
		if got[i].Mapped != [2]int{1, 1} || got[i].Heard != [2]bool{true, false} {
			t.Fatalf("outcome family %+v: mapped %v, heard %v; want [1 1], [true false]", got[i], got[i].Mapped, got[i].Heard)
		}
		got[i].Mapped, got[i].Heard = [2]int{}, [2]bool{}
	}
	if len(got) == 0 || !reflect.DeepEqual(got, dec1.Families) {
		t.Fatalf("outcome families %+v, decision %+v", prev.Families, dec1.Families)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

// TestMappedAccounting: what a side mapped in a family in a round
// is its granted plan's new (socket, destination) pairs — a Direct target
// once per socket that never sent to it, minus the sockets it failed to
// bind, never a LAN target; spray ports no more than the distinct ports it
// reported — plus the peer_targets ports it was sent, the two sandwich
// probes of its fresh helper socket and a re-observation probe that found
// a new mapping. The Direct targets enter the side's ledger.
func TestMappedAccounting(t *testing.T) {
	f := protocol.FamilyUDP4
	pub := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.20:50000"), netip.MustParseAddrPort("198.51.100.20:50010")}
	lan := netip.MustParseAddrPort("192.168.7.2:4000")
	ip := pub[0].Addr()
	side := func(sockets uint16, span uint16) protocol.FamilySide {
		return protocol.FamilySide{Family: f, Role: protocol.SideBoth, Sockets: sockets, Stages: []protocol.Stage{
			{Kind: protocol.StageDirect, Targets: []netip.AddrPort{lan}, Repeats: 2},
			{Kind: protocol.StageDirect, Targets: pub, Repeats: 3},
			{Kind: protocol.StagePredict, IP: ip, Anchor: 50020, Steps: []int16{1}, Span: span},
		}}
	}
	result := func(o protocol.FamilyOutcome) *protocol.RoundResult {
		o.Family = f
		return &protocol.RoundResult{Families: []protocol.FamilyOutcome{o}}
	}
	s := &Session{}
	cur := &s.st.rounds.cur

	// Round 1: two sockets, one of which failed to bind; 9 distinct ports
	// sent (2 Direct + 7 of the 16 predicted: the side heard its peer and
	// stopped); 3 window ports pushed; sandwich; a new mapping re-observed.
	cur.plans[0].Sides = []protocol.FamilySide{side(2, 16)}
	cur.plans[0].Sides[0].Sandwich, cur.sandwich[0][0] = true, true
	cur.pushed[0][0] = 3
	cur.results[0] = result(protocol.FamilyOutcome{DistinctPorts: 9, BindFailed: 1,
		Remap: &protocol.Remap{Observer: 0, Observed: netip.MustParseAddrPort("203.0.113.9:7000"), Cookie: 5}})
	if got, want := s.mappedLocked(0, f), 2+7+3+sandwichProbes+1; got != want {
		t.Fatalf("round 1: mapped %d, want %d", got, want)
	}
	// No report from the other side: its grant counts.
	cur.plans[1].Sides = []protocol.FamilySide{side(1, 16)}
	if got := s.mappedLocked(1, f); got != 2+16 {
		t.Fatalf("round 1, no result: mapped %d, want 18", got)
	}

	// Round 2: four sockets now; the one socket that sent last round holds
	// both targets' mappings.
	s.st.rounds.cur = roundState{}
	cur.plans[0].Sides = []protocol.FamilySide{side(4, 48)}
	cur.results[0] = result(protocol.FamilyOutcome{DistinctPorts: 200})
	if got, want := s.mappedLocked(0, f), 3*2+48; got != want {
		t.Fatalf("round 2: mapped %d, want %d", got, want)
	}
	if got := s.st.rounds.directSent[0][0][pub[1]]; got != 4 {
		t.Fatalf("ledger %v", s.st.rounds.directSent[0][0])
	}
	// A reply-only side maps only what it was pushed.
	cur.plans[1].Sides = []protocol.FamilySide{{Family: f, Role: protocol.SideReplyOnly, Sockets: 1,
		Stages: []protocol.Stage{{Kind: protocol.StageReplyOnly}}}}
	cur.pushed[1][0] = 2
	if got := s.mappedLocked(1, f); got != 2 {
		t.Fatalf("reply only: mapped %d, want 2", got)
	}
}

// TestFireAtOrigin: the FireAt axis starts at natprobe's
// own registration time (Handle.Registered) when the Registry runs on the
// coordinator's clock, at the coordinator's reading around Register when it
// runs on another clock, and at the session's creation without a Registry;
// round 1's FireAt adds the summary→ready round trip, max(RTT), to now + D.
func TestFireAtOrigin(t *testing.T) {
	cases := []struct {
		name  string
		reg   func(clk *clock.Fake, arm *atomic.Bool) *natprobe.Registry
		regAt time.Duration
	}{
		{"same clock", func(clk *clock.Fake, arm *atomic.Bool) *natprobe.Registry {
			// Register reads the clock 1 ms into a call that lasts 2 ms.
			return natprobe.NewRegistry(natprobe.RegistryConfig{Clock: armedClock{clk, arm}})
		}, time.Millisecond},
		{"other clock", func(*clock.Fake, *atomic.Bool) *natprobe.Registry {
			return natprobe.NewRegistry(natprobe.RegistryConfig{}) // the system clock: meaningless on the fake one
		}, 0},
		{"relay-only", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rp := &recordingPlanner{}
			var arm atomic.Bool
			r := newRig(t, func(cfg *Config) {
				cfg.Planner = rp
				if c.reg != nil {
					cfg.Registry, cfg.NoObserver = c.reg(cfg.Clock.(*clock.Fake), &arm), false
				}
			})
			r.clk.Advance(time.Second)
			arm.Store(true)
			p := r.pair(SessionOptions{})
			if p.s.regAt != c.regAt {
				t.Fatalf("registration at %v of session time, want %v", p.s.regAt, c.regAt)
			}
			if c.reg != nil && c.name == "same clock" && !p.s.handle.Registered().Equal(p.s.epoch.Add(c.regAt)) {
				t.Fatalf("Registered %v, epoch %v", p.s.handle.Registered(), p.s.epoch)
			}
			p.summaries()
			in1, _ := rp.round(1)
			now := p.s.since(r.clk.Now())
			if want := now + in1.D + max(in1.RTT[0], in1.RTT[1]) - c.regAt; in1.FireAt != want || in1.RTT[0] == 0 {
				t.Fatalf("round 1 fire_at %v, want now %v + D %v + max RTT %v − %v", in1.FireAt, now, in1.D, in1.RTT, c.regAt)
			}
			p.s.Abort(protocol.ReasonCanceled, "")
			r.wait(p.s)
		})
	}
}

func TestRegisteredAt(t *testing.T) {
	t0 := time.Unix(1000, 0)
	t1, t2 := t0.Add(time.Millisecond), t0.Add(2*time.Millisecond)
	for _, c := range []struct{ reg, want time.Time }{{t1, t1}, {t0.Add(-time.Hour), t0}, {t2.Add(time.Hour), t2}, {t0, t0}, {t2, t2}} {
		if got := registeredAt(c.reg, t0, t2); !got.Equal(c.want) {
			t.Errorf("registeredAt(%v) = %v, want %v", c.reg, got, c.want)
		}
	}
}

// TestMappings: the mapping list keeps a mapping's first sighting and its
// newest 16, and ignores addresses without a port.
func TestMappings(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	s.mu.Lock()
	s.st.rounds.fireAt[1], s.st.rounds.fireAt[2] = time.Second, 2*time.Second
	s.addMappingLocked(0, 1, netip.AddrPort{})
	s.addMappingLocked(0, 1, mustAP("192.0.2.1:0"))
	for i := range maxMappings + 1 {
		s.addMappingLocked(0, 1, netip.AddrPortFrom(pubI.Addr(), uint16(1000+i)))
	}
	s.addMappingLocked(0, 2, netip.AddrPortFrom(pubI.Addr(), 1005))
	got := slices.Clone(s.st.rounds.mappings[0])
	s.mu.Unlock()
	if len(got) != maxMappings || got[0].Addr.Port() != 1001 || got[maxMappings-1].Addr.Port() != 1016 || got[4].At != time.Second {
		t.Fatalf("mappings %+v", got)
	}
	s.Abort(protocol.ReasonCanceled, "")
	r.wait(s)
}

// TestPushCharge: a peer_targets assist is cut to what its side may still be
// charged — two packets a target or window port within the session budget
// and the key's quota, 64 a family and round, a window narrowed around its
// middle — and charged when sent; the audit pays the packets beyond the
// grant from that credit, whichever round they were sent in.
func TestPushCharge(t *testing.T) {
	_, s := testSession(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	st.rounds.cur = roundState{n: 1, class: protocol.BudgetLight}
	st.audit.granted[1] = int(s.budget.MaxPackets) - 41 // room for 20 targets
	targets := []netip.AddrPort{netip.AddrPortFrom(pubI.Addr(), 7), netip.AddrPortFrom(pubI.Addr(), 8),
		netip.AddrPortFrom(pubI.Addr(), 9), netip.AddrPortFrom(pubI.Addr(), 10)}
	a := protocol.Assist{Family: protocol.FamilyUDP4, Targets: slices.Clone(targets),
		Window: &protocol.PortWindow{IP: pubI.Addr(), Lo: 1000, Hi: 1063}}
	if n := s.trimPushLocked(1, &a, 0); n != 20 || len(a.Targets) != 4 || a.Window.Lo != 1024 || a.Window.Hi != 1039 {
		t.Fatalf("trimmed to %d: %+v %+v", n, a.Targets, a.Window)
	}
	s.chargePushLocked(1, 0, 20, 0)
	if st.audit.granted[1] != int(s.budget.MaxPackets)-1 || st.audit.credit[1] != 40 || st.rounds.cur.pushed[1][0] != 20 || st.rounds.recentPorts[1][1] != 20 {
		t.Fatalf("charge: granted %d credit %v pushed %v ports %v", st.audit.granted[1], st.audit.credit, st.rounds.cur.pushed, st.rounds.recentPorts[1])
	}
	a = protocol.Assist{Family: protocol.FamilyUDP4, Targets: slices.Clone(targets), Window: &protocol.PortWindow{IP: pubI.Addr(), Lo: 1, Hi: 2}}
	if n := s.trimPushLocked(1, &a, 0); n != 0 || len(a.Targets) != 0 || a.Window != nil {
		t.Fatalf("no budget left: %d %+v", n, a)
	}
	st.audit.granted[1] = 0
	st.rounds.cur.pushed[0][0] = protocol.MaxPushPerRound - 3
	a = protocol.Assist{Family: protocol.FamilyUDP4, Targets: slices.Clone(targets[:2]), Window: &protocol.PortWindow{IP: pubR.Addr(), Lo: 5, Hi: 9}}
	if n := s.trimPushLocked(0, &a, 0); n != 3 || len(a.Targets) != 2 || a.Window.Lo != 7 || a.Window.Hi != 7 {
		t.Fatalf("the client's cap: %d %+v %+v", n, a.Targets, a.Window)
	}

	// The audit: 10 granted, 40 credit. Sending 30 pays 20 from the credit;
	// sending 60 more than the credit covers is a strike.
	st.rounds.cur.granted[1] = 10
	if term := s.auditLocked(1, &protocol.RoundResult{Families: []protocol.FamilyOutcome{{Sent: 30}}}); term != nil ||
		st.audit.credit[1] != 20 || st.audit.strikes[1] != 0 {
		t.Fatalf("paid audit: %v credit %v strikes %v", term, st.audit.credit, st.audit.strikes)
	}
	if term := s.auditLocked(1, &protocol.RoundResult{Families: []protocol.FamilyOutcome{{Sent: 60}}}); term != nil ||
		st.audit.credit[1] != 0 || st.audit.strikes[1] != 1 || !st.audit.halve[1] {
		t.Fatalf("over the credit: %v credit %v strikes %v", term, st.audit.credit, st.audit.strikes)
	}
}

// TestNoAdmissibleTarget: a round in which both clients sent nothing and
// refused targets ends the session at once with candidate_timeout
// (no_admissible_target); one side that sent, or no refusal, keeps the
// ladder going; NoEarlyAbort keeps the end for the punching deadline.
func TestNoAdmissibleTarget(t *testing.T) {
	refused := simclient.Outcome{Family: protocol.FamilyUDP4, Rejected: 3}
	t.Run("both refused", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		if gos := p.endRound(1, [2]simclient.Outcome{refused, refused}); gos[0] != nil || gos[1] != nil {
			t.Fatal("a round followed")
		}
		if res := r.wait(p.s); res.Reason != protocol.ReasonCandidateTimeout || res.Detail != detailNoAdmissible || len(res.Rounds) != 1 {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("one side sent", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		sent := refused
		sent.Sent = 4
		if gos := p.endRound(1, [2]simclient.Outcome{refused, sent}); gos[0] == nil || gos[0].Round != 2 {
			t.Fatal("no second round")
		}
		if noAdmissibleTarget([2]*protocol.RoundResult{{Families: []protocol.FamilyOutcome{{}}}, {Families: []protocol.FamilyOutcome{{}}}}) {
			t.Fatal("nothing sent and nothing refused is not the rule")
		}
		p.s.Abort(protocol.ReasonCanceled, "")
		r.wait(p.s)
	})
	t.Run("NoEarlyAbort", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(ablated(ablation.Set{NoEarlyAbort: true}))
		p.punching()
		for i := range 2 {
			p.windowEnd(i, 1, refused)
		}
		testkit.WaitFor(t, "deferred", func() bool {
			p.s.mu.Lock()
			defer p.s.mu.Unlock()
			return p.s.st.deferred != nil
		})
		if p.s.Snapshot().State == StateClosed {
			t.Fatal("ended early")
		}
		r.clk.Advance(time.Minute)
		if res := r.wait(p.s); res.Reason != protocol.ReasonCandidateTimeout || res.Detail != detailNoAdmissible {
			t.Fatalf("result %+v", res)
		}
	})
}

// TestGoneAtRoundEnd: a side whose control link is lost while punching ends
// the session with control_interrupted once the round is over, without a
// next round.
func TestGoneAtRoundEnd(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	_ = p.cl[1].Close()
	testkit.WaitFor(t, "gone", func() bool {
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		return p.s.st.gone[1]
	})
	p.windowEnd(0, 1, fired(5))
	r.clk.Advance(10 * time.Second)
	if res := r.wait(p.s); res.Reason != protocol.ReasonControlInterrupted || res.FailedRole != protocol.RoleResponder {
		t.Fatalf("result %+v", res)
	}
}

// armedClock is clk, except that once armed its next Now lasts 2 ms and
// reads the clock 1 ms into it.
type armedClock struct {
	*clock.Fake
	arm *atomic.Bool
}

func (c armedClock) Now() time.Time {
	now := c.Fake.Now()
	if c.arm.CompareAndSwap(true, false) {
		c.Fake.Advance(2 * time.Millisecond)
		return now.Add(time.Millisecond)
	}
	return now
}

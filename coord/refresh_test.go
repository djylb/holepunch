package coord

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/internal/nat"
	engine "github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// The anchor refresh before a round.

// TestRefreshEvents: the two probes of each wanted side and family complete
// the refresh and become the planner's input, on the FireAt axis; a probe
// of another round, side or family, or one that came after the wait, is
// ignored; a family with one probe is input too, one with its two
// on different IPs is not.
func TestRefreshEvents(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	epoch := s.epoch
	ip := netip.MustParseAddr("198.51.100.20")
	ev := func(role protocol.Role, round, phase uint8, port uint16, after time.Duration) nat.SandwichEvent {
		return nat.SandwichEvent{Role: role, Round: round, Phase: phase, Observed: netip.AddrPortFrom(ip, port), At: epoch.Add(after)}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	s.regAt = 100 * time.Millisecond
	st.refresh = refreshState{pending: true, k: 2, until: time.Hour, cap: time.Hour}
	st.refresh.want[1][0] = true
	st.refresh.asked = st.refresh.want
	s.refreshEventLocked(ev(protocol.RoleResponder, 3, nat.RefreshFirst, 1, time.Second), 0) // another round
	s.refreshEventLocked(ev(protocol.RoleInitiator, 2, nat.RefreshFirst, 1, time.Second), 0) // not asked
	s.refreshEventLocked(ev(protocol.RoleResponder, 2, nat.RefreshFirst, 40010, time.Second), 0)
	if !st.refresh.pending || st.work.refreshed {
		t.Fatal("one probe completed the refresh")
	}
	s.refreshEventLocked(ev(protocol.RoleResponder, 2, nat.RefreshSecond, 40013, time.Second+100*time.Millisecond), 0)
	if st.refresh.pending || !st.refresh.ready || !st.work.refreshed {
		t.Fatal("both probes did not complete the refresh")
	}
	in := s.refreshInputLocked()
	if len(in[0]) != 0 || len(in[1]) != 1 {
		t.Fatalf("input %+v", in)
	}
	got := in[1][0]
	if got.Family != protocol.FamilyUDP4 || got.First.Port() != 40010 || got.Second.Port() != 40013 ||
		got.FirstAt != 900*time.Millisecond || got.SecondAt != time.Second {
		t.Fatalf("refresh %+v", got)
	}
	// After the wait a late probe changes nothing.
	s.refreshEventLocked(ev(protocol.RoleResponder, 2, nat.RefreshSecond, 50000, 2*time.Second), 0)
	if s.refreshInputLocked()[1][0].Second.Port() != 40013 {
		t.Fatal("a probe after the wait was taken")
	}
	// Half a refresh is input; one split over two IPs is not.
	st.refresh = refreshState{pending: true, k: 2, until: time.Hour, cap: time.Hour}
	st.refresh.want[0][0] = true
	st.refresh.got[0][0][0] = refreshProbe{addr: netip.AddrPortFrom(ip, 1), at: time.Second}
	if in := s.refreshInputLocked(); len(in[0]) != 1 || in[0][0].First.Port() != 1 || in[0][0].Second.IsValid() ||
		in[0][0].Family != protocol.FamilyUDP4 {
		t.Fatalf("half a refresh: %+v", in)
	}
	st.refresh.got[0][0][1] = refreshProbe{addr: netip.MustParseAddrPort("203.0.113.9:2")}
	if in := s.refreshInputLocked(); len(in[0]) != 0 {
		t.Fatalf("a refresh over two IPs: %+v", in)
	}
}

// TestRefreshWaitBound: the wait for a side's family ends with its second
// probe, or refreshGap plus one and a half UDP round trips after its first;
// a family without a probe holds it until the cap.
func TestRefreshWaitBound(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	epoch := s.epoch
	ip := netip.MustParseAddr("198.51.100.20")
	ev := func(role protocol.Role, phase uint8, port uint16, after time.Duration) nat.SandwichEvent {
		return nat.SandwichEvent{Role: role, Round: 2, Phase: phase, Observed: netip.AddrPortFrom(ip, port), At: epoch.Add(after)}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	// timer runs the session timer's work at now, which takes the lock.
	timer := func(now time.Duration) {
		s.mu.Unlock()
		defer s.mu.Lock()
		_ = s.timerLocked(now)
	}
	st.adm.pair.ProbeRTTMs = map[protocol.Role]uint32{protocol.RoleInitiator: 40, protocol.RoleResponder: 80}
	ask := func(sides ...int) {
		st.refresh = refreshState{pending: true, k: 2, until: 5 * time.Second, cap: 5 * time.Second}
		for _, r := range sides {
			st.refresh.want[r][0] = true
		}
		st.work.refreshed = false
	}

	// The initiator's first probe at 1 s: the wait ends at 1 s + 60 ms + 60 ms.
	ask(0)
	s.refreshEventLocked(ev(protocol.RoleInitiator, nat.RefreshFirst, 40010, time.Second), time.Second)
	if want := time.Second + refreshGap + 60*time.Millisecond; !st.refresh.pending || st.refresh.until != want {
		t.Fatalf("after the first probe: pending %v until %v, want %v", st.refresh.pending, st.refresh.until, want)
	}
	timer(st.refresh.until)
	if st.refresh.pending || !st.work.refreshed {
		t.Fatal("the bound after the first probe did not end the wait")
	}
	if in := s.refreshInputLocked(); len(in[0]) != 1 || in[0][0].First.Port() != 40010 || in[0][0].Second.IsValid() {
		t.Fatalf("input %+v, want the first probe alone", in)
	}

	// Both sides asked: the responder sent nothing yet, so the cap holds.
	ask(0, 1)
	s.refreshEventLocked(ev(protocol.RoleInitiator, nat.RefreshFirst, 40010, time.Second), time.Second)
	s.refreshEventLocked(ev(protocol.RoleInitiator, nat.RefreshSecond, 40012, time.Second+refreshGap), time.Second+refreshGap)
	if !st.refresh.pending || st.refresh.until != 5*time.Second {
		t.Fatalf("one side done: pending %v until %v, want the cap", st.refresh.pending, st.refresh.until)
	}
	// The responder's second probe alone ends its wait: it is the newest point.
	s.refreshEventLocked(ev(protocol.RoleResponder, nat.RefreshSecond, 50013, 2*time.Second), 2*time.Second)
	if st.refresh.pending {
		t.Fatal("every side has its newest probe and the wait goes on")
	}

	// Nothing comes: the cap ends the wait with no input.
	ask(1)
	timer(5 * time.Second)
	if st.refresh.pending || len(s.refreshInputLocked()[1]) != 0 {
		t.Fatal("the cap did not end an empty wait")
	}
}

// TestRefreshNotAsked: no registration means no refresh; nothing is sent
// and the round goes on.
func TestRefreshNotAsked(t *testing.T) {
	_, s := testSession(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	d := decision{ok: true}
	d.dec.Final = true // a final round may refresh, but not without a registration
	if s.beginRefreshLocked(planTicket{k: 2, gen: s.st.plan.gen}, d, plan.ClassifyInput{}, plan.RoundInput{}, 0) || s.st.refresh.pending || s.st.ctr.Refreshes != 0 {
		t.Fatal("refresh without a registration")
	}
}

// TestRefreshNoRefresh: a paired SEQ × SEQ round asks both sides for a
// refresh, and the NoRefresh ablation asks for none.
func TestRefreshNoRefresh(t *testing.T) {
	u4 := protocol.FamilyUDP4
	view := func(pub netip.AddrPort) protocol.PeerView {
		return protocol.PeerView{Families: []protocol.FamilyView{{Family: u4, Traits: simclient.SeqTraits(pub),
			Endpoints: []protocol.Endpoint{{Addr: pub, Source: protocol.EndpointServer, Verified: true}}}}}
	}
	for _, abl := range []ablation.Set{{}, {NoRefresh: true}} {
		r := newRig(t, withRegistry(natprobe.NewRegistry(natprobe.RegistryConfig{})))
		p := r.pair(ablated(abl))
		var pl engine.DefaultPlanner
		views := [2]protocol.PeerView{view(pubI), view(pubR)}
		policy := protocol.Policy{Budget: protocol.DefaultBudget()}
		cl := pl.Classify(plan.ClassifyInput{Initiator: views[0], Responder: views[1], Policy: policy})
		in := plan.RoundInput{Round: 1, Class: cl, Views: views, Policy: policy, Remaining: 10 * time.Second, BudgetLeft: [2]int{-1, -1},
			MaxRounds: 3, HandshakeMs: 10000}
		d := decision{ok: true, dec: pl.Round(in), cls: cl, planner: pl}
		if d.dec.Stop != "" {
			t.Fatalf("round 1 stops: %s", d.dec.Stop)
		}
		p.s.mu.Lock()
		asked := p.s.beginRefreshLocked(planTicket{k: 1, gen: p.s.st.plan.gen}, d, plan.ClassifyInput{}, in, 0)
		refreshes := p.s.st.ctr.Refreshes
		p.s.mu.Unlock()
		if asked == abl.NoRefresh || asked && refreshes != 2 {
			t.Errorf("%s: asked %v (%d refreshes)", abl, asked, refreshes)
		}
		p.s.Abort(protocol.ReasonCanceled, "")
		r.wait(p.s)
	}
}

// TestRefreshRound1Go: round 1's go waits for its anchor refresh
// even when both readies are in; the refresh's end sends it, carrying the
// plan only to the side whose predict stage was re-aimed — the anchor moved,
// the span cut, never grown, MaxPackets following.
func TestRefreshRound1Go(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	sums := p.summaries()
	predict := protocol.Stage{Kind: protocol.StagePredict, IP: pubR.Addr(), Anchor: 40000, Steps: []int16{1}, Span: 16, Pair: true}
	p.s.mu.Lock()
	st := &p.s.st
	side := &st.rounds.cur.plans[0].Sides[0]
	side.Stages = append(side.Stages, predict)
	side.MaxPackets += 16
	before := st.rounds.cur.plans[0]
	st.refresh = refreshState{pending: true, k: 1, gen: st.plan.gen, until: time.Hour, cap: time.Hour}
	p.s.mu.Unlock()

	send(t, p.cl[0], simclient.Ready(sums[0], protocol.RoleInitiator, 1))
	send(t, p.cl[1], simclient.Ready(sums[1], protocol.RoleResponder, 1))
	testkit.WaitFor(t, "both readies taken", func() bool {
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		return st.ready[0] && st.ready[1]
	})
	p.s.mu.Lock()
	if st.state != StateSummarized {
		p.s.mu.Unlock()
		t.Fatalf("state %s: the go left before the refresh", st.state)
	}
	re := st.rounds.cur.plans
	for r := range re {
		re[r].Sides = slices.Clone(re[r].Sides)
	}
	re[0].Sides[0].Stages = slices.Clone(re[0].Sides[0].Stages)
	n := len(re[0].Sides[0].Stages) - 1
	re[0].Sides[0].Stages[n].Anchor, re[0].Sides[0].Stages[n].Span = 40007, 24 // the span would grow: cut to 16
	d := decision{ok: true, dec: plan.RoundDecision{Sides: [2][]protocol.FamilySide{re[0].Sides, re[1].Sides}}}
	st.refresh.pending = false
	fx := p.s.reanchorRound1Locked(d, true, r.clk.Now())
	p.s.mu.Unlock()
	p.s.apply(fx)

	g0, g1 := expect[protocol.PunchGo](t, p.cl[0]), expect[protocol.PunchGo](t, p.cl[1])
	if g1.Plan != nil {
		t.Fatalf("the responder's plan did not change, yet its go carries one")
	}
	if g0.Plan == nil {
		t.Fatal("the initiator's go carries no anchor update")
	}
	if err := before.CheckAnchorUpdate(*g0.Plan); err != nil {
		t.Fatalf("the update is not an anchor update: %v", err)
	}
	if got := g0.Plan.Sides[0].Stages[n]; got.Anchor != 40007 || got.Span != 16 {
		t.Fatalf("predict stage %+v, want anchor 40007 span 16", got)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

// TestReanchored: only predict stages at the same position of the same
// family take the planner's new anchor, their spans never grow; a family
// whose stages differ keeps its plan.
func TestReanchored(t *testing.T) {
	f4, f6 := protocol.FamilyUDP4, protocol.FamilyUDP6
	direct := protocol.Stage{Kind: protocol.StageDirect, Targets: []netip.AddrPort{pubR}}
	predict := func(anchor, span uint16) protocol.Stage {
		return protocol.Stage{Kind: protocol.StagePredict, IP: pubR.Addr(), Anchor: anchor, Steps: []int16{1}, Span: span}
	}
	rp := protocol.RoundPlan{Round: 1, Sides: []protocol.FamilySide{
		{Family: f4, Sockets: 1, MaxPackets: 19, MaxDistinctPorts: 19, Stages: []protocol.Stage{direct, predict(40000, 16)}},
		{Family: f6, Sockets: 1, MaxPackets: 19, MaxDistinctPorts: 19, Stages: []protocol.Stage{direct, predict(50000, 16)}},
	}}
	sides := []protocol.FamilySide{
		{Family: f6, Stages: []protocol.Stage{predict(50009, 16)}}, // another structure: kept
		{Family: f4, Stages: []protocol.Stage{direct, predict(40005, 12)}},
	}
	got, ok := reanchored(rp, sides)
	if !ok {
		t.Fatal("nothing re-aimed")
	}
	if st := got.Sides[0].Stages[1]; st.Anchor != 40005 || st.Span != 12 || got.Sides[0].MaxPackets != 15 {
		t.Fatalf("udp4 %+v (max_packets %d)", st, got.Sides[0].MaxPackets)
	}
	if st := got.Sides[1].Stages[1]; st.Anchor != 50000 || st.Span != 16 {
		t.Fatalf("udp6 changed: %+v", st)
	}
	if rp.Sides[0].Stages[1].Anchor != 40000 {
		t.Fatal("the plan was written")
	}
	if _, ok := reanchored(rp, []protocol.FamilySide{{Family: f4, Stages: []protocol.Stage{direct, predict(40000, 20)}}}); ok {
		t.Fatal("a longer span alone changed the plan")
	}
}

// TestRefreshMapped: the refresh's two new sockets count in the Mapped of
// the round they were asked for.
func TestRefreshMapped(t *testing.T) {
	f := protocol.FamilyUDP4
	s := &Session{}
	cur := &s.st.rounds.cur
	cur.n = 2
	cur.plans[1].Sides = []protocol.FamilySide{{Family: f, Role: protocol.SideReplyOnly, Sockets: 1, Stages: []protocol.Stage{{Kind: protocol.StageReplyOnly}}}}
	s.st.refresh = refreshState{k: 2}
	s.st.refresh.asked[1][0] = true
	if got := s.mappedLocked(1, f); got != refreshProbes {
		t.Fatalf("mapped %d, want %d", got, refreshProbes)
	}
	s.st.refresh.k = 1
	if got := s.mappedLocked(1, f); got != 0 {
		t.Fatalf("an earlier round's refresh counted: %d", got)
	}
}

// TestRefreshKeepsPlannerSwitch: a planner that panicked deciding a round
// stays replaced while the round waits for its anchor refresh, which plans
// it again on the default planner and its classification; a panic while
// planning round 1 again replaces it as well.
func TestRefreshKeepsPlannerSwitch(t *testing.T) {
	u4 := protocol.FamilyUDP4
	view := func(pub netip.AddrPort) protocol.PeerView {
		return protocol.PeerView{Families: []protocol.FamilyView{{Family: u4, Traits: simclient.SeqTraits(pub),
			Endpoints: []protocol.Endpoint{{Addr: pub, Source: protocol.EndpointServer, Verified: true}}}}}
	}
	r := newRig(t, withRegistry(natprobe.NewRegistry(natprobe.RegistryConfig{})))
	p := r.pair(SessionOptions{})
	var def engine.DefaultPlanner
	views := [2]protocol.PeerView{view(pubI), view(pubR)}
	policy := protocol.Policy{Budget: protocol.DefaultBudget()}
	cl := def.Classify(plan.ClassifyInput{Initiator: views[0], Responder: views[1], Policy: policy})
	in := plan.RoundInput{Round: 1, Class: cl, Views: views, Policy: policy, Remaining: 10 * time.Second, BudgetLeft: [2]int{-1, -1},
		MaxRounds: 3, HandshakeMs: 10000}
	switched := decision{ok: true, switched: true, planner: def, cls: cl, dec: def.Round(in)}
	isDefault := func(pl plan.Planner) bool { _, ok := pl.(engine.DefaultPlanner); return ok }

	p.s.mu.Lock()
	defer p.s.mu.Unlock()
	st := &p.s.st
	st.plan.planner = panicPlanner{where: "round"}
	if !p.s.beginRefreshLocked(planTicket{k: 1, gen: st.plan.gen}, switched, plan.ClassifyInput{}, in, 0) {
		t.Fatal("no refresh asked")
	}
	if !isDefault(st.plan.planner) || !isDefault(st.refresh.p) || !slices.Equal(st.plan.cls.Ladder, cl.Ladder) {
		t.Fatalf("planner %T, refresh planner %T", st.plan.planner, st.refresh.p)
	}

	st.plan.planner, st.state = panicPlanner{where: "round"}, StateSummarized
	p.s.reanchorRound1Locked(switched, true, r.clk.Now())
	if !isDefault(st.plan.planner) {
		t.Fatalf("planner %T after round 1 was planned again by the default one", st.plan.planner)
	}
}

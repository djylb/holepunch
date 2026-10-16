package holepunch

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// silentPeer is the verified endpoint of a peer that never answers.
const silentPeer = "203.0.113.99:4000"

// soloRound runs one client to the round_result of its first round: the
// server sends policy pol, a direct first round towards silentPeer edited
// by edit, and the go; during runs right after the go and may read the link
// as long as it hands back the round_result it consumed (nil otherwise).
func soloRound(t *testing.T, pol *protocol.Policy, tweak func(*Options), edit func(*protocol.RoundPlan),
	during func(so *solo) *protocol.RoundResult) (*solo, protocol.ProbeReport, *protocol.RoundResult) {
	t.Helper()
	w := newWorld(t)
	so := newSolo(t, w, nil, tweak)
	to := testTimeouts()
	to.GoWaitMs = 500
	so.startWith(to, pol)
	rep, self := so.report()
	peer := fakePeer(silentPeer)
	r1 := directPlan(1, so.role, roleViews(so.role, self, peer))
	if edit != nil {
		edit(&r1)
	}
	so.link.send(protocol.ProbeSummary{
		SessionID: so.s.sid, Self: self, Peer: peer,
		Pair:      protocol.PairFacts{SharedFamilies: []protocol.Family{protocol.FamilyUDP4}},
		Transport: protocol.TransportPick{Mode: "quic"}, Timeouts: to,
		Plan: protocol.PlanSpec{ID: "p", PairClass: "test", RoundsMax: 3, Budget: protocol.DefaultBudget(), Round1: r1},
	})
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, DelayMs: 5, WindowMs: r1.WindowMs})
	var rr *protocol.RoundResult
	if during != nil {
		rr = during(so)
	}
	if rr == nil {
		m, ok := so.link.next(5*time.Second, protocol.MsgRoundResult)
		if !ok {
			t.Fatal("no round_result")
		}
		rr = m.(*protocol.RoundResult)
	}
	return so, rep, rr
}

// pushTargets sends the client a peer_targets assist of round 1.
func pushTargets(so *solo, targets []string, win *protocol.PortWindow) {
	a := protocol.Assist{SessionID: so.s.sid, From: protocol.RoleServer, Kind: protocol.AssistPeerTargets, Round: 1,
		Family: protocol.FamilyUDP4, Source: protocol.TargetsInject, Window: win}
	for _, s := range targets {
		a.Targets = append(a.Targets, netip.MustParseAddrPort(s))
	}
	so.link.send(a)
}

// peerWindow is a window of ports lo..hi on the silent peer's IP.
func peerWindow(lo, hi uint16) *protocol.PortWindow {
	return &protocol.PortWindow{IP: netip.MustParseAddrPort(silentPeer).Addr(), Lo: lo, Hi: hi}
}

// exactGrant makes the first round's grant exactly what its one direct
// target expands to: repeats packets to one port.
func exactGrant(repeats uint8) func(*protocol.RoundPlan) {
	return func(r *protocol.RoundPlan) {
		r.Sides[0].Stages[0].Repeats = repeats
		r.Sides[0].MaxPackets = uint32(repeats)
		r.Sides[0].MaxDistinctPorts = 1
	}
}

// Pushed targets do not spend the plan's grant: the plan sends all it was
// granted, every pushed target and window port two more packets, and the
// round reports no budget_hit. The window's adjacent ports wait for
// one another under the run guard; the Direct repeats, which run longest,
// let the last of them out.
func TestPeerTargetsOwnQuota(t *testing.T) {
	t.Parallel()
	_, _, rr := soloRound(t, nil, nil, exactGrant(6), func(so *solo) *protocol.RoundResult {
		pushTargets(so, []string{"203.0.113.99:4011", "203.0.113.99:4022", "203.0.113.99:4033"}, peerWindow(5000, 5004))
		return nil
	})
	f := rr.Families[0]
	if rr.Status != protocol.RoundWindowEnd || f.BudgetHit || f.Sent != 6+8*targetPackets {
		t.Fatalf("round_result %+v family %+v", rr, f)
	}
}

// A plan cut short by its grant is budget_hit, and targets pushed after that
// are still sent in the round.
func TestPeerTargetsAfterPlanCut(t *testing.T) {
	t.Parallel()
	_, _, rr := soloRound(t, nil, nil, func(r *protocol.RoundPlan) {
		exactGrant(6)(r)
		r.Sides[0].MaxPackets = 3
	}, func(so *solo) *protocol.RoundResult {
		for {
			m, ok := so.link.next(5*time.Second, protocol.MsgProgress, protocol.MsgRoundResult)
			if !ok {
				t.Fatal("no budget_exhausted progress")
			}
			if rr, ok := m.(*protocol.RoundResult); ok {
				t.Fatalf("round ended before the plan was cut: %+v", rr)
			}
			if m.(*protocol.Progress).Stage == stageBudgetExhausted {
				break
			}
		}
		pushTargets(so, []string{"203.0.113.99:4011", "203.0.113.99:4022"}, nil)
		return nil
	})
	f := rr.Families[0]
	if rr.Status != protocol.RoundBudgetExhausted || !f.BudgetHit || f.Sent != 3+2*targetPackets {
		t.Fatalf("round_result %+v family %+v", rr, f)
	}
}

// Pushed targets get only what the class ceiling leaves above the round's
// grants: light allows 150 packets, the grant is 146, so two targets fit.
func TestPeerTargetsClassCeiling(t *testing.T) {
	t.Parallel()
	_, _, rr := soloRound(t, nil, nil, func(r *protocol.RoundPlan) {
		exactGrant(4)(r)
		r.Budget = protocol.BudgetLight
		r.Sides[0].MaxPackets = 146
	}, func(so *solo) *protocol.RoundResult {
		pushTargets(so, []string{"203.0.113.99:4011", "203.0.113.99:4022", "203.0.113.99:4033", "203.0.113.99:4044"}, nil)
		return nil
	})
	if f := rr.Families[0]; f.Sent != 4+4 || f.BudgetHit {
		t.Fatalf("family %+v", f)
	}
}

// At most maxRoundExtras pushed targets a family and round; the rest are
// budget drops.
func TestExtraItemsCap(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	fs := rt.fam(protocol.FamilyUDP4)
	fr := &familyRound{rt: rt, w: &worker{fam: protocol.FamilyUDP4, fs: fs}, socks: []*udpSock{s}}
	var targets []extraTarget
	for p := range maxRoundExtras + 6 {
		targets = append(targets, extraTarget{to: netipAP("198.51.100.7", 2000+p), kind: candidate.KindTargets})
	}
	items := fr.extraItems(targets, rt.clk.Now())
	if len(items) != maxRoundExtras*targetPackets || fs.cnt.drops[dropBudget].Load() != 6 {
		t.Fatalf("%d items, %d drops", len(items), fs.cnt.drops[dropBudget].Load())
	}
	for _, it := range items {
		if it.quota != quotaTargets || it.sock != s || it.hops != 0 {
			t.Fatalf("item %+v", it)
		}
	}
	if more := fr.extraItems(targets[:1], rt.clk.Now()); len(more) != 0 || fs.cnt.drops[dropBudget].Load() != 7 {
		t.Fatalf("past the cap: %d items", len(more))
	}
}

// A batch's window ports leave after its explicit targets, in the
// order of the round's spray seed — per IP, each IP on its own sub-stream —
// not Lo..Hi; another seed gives another order. Beyond the quota the batch
// loses window ports, drawn by that order, before any explicit target.
func TestWindowPortsScattered(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	fs := rt.fam(protocol.FamilyUDP4)
	newRound := func(seed byte) *familyRound {
		return &familyRound{rt: rt, w: &worker{fam: protocol.FamilyUDP4, fs: fs}, socks: []*udpSock{s}, seed: [8]byte{seed, 1, 2, 3}}
	}
	explicit := []netip.AddrPort{netipAP("198.51.100.7", 4011), netipAP("198.51.100.7", 4022)}
	var window, other []uint16
	batch := []extraTarget{{to: explicit[0], kind: candidate.KindTargets}}
	for p := uint16(5000); p < 5016; p++ {
		window = append(window, p)
		batch = append(batch, extraTarget{to: netip.AddrPortFrom(explicit[0].Addr(), p), kind: candidate.KindTargets, window: true})
	}
	batch = append(batch, extraTarget{to: explicit[1], kind: candidate.KindTargets})
	for p := uint16(6000); p < 6004; p++ {
		other = append(other, p)
		batch = append(batch, extraTarget{to: netipAP("198.51.100.8", int(p)), kind: candidate.KindTargets, window: true})
	}
	// firstOrder is the order of the batch's first packets: all due at once.
	firstOrder := func(items []sendItem) []netip.AddrPort {
		var out []netip.AddrPort
		for _, it := range items {
			if it.due.Equal(items[0].due) {
				out = append(out, it.to)
			}
		}
		return out
	}
	fr := newRound(1)
	got := firstOrder(fr.extraItems(batch, rt.clk.Now()))
	want := slices.Clone(explicit)
	for _, p := range plan.ScatterPorts(fr.seed, 0, window) {
		want = append(want, netip.AddrPortFrom(explicit[0].Addr(), p))
	}
	for _, p := range plan.ScatterPorts(fr.seed, 1, other) {
		want = append(want, netipAP("198.51.100.8", int(p)))
	}
	if !slices.Equal(got, want) {
		t.Fatalf("first packets %v\nwant %v", got, want)
	}
	var ports []uint16
	for _, a := range got[2 : 2+len(window)] {
		ports = append(ports, a.Port())
	}
	if slices.Equal(ports, window) || plan.MaxConsecutiveRun(ports) > 3 {
		t.Fatalf("window order %v", ports)
	}
	if again := firstOrder(newRound(2).extraItems(batch, rt.clk.Now())); slices.Equal(again, got) {
		t.Fatal("another spray seed, the same order")
	}

	// Four places left in the round: the explicit targets and the first two
	// window ports of the scattered order; the other 18 are budget drops.
	fr = newRound(1)
	fr.extras.Store(maxRoundExtras - 4)
	drops := fs.cnt.drops[dropBudget].Load()
	got = firstOrder(fr.extraItems(batch, rt.clk.Now()))
	first := plan.ScatterPorts(fr.seed, maxRoundExtras-4, window)[:2]
	want = []netip.AddrPort{explicit[0], explicit[1], netip.AddrPortFrom(explicit[0].Addr(), first[0]), netip.AddrPortFrom(explicit[0].Addr(), first[1])}
	if !slices.Equal(got, want) || fs.cnt.drops[dropBudget].Load()-drops != int64(len(batch)-4) {
		t.Fatalf("over the quota: %v, want %v", got, want)
	}
}

// On the wire, a 12-port window pushed into a running round leaves
// whole, two packets a port, and the run guard keeps every run within three
// (with the Direct target, 13 of the light class's 16 distinct ports).
func TestPeerTargetsWindowOnWire(t *testing.T) {
	t.Parallel()
	so, _, rr := soloRound(t, nil, nil, exactGrant(6), func(so *solo) *protocol.RoundResult {
		pushTargets(so, nil, peerWindow(5000, 5011))
		return nil
	})
	if f := rr.Families[0]; f.Sent != 6+12*targetPackets || f.BudgetHit {
		t.Fatalf("family %+v", f)
	}
	sent := map[uint16]int{}
	for _, p := range sentPorts(t, so.w.n, so.host)[netip.MustParseAddrPort(silentPeer).Addr()] {
		sent[p]++
	}
	for p := uint16(5000); p <= 5011; p++ {
		if sent[p] != targetPackets {
			t.Fatalf("window port %d sent %d times: %v", p, sent[p], sent)
		}
	}
	if st := so.host.Stats(); st.MaxConsecutiveRun > maxAnswerRun {
		t.Fatalf("run of %d consecutive ports", st.MaxConsecutiveRun)
	}
}

// Pushed targets and window ports are candidates of kind targets
// (cand_kind=targets); an upstream-LAN candidate ranks with the LAN
// ones until the hairpin self-test succeeded, then as a pushed target.
func TestPeerTargetsKinds(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	pub := netip.MustParseAddr("198.51.100.7")
	w := &worker{fam: protocol.FamilyUDP4, fs: rt.fam(protocol.FamilyUDP4), samePublic: true,
		verified: map[netip.Addr]bool{pub: true}, endpoints: map[netip.AddrPort]bool{}, lan: map[netip.Addr]bool{},
		reported: map[netip.Addr]bool{}}
	rt.fam(protocol.FamilyUDP4).worker = w
	a := protocol.Assist{Kind: protocol.AssistPeerTargets, Family: protocol.FamilyUDP4, Source: protocol.TargetsPortmap,
		Targets: []netip.AddrPort{netipAP("198.51.100.7", 5000), netipAP("100.64.1.2", 6000), netipAP("192.0.2.9", 7000)},
		Window:  &protocol.PortWindow{IP: pub, Lo: 6000, Hi: 6001}}
	kinds := func() map[netip.AddrPort]candidate.Kind {
		out := map[netip.AddrPort]candidate.Kind{}
		targets, _ := rt.peerTargets(a)
		for _, x := range targets {
			out[x.to] = x.kind
		}
		return out
	}
	got := kinds()
	want := map[netip.AddrPort]candidate.Kind{
		netipAP("198.51.100.7", 5000): candidate.KindTargets,
		netipAP("100.64.1.2", 6000):   candidate.KindLAN,
		netipAP("198.51.100.7", 6000): candidate.KindTargets,
		netipAP("198.51.100.7", 6001): candidate.KindTargets,
	}
	if len(got) != len(want) {
		t.Fatalf("targets %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%v: kind %v want %v", k, got[k], v)
		}
	}
	if _, rej := rt.peerTargets(a); rej != 1 {
		t.Fatalf("refused %d (the unverified public target)", rej)
	}
	if n := w.fs.cnt.targetRejected.Load(); n != 2 {
		t.Fatalf("rejected %d", n)
	}
	w.hairpinOK.Store(true)
	if k := kinds()[netipAP("100.64.1.2", 6000)]; k != candidate.KindTargets {
		t.Fatalf("upstream candidate after a hairpin success: %v", k)
	}
	a.Source = protocol.TargetsSandwich
	if _, ok := kinds()[netipAP("100.64.1.2", 6000)]; ok {
		t.Fatal("a private target outside source portmap was admitted")
	}
}

// A round whose targets admission refuses reports nothing sent and the
// refusals — planned targets and pushed ones alike — so that the server can
// end a session no round can serve.
func TestRoundReportsRejected(t *testing.T) {
	t.Parallel()
	_, _, rr := soloRound(t, nil, nil, func(r *protocol.RoundPlan) {
		r.Sides[0].Stages = []protocol.Stage{
			{Kind: protocol.StageDirect, Targets: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.250:5000")}, Repeats: 2},
			{Kind: protocol.StagePredict, IP: netip.MustParseAddr("198.51.100.251"), Anchor: 6000, Steps: []int16{1}, Span: 4},
		}
	}, func(so *solo) *protocol.RoundResult {
		pushTargets(so, []string{"198.51.100.252:7000"}, nil)
		return nil
	})
	if f := rr.Families[0]; f.Sent != 0 || f.Rejected != 3 {
		t.Fatalf("family %+v", f)
	}
}

// A paired predict stage is expanded with the initiator's spray seed
// of the round on both sides — the initiator's packets in the first pair
// order, the responder's in the second — so that the sides' mappings pair
// up; any other stage with the side's own spray seed.
func TestSprayItemsPaired(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("198.51.100.7")
	rp := protocol.RoundPlan{Round: 2, Seed: 99}
	tok, route := rt.start.Token, rt.start.Wire.RouteID
	pairSeed := udpwire.SpraySeed(tok, route, udpwire.RoleInitiator, rp.Round, rp.Seed)
	fr := &familyRound{rt: rt, run: &roundRun{plan: rp}, socks: []*udpSock{s},
		w: &worker{fam: protocol.FamilyUDP4, fs: rt.fam(protocol.FamilyUDP4), verified: map[netip.Addr]bool{peer: true}}}
	paired := protocol.Stage{Kind: protocol.StagePredict, IP: peer, Anchor: 40000, Steps: []int16{1}, Span: 16, Pair: true}
	ports := func(items []sendItem) []uint16 {
		var out []uint16
		for _, it := range items {
			out = append(out, it.to.Port())
		}
		return out
	}
	for _, role := range []udpwire.Role{udpwire.RoleInitiator, udpwire.RoleResponder} {
		codec, err := udpwire.NewCodec(tok, route, role, udpwire.PadPolicy{Min: 60, Max: 160}, rt.clk.Now)
		if err != nil {
			t.Fatal(err)
		}
		rt.codec = codec
		fr.seed = udpwire.SpraySeed(tok, route, role, rp.Round, rp.Seed)
		want := plan.ExpandPaired(paired.Anchor, paired.Steps, int(paired.Span),
			plan.ExpandInput{PairSeed: pairSeed, Responder: role == udpwire.RoleResponder})
		if got := ports(fr.sprayItems(0, paired, rt.clk.Now(), nil)); !slices.Equal(got, want) || len(got) != 16 {
			t.Fatalf("%v: paired ports %v, want %v", role, got, want)
		}
		plain := paired
		plain.Pair = false
		want = plan.ExpandPredict(plain.Anchor, plain.Steps, int(plain.Span), plan.ExpandInput{Seed: fr.seed})
		if got := ports(fr.sprayItems(0, plain, rt.clk.Now(), nil)); !slices.Equal(got, want) {
			t.Fatalf("%v: predict ports %v, want %v", role, got, want)
		}
	}
}

// Targets the gate refuses were never written: a background round whose
// spray runs into the session's distinct-target limit is no failure spike
// and is not halted.
func TestBackgroundRoundGateRefusalsNoHalt(t *testing.T) {
	t.Parallel()
	pol := &protocol.Policy{Budget: protocol.Budget{MaxDistinctTargets: 2}}
	so, _, rr := soloRound(t, pol, nil, func(r *protocol.RoundPlan) {
		r.Budget = protocol.BudgetBackground
		peer := r.Sides[0].Stages[0].Targets[0]
		r.Sides[0].Stages = append(r.Sides[0].Stages,
			protocol.Stage{Kind: protocol.StagePredict, IP: peer.Addr(), Anchor: 6000, Steps: []int16{1}, Span: 32})
	}, nil)
	if f := rr.Families[0]; f.Halted || f.Sent == 0 {
		t.Fatalf("family %+v", f)
	}
	if got := so.host.Stats(); got.MaxConsecutiveRun > maxAnswerRun {
		t.Fatalf("run of %d consecutive ports", got.MaxConsecutiveRun)
	}
}

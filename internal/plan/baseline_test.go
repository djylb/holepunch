package plan

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// The plain-punching baseline.

// plainRound is the Plain ablation's one round as the catalogue has it:
// easy_r1_direct, both sides D(plainPackets) at once.
func TestPlainRoundIsEasyR1(t *testing.T) {
	vr, _ := variantOf(vEasy1)
	for _, s := range []sideTmpl{vr.a, vr.b} {
		if len(s.stages) != 1 || s.stages[0].kind != protocol.StageDirect || int(s.stages[0].repeats) != plainPackets ||
			s.stages[0].ttl != 0 || s.sendDelayMs != 0 {
			t.Fatalf("easy_r1_direct side %+v, want D(%d) at once", s, plainPackets)
		}
	}
	for n, want := range map[int]uint8{1: 5, 2: 3, 3: 3, 8: 3} {
		if got := baselineRepeatsFor(n); got != want || int(got)*n < plainPackets {
			t.Errorf("%d targets: D(%d), want D(%d)", n, got, want)
		}
	}
}

// secondEndpoint adds the verified mapping of the peer's second socket, as
// a full probe sees it: the two Direct targets of the ladder.
func secondEndpoint(v protocol.PeerView) protocol.PeerView {
	for i := range v.Families {
		fv := &v.Families[i]
		obs := fv.Traits.Observed
		fv.Endpoints = append(slices.Clone(fv.Endpoints), protocol.Endpoint{Addr: netip.AddrPortFrom(obs.Addr(), obs.Port()+100),
			Source: protocol.EndpointSecond, Socket: 1, Verified: true})
	}
	return v
}

// TestRound1Baseline: for every combination class of DefaultPlanner
// — each role order, each start the strategy memory can give the ladder,
// one or two verified peer endpoints, the Background mode's slow birthday
// and a dual-stack pair — the first round has each side's primary socket
// send to the peer's verified endpoints at the normal TTL as the side
// fires, at least D(3) a target and at least the Plain round's packets in
// all, except the OPEN side of open_x_edm, which by design only replies.
func TestRound1Baseline(t *testing.T) {
	f4, f6 := protocol.FamilyUDP4, protocol.FamilyUDP6
	v6open := func(n int) protocol.Traits {
		tr := withObserved(openTraits(f6), observedFor(f6, n))
		tr.NoNAT = protocol.TriTrue
		return tr
	}
	seqAt := func(n int) protocol.Traits {
		tr := withObserved(seqTraits(f4), observedFor(f4, n))
		tr.PortAnchor = tr.Observed.Port()
		return tr
	}
	type pairCase struct {
		name  string
		a, b  protocol.PeerView
		class string
		mode  protocol.SessionMode
	}
	single := func(name, class string, a, b protocol.Traits) pairCase {
		return pairCase{name: name, a: view(a), b: view(b), class: class}
	}
	cases := []pairCase{
		single("open×open", PairEasy, openTraits(f4), withObserved(openTraits(f4), observedFor(f4, 11))),
		single("open×pdf", PairEasy, openTraits(f4), pdfTraits(f4)),
		single("pdf×pdf", PairEasy, pdfTraits(f4), withObserved(pdfTraits(f4), observedFor(f4, 12))),
		single("v6 direct", PairV6Direct, v6open(1), v6open(2)),
		single("open×seq", PairOpenEDM, openTraits(f4), seqTraits(f4)),
		single("open×rnd", PairOpenEDM, openTraits(f4), rndTraits(f4)),
		single("pdf×seq", PairPDFSeq, pdfTraits(f4), seqTraits(f4)),
		single("pdf×rnd", PairPDFRnd, pdfTraits(f4), rndTraits(f4)),
		single("seq×seq", PairSeqSeq, seqTraits(f4), seqAt(6)),
		single("seq×rnd", PairSeqRnd, seqTraits(f4), rndTraits(f4)),
		single("rnd×rnd", PairRndRnd, rndTraits(f4), withObserved(rndTraits(f4), observedFor(f4, 9))),
		single("pdf×pres", PairPDFPres, pdfTraits(f4), presTraits(f4)),
		single("pres×pres", PairPresPres, presTraits(f4), withObserved(presTraits(f4), observedFor(f4, 8))),
		{name: "pdf×rnd background", a: view(pdfTraits(f4)), b: view(rndTraits(f4)), class: PairPDFRnd, mode: protocol.ModeBackground},
		{name: "dual pdf×seq, v6 direct", a: dual(pdfTraits(f4), v6open(1)), b: dual(seqTraits(f4), v6open(2)), class: PairV6Direct},
	}
	var p DefaultPlanner
	runs := 0
	for _, c := range cases {
		for _, endpoints := range []int{1, 2} {
			for swap := range 2 {
				va, vb := c.a, c.b
				if endpoints == 2 {
					va, vb = secondEndpoint(va), secondEndpoint(vb)
				}
				if swap == 1 {
					va, vb = vb, va
				}
				ci := api.ClassifyInput{Initiator: va, Responder: vb, Policy: protocol.Policy{Budget: protocol.DefaultBudget()},
					Timeouts: protocol.DefaultTimeouts(), Mode: c.mode}
				if c.mode == protocol.ModeBackground {
					ci.Policy.Budget = protocol.BackgroundBudget()
				}
				cl := p.Classify(ci)
				if cl.Reject != "" || cl.PairClass != c.class {
					t.Fatalf("%s: class %q, reject %q", c.name, cl.PairClass, cl.Reject)
				}
				for start := range cl.Ladder {
					name := fmt.Sprintf("%s/%d endpoints/swap %d/start %d", c.name, endpoints, swap, start)
					in := api.RoundInput{Round: 1, Class: cl, Order: append(slices.Clone(cl.Ladder[start:]), cl.Ladder[:start]...),
						MemoryPromoted: start > 0, RTT: [2]time.Duration{40 * time.Millisecond, 60 * time.Millisecond},
						Remaining: 58 * time.Second, D: 150 * time.Millisecond, BudgetLeft: [2]int{-1, -1}, Views: [2]protocol.PeerView{va, vb},
						Policy: ci.Policy, AllowExtreme: true, MaxRounds: 6, HandshakeMs: 60000, SandwichOK: true}
					dec := p.Round(classified(in, ci))
					if dec.Stop != "" {
						t.Fatalf("%s: round 1 stops (%s)", name, dec.Stop)
					}
					for fi, fp := range famsOf(ci) {
						for role := range 2 {
							fs := dec.Sides[role][fi]
							if c.mode == protocol.ModeBackground {
								if stagePackets(fs) != int(fs.MaxPackets) { // checkSide reads the default session budget
									t.Errorf("%s: MaxPackets differs from the stages: %s", name, describe(fs))
								}
							} else {
								checkSide(t, fs, dec.Budget, dec.Window)
							}
							if fp.PairClass == PairOpenEDM && role == roleIndex(fp.SideA) {
								continue // the OPEN side only replies, by design
							}
							peer, _ := findFamily(in.Views[1-role], fp.Family)
							checkBaseline(t, fmt.Sprintf("%s/%s/%s role %d", name, fp.Family, dec.VariantName, role), fs, peer)
							runs++
						}
					}
				}
			}
		}
	}
	if runs < 200 {
		t.Fatalf("setup: %d sides checked", runs)
	}
}

// checkBaseline fails unless the family side fs carries the baseline toward
// the peer family peer: a Direct stage at the normal TTL, firing with the
// side, aimed at every verified endpoint of the peer's primary and second
// sockets — the peer's observed endpoint first — with at least D(3) a
// target and plainPackets in all. Direct stages go out from every round
// socket, the primary first.
func checkBaseline(t *testing.T, name string, fs protocol.FamilySide, peer protocol.FamilyView) {
	t.Helper()
	var want []netip.AddrPort
	for _, e := range peer.Endpoints {
		if e.Verified && (e.Source == protocol.EndpointServer || e.Source == protocol.EndpointSecond) {
			want = append(want, e.Addr)
		}
	}
	if fs.Role == protocol.SideReplyOnly {
		t.Errorf("%s: the side only replies: %s", name, describe(fs))
		return
	}
	for _, st := range fs.Stages {
		if st.Kind != protocol.StageDirect || st.TTL != 0 || st.AtMs > fs.SendDelayMs || !slices.Contains(st.Targets, peer.Traits.Observed) {
			continue
		}
		for _, w := range want {
			if !slices.Contains(st.Targets, w) {
				t.Errorf("%s: baseline misses the verified endpoint %v: %s", name, w, describe(fs))
			}
		}
		if st.Repeats < baselineRepeats || int(st.Repeats)*len(want) < plainPackets {
			t.Errorf("%s: baseline D(%d) to %d targets, fewer than Plain's %d packets: %s", name, st.Repeats, len(want), plainPackets, describe(fs))
		}
		return
	}
	t.Errorf("%s: no normal-TTL Direct to the peer's observed %v as the side fires: %s", name, peer.Traits.Observed, describe(fs))
}

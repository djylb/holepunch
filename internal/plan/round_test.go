package plan

import (
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/msgframe"
	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

func TestCategoryString(t *testing.T) {
	for c, want := range map[Category]string{CatNone: "none", CatOpen: "open", CatPDF: "pdf", CatSEQ: "seq", CatRND: "rnd", Category(99): "invalid"} {
		if got := c.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", c, got, want)
		}
	}
}

func TestAttributeWrapper(t *testing.T) {
	ev := api.Evidence{Fatal: [2]protocol.Reason{protocol.ReasonUDPBlocked, protocol.ReasonUDPBlocked}}
	if r := Attribute(ev); r != protocol.ReasonUDPBlocked {
		t.Fatalf("Attribute = %s, want udp_blocked", r)
	}
}

func TestExpandStageKinds(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.9")
	direct := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:40000")}
	if got := ExpandStage(protocol.Stage{Kind: protocol.StageDirect, Targets: direct}, ExpandInput{}); len(got) != 1 || got[0] != direct[0] {
		t.Fatalf("direct expand = %v", got)
	}
	if got := ExpandStage(protocol.Stage{Kind: protocol.StageReplyOnly}, ExpandInput{}); got != nil {
		t.Fatalf("reply_only expand = %v, want nil", got)
	}
	if got := ExpandStage(protocol.Stage{Kind: protocol.StagePredict, IP: ip, Anchor: 40000, Steps: []int16{1}, Span: 8}, ExpandInput{Seed: [8]byte{1}}); len(got) == 0 {
		t.Fatal("predict expand empty")
	}
	if got := ExpandStage(protocol.Stage{Kind: protocol.StageRandom, IP: ip, Count: 8}, ExpandInput{Seed: [8]byte{1}}); len(got) == 0 {
		t.Fatal("random expand empty")
	}
}

// A sandwich is set on the predicted (SEQ) side when both peers negotiated it.
func TestSandwichOnSEQSide(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f) // responder = SEQ
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 1, nil)
	in.SandwichOK = true
	dec := p.Round(in)
	if !sandwichOf(dec)[1] {
		t.Errorf("sandwich not set on the SEQ (responder) side: %v", sandwichOf(dec))
	}
	if sandwichOf(dec)[0] {
		t.Errorf("sandwich wrongly set on the PDF (initiator) side")
	}
}

// The sandwich is flagged per family: in a dual
// stack where only IPv4 is PDF × SEQ, the SEQ side runs it in IPv4 alone,
// and the IPv6 family of the same side — PDF × PDF — does not.
func TestSandwichPerFamily(t *testing.T) {
	a4, b4 := pdfTraits(protocol.FamilyUDP4), seqTraits(protocol.FamilyUDP4)
	a6, b6 := pdfTraits(protocol.FamilyUDP6), pdfTraits(protocol.FamilyUDP6)
	b6.Observed = observedFor(protocol.FamilyUDP6, 5)
	var p DefaultPlanner
	ci := api.ClassifyInput{Initiator: dual(a4, a6), Responder: dual(b4, b6), Policy: protocol.Policy{Budget: protocol.DefaultBudget()}, Timeouts: protocol.DefaultTimeouts()}
	cl := p.Classify(ci)
	in := roundInput(cl, a4, b4, 1, nil)
	in.Views, in.SandwichOK = [2]protocol.PeerView{dual(a4, a6), dual(b4, b6)}, true
	dec := p.Round(in)
	if dec.Stop != "" || len(dec.Sides[1]) != 2 {
		t.Fatalf("stop %q, responder families %d", dec.Stop, len(dec.Sides[1]))
	}
	for r, sides := range dec.Sides {
		for _, fs := range sides {
			want := r == 1 && fs.Family == protocol.FamilyUDP4
			if fs.Sandwich != want {
				t.Errorf("role %d %s: sandwich %v, want %v", r, fs.Family, fs.Sandwich, want)
			}
		}
	}
}

// Dual stack with the same pair class on both families runs both families each
// round and keeps the invariants (also exercises per-family variant selection
// past the primary and the shared allocator over several rounds).
func TestDualStackSamePairClass(t *testing.T) {
	a4, b4 := pdfTraits(protocol.FamilyUDP4), seqTraits(protocol.FamilyUDP4)
	a6, b6 := pdfTraits(protocol.FamilyUDP6), seqTraits(protocol.FamilyUDP6)
	var p DefaultPlanner
	ci := api.ClassifyInput{Initiator: dual(a4, a6), Responder: dual(b4, b6), Policy: protocol.Policy{Budget: protocol.DefaultBudget()}, Timeouts: protocol.DefaultTimeouts()}
	cl := p.Classify(ci)
	var prev []api.RoundOutcome
	for round := 1; round <= 5; round++ {
		in := roundInput(cl, a4, b4, round, prev)
		in.Views = [2]protocol.PeerView{dual(a4, a6), dual(b4, b6)}
		in.AllowExtreme = true
		in.MaxRounds = 6
		dec := p.Round(in)
		if dec.Stop != "" {
			break
		}
		for r := 0; r < 2; r++ {
			if len(dec.Sides[r]) != 2 {
				t.Fatalf("round %d role %d has %d families, want 2", round, r, len(dec.Sides[r]))
			}
			for _, fs := range dec.Sides[r] {
				checkSide(t, fs, dec.Budget, dec.Window)
			}
		}
		prev = append(prev, api.RoundOutcome{Round: round, Variant: dec.Variant, Class: api.RoundNoContact, Budget: dec.Budget})
		if dec.Final {
			break
		}
	}
}

// A v6-public-direct pair uses the v6_direct ladder (easy's first three rounds).
func TestV6Direct(t *testing.T) {
	a := openTraits(protocol.FamilyUDP6)
	a.NoNAT = protocol.TriTrue
	b := openTraits(protocol.FamilyUDP6)
	b.NoNAT = protocol.TriTrue
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	if cl.PairClass != PairV6Direct {
		t.Fatalf("pair class = %q, want v6_direct", cl.PairClass)
	}
	if len(cl.Ladder) != 3 {
		t.Fatalf("v6_direct ladder length %d, want 3", len(cl.Ladder))
	}
}

// Rescue with no verified endpoints for the silent side degrades it to
// reply_only (the plan still encodes).
func TestRescueReplyOnly(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 2, []api.RoundOutcome{{Round: 1, Variant: cl.Ladder[0], Class: api.RoundOneWay, Budget: protocol.BudgetBalanced}})
	// seer = initiator saw a packet; silent = responder, but give the seer
	// (initiator) no verified endpoints so the silent side has no target.
	in.Evidence.SeenFrom[0] = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.2:40002")}
	in.Evidence.Hit[0] = true
	in.Views[0] = protocol.PeerView{Families: []protocol.FamilyView{{Family: f, Traits: a}}} // no endpoints
	dec := p.Round(in)
	if !dec.Rescue {
		t.Fatalf("expected rescue, got %q", dec.VariantName)
	}
	rp := protocol.RoundPlan{Round: 2, Variant: dec.VariantName, Budget: dec.Budget, WindowMs: uint16(dec.Window / time.Millisecond), Seed: 1, Rescue: true, Sides: dec.Sides[1]}
	pg := protocol.PunchGo{SessionID: "s1", Round: 2, WindowMs: rp.WindowMs, Plan: &rp}
	if _, err := msgframe.Encode(pg); err != nil {
		t.Fatalf("rescue silent side does not marshal: %v", err)
	}
}

// Low TTL disabled by policy clears the ttl of every stage.
func TestLowTTLDisabled(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := openTraits(f), openTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	off := false
	in := roundInput(cl, a, b, 2, []api.RoundOutcome{{Round: 1, Variant: vEasy1, Class: api.RoundNoContact, Budget: protocol.BudgetLight}})
	in.Policy.LowTTL = &off
	dec := p.Round(in)
	for r := 0; r < 2; r++ {
		for _, fs := range dec.Sides[r] {
			for _, st := range fs.Stages {
				if st.TTL != 0 {
					t.Errorf("ttl %d with low TTL disabled", st.TTL)
				}
			}
		}
	}
}

package plan

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// checkSide asserts a FamilySide never exceeds its budget class or the session
// budget, and satisfies the feasibility invariant (granted = emittable):
// MaxPackets is exactly what the stages ask for and never less than what
// they expand to.
func checkSide(t *testing.T, fs protocol.FamilySide, class protocol.BudgetClass, win time.Duration) {
	t.Helper()
	if need := stagePackets(fs); need != int(fs.MaxPackets) {
		t.Errorf("%s: stages ask for %d packets, MaxPackets %d: %s", fs.Role, need, fs.MaxPackets, describe(fs))
	}
	if got := expandedPackets(fs); got > int(fs.MaxPackets) {
		t.Errorf("%s: stages expand to %d packets > MaxPackets %d: %s", fs.Role, got, fs.MaxPackets, describe(fs))
	}
	lim, ok := class.Limits()
	if !ok {
		t.Fatalf("invalid class %q", class)
	}
	sessB := protocol.DefaultBudget()
	if fs.MaxPackets > lim.MaxPackets {
		t.Errorf("%s MaxPackets %d > class %d", fs.Role, fs.MaxPackets, lim.MaxPackets)
	}
	if fs.MaxPPS > lim.MaxPPS {
		t.Errorf("MaxPPS %d > class %d", fs.MaxPPS, lim.MaxPPS)
	}
	if fs.MaxPPS > sessB.MaxPPS {
		t.Errorf("MaxPPS %d > session %d", fs.MaxPPS, sessB.MaxPPS)
	}
	if n := int(fs.Sockets) + fs.FreshSockets(); n > int(lim.MaxSockets) {
		t.Errorf("Sockets %d + fresh %d > class %d", fs.Sockets, fs.FreshSockets(), lim.MaxSockets)
	}
	if n := int(fs.Sockets) + fs.FreshSockets(); n > int(sessB.MaxSockets) {
		t.Errorf("Sockets %d + fresh %d > session %d", fs.Sockets, fs.FreshSockets(), sessB.MaxSockets)
	}
	if fs.MaxDistinctPorts > lim.MaxDistinctPorts {
		t.Errorf("MaxDistinctPorts %d > class %d", fs.MaxDistinctPorts, lim.MaxDistinctPorts)
	}
	if fs.MaxNewPerSec > sessB.MaxNewPerSec {
		t.Errorf("MaxNewPerSec %d > session %d", fs.MaxNewPerSec, sessB.MaxNewPerSec)
	}
	newTargets := sprayCount(fs)
	feasible := int(fs.MaxNewPerSec)*int(win/time.Millisecond)/1000 + 16
	if newTargets > feasible {
		t.Errorf("new targets %d > feasible %d (nps=%d win=%v role=%s)", newTargets, feasible, fs.MaxNewPerSec, win, fs.Role)
	}
	if newTargets > int(lim.MaxDistinctPorts) {
		t.Errorf("new targets %d > class distinct %d", newTargets, lim.MaxDistinctPorts)
	}
	if len(fs.Stages) < 1 {
		t.Errorf("%s has no stage (plan would not encode)", fs.Role)
	}
	if fs.SendDelayMs > 0 && fs.Role != protocol.SideSender {
		t.Errorf("send_delay %d but role %s (must be sender)", fs.SendDelayMs, fs.Role)
	}
}

// stagePackets is the number of initiated packets the stages of fs ask for:
// Direct = sockets x targets x repeats, Predict = span, Random = count.
func stagePackets(fs protocol.FamilySide) int {
	n := 0
	for _, st := range fs.Stages {
		switch st.Kind {
		case protocol.StageDirect:
			n += int(fs.Sockets) * len(st.Targets) * int(st.Repeats)
		case protocol.StagePredict:
			n += int(st.Span)
		case protocol.StageRandom:
			n += int(st.Count)
		case protocol.StageFresh, protocol.StageFreshPeer:
			n += FreshPackets(st)
		}
	}
	return n
}

// expandedPackets is what the client actually sends for fs: the Direct
// stages on every socket, the predict and random stages as ExpandStage
// generates them.
func expandedPackets(fs protocol.FamilySide) int {
	n := 0
	for i, st := range fs.Stages {
		switch st.Kind {
		case protocol.StageDirect:
			n += int(fs.Sockets) * len(st.Targets) * int(st.Repeats)
		case protocol.StagePredict, protocol.StageRandom, protocol.StageFreshPeer:
			n += len(ExpandStage(st, ExpandInput{Seed: [8]byte{7, byte(i)}, StageIndex: i, PairSeed: [8]byte{8}})) * int(max(st.Repeats, 1))
		case protocol.StageFresh:
			n += len(FreshPorts([8]byte{8}, int(st.Count))) * int(st.Repeats) * max(len(st.Targets), 1)
		}
	}
	return n
}

func describe(fs protocol.FamilySide) string {
	s := fmt.Sprintf("%s role=%s sockets=%d MaxPackets=%d MaxDistinct=%d stages:", fs.Family, fs.Role, fs.Sockets, fs.MaxPackets, fs.MaxDistinctPorts)
	for _, st := range fs.Stages {
		s += fmt.Sprintf(" %s(targets=%d rep=%d anchor=%d span=%d count=%d)", st.Kind, len(st.Targets), st.Repeats, st.Anchor, st.Span, st.Count)
	}
	return s
}

// sprayCount is the new destinations of fs's generated stages: the predict
// and random ports and the peer's fresh ports.
func sprayCount(fs protocol.FamilySide) int {
	n := 0
	for _, st := range fs.Stages {
		switch st.Kind {
		case protocol.StagePredict:
			n += int(st.Span)
		case protocol.StageRandom, protocol.StageFreshPeer:
			n += int(st.Count)
		}
	}
	return n
}

// realisticView is the merged view natprobe hands over: an endpoint-dependent
// peer with every observer mapping of two sockets, an endpoint-independent
// one with two sibling sockets.
func realisticView(tr protocol.Traits) protocol.PeerView {
	if tr.EndpointDependent() {
		return apdmView(tr)
	}
	return siblingView(tr)
}

// TestLaddersBudgetInvariant: every round of every pair class stays within its
// class ceiling and the session budget, and every side's MaxPackets
// is exactly what its stages expand to, with the minimal views of the
// fixtures and with the realistic endpoint sets of natprobe's merge, with a
// full and a nearly spent packet budget — window in [700ms,10s], round 1 <=
// balanced, and escalation is at most one class per round (on the actual
// granted class).
func TestLaddersBudgetInvariant(t *testing.T) {
	f := protocol.FamilyUDP4
	combos := []struct {
		name      string
		a, b      protocol.Traits
		pairClass string
	}{
		{"easy", openTraits(f), openTraits(f), PairEasy},
		{"open_x_edm", openTraits(f), seqTraits(f), PairOpenEDM},
		{"pdf_x_seq", pdfTraits(f), seqTraits(f), PairPDFSeq},
		{"pdf_x_rnd", pdfTraits(f), rndTraits(f), PairPDFRnd},
		{"seq_x_seq", seqTraits(f), seqTraits(f), PairSeqSeq},
		{"seq_x_rnd", seqTraits(f), rndTraits(f), PairSeqRnd},
		{"rnd_x_rnd", rndTraits(f), rndTraits(f), PairRndRnd},
		{"pdf_x_pres", pdfTraits(f), presTraits(f), PairPDFPres},
		{"pres_x_pres", presTraits(f), presTraits(f), PairPresPres},
	}
	var p DefaultPlanner
	for _, c := range combos {
		for _, realistic := range []bool{false, true} {
			for _, budgetLeft := range []int{3000, 100} {
				t.Run(fmt.Sprintf("%s/realistic=%v/left=%d", c.name, realistic, budgetLeft), func(t *testing.T) {
					ci := classifyInput(c.a, c.b)
					views := [2]protocol.PeerView{view(c.a), view(c.b)}
					if realistic {
						views = [2]protocol.PeerView{realisticView(c.a), realisticView(c.b)}
						ci.Initiator, ci.Responder = views[0], views[1]
					}
					cl := p.Classify(ci)
					if cl.Reject != "" {
						t.Fatalf("unexpected reject %v", cl.Reject)
					}
					if cl.PairClass != c.pairClass {
						t.Fatalf("pair class %q, want %q", cl.PairClass, c.pairClass)
					}
					var prev []api.RoundOutcome
					prevRank := 0
					for round := 1; round <= 6; round++ {
						in := roundInput(cl, c.a, c.b, round, prev)
						in.Views = views
						in.BudgetLeft = [2]int{budgetLeft, budgetLeft}
						in.AllowExtreme = true
						in.MaxRounds = 6
						in.Policy.Budget.Birthday = protocol.BirthdayAggressive
						in.HandshakeMs = 40000
						dec := p.Round(in)
						if dec.Stop != "" {
							break
						}
						if dec.Window < 700*time.Millisecond || dec.Window > 10*time.Second {
							t.Fatalf("round %d window %v out of range", round, dec.Window)
						}
						rank := dec.Budget.Rank()
						if round == 1 && rank > protocol.BudgetBalanced.Rank() {
							t.Fatalf("round 1 budget %q exceeds balanced", dec.Budget)
						}
						if prevRank > 0 && rank > prevRank+1 {
							t.Fatalf("round %d escalated from rank %d to %d (>1)", round, prevRank, rank)
						}
						prevRank = rank
						for role := range 2 {
							total := 0
							for _, fs := range dec.Sides[role] {
								checkSide(t, fs, dec.Budget, dec.Window)
								total += int(fs.MaxPackets)
							}
							if total > budgetLeft {
								t.Fatalf("round %d role %d: %d packets > BudgetLeft %d", round, role, total, budgetLeft)
							}
						}
						prev = append(prev, api.RoundOutcome{Round: round, Variant: dec.Variant, Class: api.RoundNoContact, Rescue: dec.Rescue,
							Budget: dec.Budget, Families: dec.Families})
						if dec.Final {
							break
						}
					}
				})
			}
		}
	}
}

func TestNoCommonFamily(t *testing.T) {
	var p DefaultPlanner
	in := api.ClassifyInput{
		Initiator: view(openTraits(protocol.FamilyUDP4)),
		Responder: view(openTraits(protocol.FamilyUDP6)),
		Policy:    protocol.Policy{Budget: protocol.DefaultBudget()},
	}
	if cl := p.Classify(in); cl.Reject != protocol.ReasonNoCommonFamily {
		t.Fatalf("reject = %v, want no_common_family", cl.Reject)
	}
}

// TestStopRuleTimeAndBudget: time stop uses the coordinator's D and the
// budget floor stops at BudgetLeft < 60.
func TestStopRuleTimeAndBudget(t *testing.T) {
	var p DefaultPlanner
	f := protocol.FamilyUDP4
	cl := p.Classify(classifyInput(openTraits(f), openTraits(f)))
	prev := []api.RoundOutcome{{Round: 1, Variant: vEasy1, Class: api.RoundNoContact, Budget: protocol.BudgetLight}}

	low := roundInput(cl, openTraits(f), openTraits(f), 2, prev)
	low.Remaining = 300 * time.Millisecond
	if dec := p.Round(low); dec.Stop == "" {
		t.Fatal("expected stop on low remaining")
	}

	broke := roundInput(cl, openTraits(f), openTraits(f), 2, prev)
	broke.BudgetLeft = [2]int{50, 3000}
	if dec := p.Round(broke); dec.Stop != protocol.ReasonPacketBudgetExceeded {
		t.Fatalf("stop = %v, want packet_budget_exceeded", dec.Stop)
	}
}

// TestStopRuleUsesCoordinatorD: the planner uses the coordinator's D and
// does not substitute a fixed margin. Remaining just below 700ms + D stops.
func TestStopRuleUsesCoordinatorD(t *testing.T) {
	var p DefaultPlanner
	f := protocol.FamilyUDP4
	cl := p.Classify(classifyInput(openTraits(f), openTraits(f)))
	prev := []api.RoundOutcome{{Round: 1, Variant: vEasy1, Class: api.RoundNoContact, Budget: protocol.BudgetLight}}
	in := roundInput(cl, openTraits(f), openTraits(f), 2, prev)
	in.D = 200 * time.Millisecond
	in.Remaining = 880 * time.Millisecond // < 700 + 200
	if dec := p.Round(in); dec.Stop == "" {
		t.Fatalf("Remaining 880ms < 700ms + D(200ms) must stop, got %s", dec.VariantName)
	}
	in.Remaining = 1000 * time.Millisecond // > 900
	if dec := p.Round(in); dec.Stop != "" {
		t.Fatalf("Remaining 1000ms > 700 + D should open a round, got stop %s", dec.Stop)
	}
}

func TestRescueRound(t *testing.T) {
	var p DefaultPlanner
	f := protocol.FamilyUDP4
	cl := p.Classify(classifyInput(pdfTraits(f), seqTraits(f)))
	in := roundInput(cl, pdfTraits(f), seqTraits(f), 2, []api.RoundOutcome{{Round: 1, Variant: cl.Ladder[0], Class: api.RoundOneWay, Budget: protocol.BudgetBalanced}})
	in.Evidence.SeenFrom[0] = []netip.AddrPort{observedFor(f, 3)} // the responder's mapping
	in.Evidence.Hit[0] = true
	dec := p.Round(in)
	if !dec.Rescue {
		t.Fatalf("expected rescue round, got %q stop=%v", dec.VariantName, dec.Stop)
	}
	if dec.Window != 1500*time.Millisecond {
		t.Fatalf("rescue window %v, want 1.5s", dec.Window)
	}
	if len(dec.Sides[0]) == 0 || dec.Sides[0][0].Role != protocol.SideSender {
		t.Fatalf("seer (initiator) not sender: %+v", dec.Sides[0])
	}
	// A second one-way after the rescue is used must not insert another rescue.
	in2 := roundInput(cl, pdfTraits(f), seqTraits(f), 3, []api.RoundOutcome{
		{Round: 1, Variant: cl.Ladder[0], Class: api.RoundOneWay, Budget: protocol.BudgetBalanced},
		{Round: 2, Variant: vRescue, Class: api.RoundOneWay, Rescue: true, Budget: protocol.BudgetLight},
	})
	in2.RescueUsed = true
	in2.Evidence.SeenFrom[0] = in.Evidence.SeenFrom[0]
	if dec2 := p.Round(in2); dec2.Rescue {
		t.Fatal("second rescue round must not be inserted")
	}
}

// TestRoundNeedsNoHiddenState: Round derives the per-family plans from its
// input, so a Classification rebuilt from its exported fields plans the
// same rounds, and one that names fewer families runs only those.
func TestRoundNeedsNoHiddenState(t *testing.T) {
	var p DefaultPlanner
	a4, b4 := pdfTraits(protocol.FamilyUDP4), seqTraits(protocol.FamilyUDP4)
	a6, b6 := openTraits(protocol.FamilyUDP6), rndTraits(protocol.FamilyUDP6)
	ci := api.ClassifyInput{Initiator: dual(a4, a6), Responder: dual(b4, b6), Policy: protocol.Policy{Budget: protocol.DefaultBudget()},
		Timeouts: protocol.DefaultTimeouts(), Pair: protocol.PairFacts{SharedFamilies: []protocol.Family{protocol.FamilyUDP6, protocol.FamilyUDP4}}}
	cl := p.Classify(ci)
	if len(cl.Families) != 2 {
		t.Fatalf("families %v", cl.Families)
	}
	rebuilt := api.Classification{PairClass: cl.PairClass, Families: slices.Clone(cl.Families), SideA: cl.SideA,
		Ladder: slices.Clone(cl.Ladder), Advice: cl.Advice}
	in := classified(roundInput(cl, protocol.Traits{}, protocol.Traits{}, 1, nil), ci)
	in.Views = [2]protocol.PeerView{ci.Initiator, ci.Responder}
	want := p.Round(in)
	in.Class = rebuilt
	if got := p.Round(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("rebuilt classification plans\n%+v\nwant\n%+v", got, want)
	}

	// Only the v4 family: its ladder is the primary one now.
	in.Class = api.Classification{Families: []protocol.Family{protocol.FamilyUDP4}, Ladder: famsOf(ci)[1].Ladder}
	got := p.Round(in)
	if got.Stop != "" || len(got.Families) != 1 || got.Families[0].Family != protocol.FamilyUDP4 || len(got.Sides[0]) != 1 ||
		got.Sides[0][0].Family != protocol.FamilyUDP4 {
		t.Fatalf("v4 only: %+v", got)
	}
	// A family the views do not share is not planned.
	in.Class.Families = []protocol.Family{"udp9"}
	if got := p.Round(in); got.Stop == "" {
		t.Fatalf("unshared family planned: %+v", got)
	}
}

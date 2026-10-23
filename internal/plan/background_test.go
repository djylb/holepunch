package plan

import (
	"testing"
	"time"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// The slow birthday of a Background session.

func backgroundInput(a, b protocol.Traits, mode protocol.SessionMode) api.ClassifyInput {
	ci := classifyInput(a, b)
	ci.Mode = mode
	ci.Policy.Budget = protocol.BackgroundBudget()
	return ci
}

// In Background mode pdf_x_rnd runs its cheap round and then the slow
// birthday: 120 RND-side sockets opened 16 a second, 1025 PDF-side ports at
// 25 a second from 4 s on, in a 45 s background-class window; the grants
// stay what the stages expand to. Interactive keeps the ladder.
func TestBackgroundLadder(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), rndTraits(f)
	var p DefaultPlanner
	if cl := p.Classify(backgroundInput(a, b, protocol.ModeInteractive)); cl.Ladder[1] != vPDFRnd2 {
		t.Fatalf("interactive ladder %v", cl.Ladder)
	}
	ci := backgroundInput(a, b, protocol.ModeBackground)
	cl := p.Classify(ci)
	if len(cl.Ladder) != 2 || cl.Ladder[0] != vPDFRnd1 || cl.Ladder[1] != vPDFRndSlow || cl.Advice != protocol.AdviceBackgroundViable {
		t.Fatalf("background ladder %v, advice %q", cl.Ladder, cl.Advice)
	}
	in := classified(roundInput(cl, a, b, 2, nil), ci)
	in.Policy.Budget = protocol.BackgroundBudget()
	in.Remaining, in.HandshakeMs = 58*time.Second, 60000
	r1 := p.Round(classified(roundInput(cl, a, b, 1, nil), ci))
	in.Prev = []api.RoundOutcome{outcomeOf(1, r1, api.RoundNoContact)}
	dec := p.Round(in)
	if dec.VariantName != "pdf_x_rnd_slow" || dec.Budget != protocol.BudgetBackground || dec.Window != 45*time.Second || !dec.Final {
		t.Fatalf("round 2 %q %s %v final %v", dec.VariantName, dec.Budget, dec.Window, dec.Final)
	}
	pdf, rnd := dec.Sides[0][0], dec.Sides[1][0]
	random := stageOf(pdf, protocol.StageRandom)
	if random == nil || random.Count != slowSpray || random.AtMs != slowStartMs || pdf.MaxNewPerSec != slowNPS || pdf.OpenPerSec != 0 {
		t.Fatalf("PDF side %s, nps %d", describe(pdf), pdf.MaxNewPerSec)
	}
	if rnd.Sockets != slowSockets || rnd.OpenPerSec != slowOpen || stageOf(rnd, protocol.StageDirect) == nil || rnd.MaxPackets != 3*slowSockets {
		t.Fatalf("RND side %s, open %d/s", describe(rnd), rnd.OpenPerSec)
	}
	for _, fs := range []protocol.FamilySide{pdf, rnd} {
		if stagePackets(fs) != int(fs.MaxPackets) {
			t.Errorf("MaxPackets differs from the stages: %s", describe(fs))
		}
	}
	// The PDF side's ports fit its rate in the window: 25 × (45 − 4) + 16.
	if int(random.Count) > slowNPS*(45000-slowStartMs)/1000+newTargetBurst {
		t.Errorf("spray %d beyond the rate", random.Count)
	}
	// The memory may start a Background session with the slow birthday: it
	// escapes the first round's cap.
	first := classified(roundInput(cl, a, b, 1, nil), ci)
	first.Policy.Budget, first.Remaining = protocol.BackgroundBudget(), 58*time.Second
	first.Order = []api.VariantID{vPDFRndSlow, vPDFRnd1}
	if d := p.Round(first); d.VariantName != "pdf_x_rnd_slow" || d.Budget != protocol.BudgetBackground || d.Sides[1][0].Sockets != slowSockets {
		t.Fatalf("slow first: %q %s %s", d.VariantName, d.Budget, describe(d.Sides[1][0]))
	}
	// Less time left: the window and the spray shrink together.
	in.Remaining = 20 * time.Second
	if short := p.Round(in); short.Window > 20*time.Second || mustStageOf(t, short.Sides[0][0], protocol.StageRandom).Count > uint16(slowNPS*20+newTargetBurst) {
		t.Fatalf("short round: window %v, %s", short.Window, describe(short.Sides[0][0]))
	}
}

func TestAdvice(t *testing.T) {
	f := protocol.FamilyUDP4
	var p DefaultPlanner
	for _, c := range []struct {
		name string
		a, b protocol.Traits
		mut  func(*api.ClassifyInput)
		want protocol.Advice
	}{
		{"pdf_x_rnd", pdfTraits(f), rndTraits(f), nil, protocol.AdviceBackgroundViable},
		{"pdf_x_rnd birthday off", pdfTraits(f), rndTraits(f), func(ci *api.ClassifyInput) { ci.Policy.Budget.Birthday = protocol.BirthdayOff }, ""},
		{"pdf_x_rnd unverified", pdfTraits(f), rndTraits(f), func(ci *api.ClassifyInput) {
			ci.Pair.Unverified = map[protocol.Family]bool{f: true}
		}, ""},
		{"rnd_x_rnd", rndTraits(f), withObserved(rndTraits(f), observedFor(f, 9)), nil, protocol.AdviceRelayOnly},
		{"pdf_x_seq", pdfTraits(f), seqTraits(f), nil, ""},
		{"pdf_x_pres", pdfTraits(f), presTraits(f), nil, ""},
		{"easy", openTraits(f), pdfTraits(f), nil, ""},
	} {
		ci := classifyInput(c.a, c.b)
		if c.mut != nil {
			c.mut(&ci)
		}
		if got := p.Classify(ci).Advice; got != c.want {
			t.Errorf("%s: advice %q, want %q", c.name, got, c.want)
		}
	}
}

func TestBackgroundOnly(t *testing.T) {
	scores := func(m map[api.VariantID]int) func(api.VariantID) int {
		return func(v api.VariantID) int { return m[v] }
	}
	for _, c := range []struct {
		name string
		m    map[api.VariantID]int
		want bool
	}{
		{"slow won, interactive failed", map[api.VariantID]int{vPDFRndSlow: 1, vPDFRnd1: -2, vPDFRnd2: -1}, true},
		{"slow never ran", map[api.VariantID]int{vPDFRnd1: -2}, false},
		{"interactive never ran", map[api.VariantID]int{vPDFRndSlow: 2}, false},
		{"an interactive rung won too", map[api.VariantID]int{vPDFRndSlow: 2, vPDFRnd1: -1, vPDFRnd2: 1}, false},
	} {
		if got := BackgroundOnly(scores(c.m)); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

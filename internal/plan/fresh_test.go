package plan

import (
	"net/netip"
	"slices"
	"testing"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// Fresh sockets.

func TestFreshPorts(t *testing.T) {
	a := FreshPorts([8]byte{1}, 24)
	if len(a) != 24 || !slices.Equal(a, FreshPorts([8]byte{1}, 24)) {
		t.Fatalf("not reproducible: %v", a)
	}
	if slices.Equal(a, FreshPorts([8]byte{2}, 24)) {
		t.Fatal("two seeds drew the same ports")
	}
	seen := map[uint16]bool{}
	for _, p := range a {
		if p < minFreshPort || SensitivePort(p) || seen[p] {
			t.Fatalf("port %d: below %d, sensitive or repeated (%v)", p, minFreshPort, a)
		}
		seen[p] = true
	}
	if MaxConsecutiveRun(a) > 3 || FreshPorts([8]byte{1}, 0) != nil {
		t.Fatal("run or empty draw")
	}
	if got := FreshPackets(protocol.Stage{Kind: protocol.StageFresh, Count: 7, Repeats: 3, Targets: make([]netip.AddrPort, 1)}); got != 21 {
		t.Fatalf("fresh packets %d, want 21", got)
	}
	if got := FreshPackets(protocol.Stage{Kind: protocol.StageFreshPeer, Count: 7, Repeats: 3}); got != 21 {
		t.Fatalf("fresh_peer packets %d, want 21", got)
	}
}

// PDF × a fresh-preserving side: the pres ladder, whose first round binds
// seven fresh sockets on the preserving side, aimed at the PDF side's
// primary endpoint, while the PDF side aims at their ports. Both primaries
// punch each other as plain hole punching would: one verified
// endpoint each here, so D(5).
func TestPDFPresRound(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), presTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	if cl.PairClass != PairPDFPres || cl.Ladder[0] != vPres1 {
		t.Fatalf("pair class %q, ladder %v", cl.PairClass, cl.Ladder)
	}
	dec := p.Round(roundInput(cl, a, b, 1, nil))
	if dec.VariantName != "pres_r1" || dec.Budget != protocol.BudgetBalanced {
		t.Fatalf("round 1 %q %s", dec.VariantName, dec.Budget)
	}
	pdf, pres := dec.Sides[0][0], dec.Sides[1][0]
	fresh := stageOf(pres, protocol.StageFresh)
	if fresh == nil || fresh.Count != 7 || fresh.Repeats != 3 || !slices.Equal(fresh.Targets, []netip.AddrPort{a.Observed}) || fresh.IP.IsValid() {
		t.Fatalf("preserving side %s", describe(pres))
	}
	if pres.Sockets != 1 || pres.MaxPackets != 5+21 || pres.MaxDistinctPorts != 1 {
		t.Fatalf("preserving side %s", describe(pres))
	}
	aim := stageOf(pdf, protocol.StageFreshPeer)
	if aim == nil || aim.Count != 7 || aim.IP != b.Observed.Addr() || pdf.MaxPackets != 5+21 || pdf.MaxDistinctPorts != 1+7 {
		t.Fatalf("PDF side %s", describe(pdf))
	}
	for _, fs := range []protocol.FamilySide{pdf, pres} {
		if d := stageOf(fs, protocol.StageDirect); d == nil || d.TTL != 0 || d.Repeats != 5 {
			t.Fatalf("no baseline: %s", describe(fs))
		}
	}
	for _, fs := range []protocol.FamilySide{pdf, pres} {
		checkSide(t, fs, dec.Budget, dec.Window)
	}
	// Round 2 is pres_r2 on heavy, 24 fresh sockets.
	dec2 := p.Round(roundInput(cl, a, b, 2, []api.RoundOutcome{outcomeOf(1, dec, api.RoundNoContact)}))
	if dec2.VariantName != "pres_r2" || mustStageOf(t, dec2.Sides[1][0], protocol.StageFresh).Count != 24 {
		t.Fatalf("round 2 %q %s", dec2.VariantName, describe(dec2.Sides[1][0]))
	}
}

// Two preserving sides pair their fresh sockets: each aims at the other's
// IP, socket k at port k.
func TestPresPresRound(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := presTraits(f), presTraits(f)
	b.Observed = observedFor(f, 8)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	if cl.PairClass != PairPresPres || cl.Reject != "" {
		t.Fatalf("pair class %q, reject %q", cl.PairClass, cl.Reject)
	}
	dec := p.Round(roundInput(cl, a, b, 1, nil))
	for r, peer := range []protocol.Traits{b, a} {
		fresh := stageOf(dec.Sides[r][0], protocol.StageFresh)
		if fresh == nil || fresh.IP != peer.Observed.Addr() || len(fresh.Targets) != 0 || fresh.Count != 7 {
			t.Fatalf("role %d: %s", r, describe(dec.Sides[r][0]))
		}
		checkSide(t, dec.Sides[r][0], dec.Budget, dec.Window)
	}
}

// The fresh ladder needs the evidence: Low confidence, a sequential peer
// or an unverified family keep the birthday ladder or drop the stage.
func TestPresNeedsEvidence(t *testing.T) {
	f := protocol.FamilyUDP4
	var p DefaultPlanner
	low := presTraits(f)
	low.PortAllocConf = protocol.ConfLow
	if cl := p.Classify(classifyInput(pdfTraits(f), low)); cl.PairClass != PairPDFRnd {
		t.Fatalf("Low confidence: %q", cl.PairClass)
	}
	medium := presTraits(f)
	medium.PortAllocConf = protocol.ConfMedium
	if cl := p.Classify(classifyInput(pdfTraits(f), medium)); cl.PairClass != PairPDFPres {
		t.Fatalf("Medium confidence: %q", cl.PairClass)
	}
	if cl := p.Classify(classifyInput(seqTraits(f), presTraits(f))); cl.PairClass != PairSeqRnd {
		t.Fatalf("SEQ × preserving: %q", cl.PairClass)
	}
	if cl := p.Classify(classifyInput(rndTraits(f), presTraits(f))); cl.PairClass != PairRndRnd {
		t.Fatalf("RND × preserving: %q", cl.PairClass)
	}
	// An unverified family runs Direct stages only: no fresh stage.
	a, b := pdfTraits(f), presTraits(f)
	ci := classifyInput(a, b)
	ci.Pair.Unverified = map[protocol.Family]bool{f: true}
	cl := p.Classify(ci)
	for r, sides := range p.Round(classified(roundInput(cl, a, b, 1, nil), ci)).Sides {
		for _, fs := range sides {
			if fs.FreshSockets() > 0 || stageOf(fs, protocol.StageFreshPeer) != nil {
				t.Fatalf("role %d: fresh stage in an unverified family: %s", r, describe(fs))
			}
		}
	}
}

// A small session socket budget cuts the fresh sockets, never the side's
// own below one, and MaxPackets stays what the stages expand to.
func TestPresSocketBudget(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), presTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 1, nil)
	in.Policy.Budget.MaxSockets = 4
	dec := p.Round(in)
	pres := dec.Sides[1][0]
	if pres.Sockets != 1 || pres.FreshSockets() != 3 || int(pres.MaxPackets) != stagePackets(pres) {
		t.Fatalf("preserving side %s", describe(pres))
	}
}

// stageOf returns fs's first stage of kind, or nil.
func stageOf(fs protocol.FamilySide, kind protocol.StageKind) *protocol.Stage {
	for i := range fs.Stages {
		if fs.Stages[i].Kind == kind {
			return &fs.Stages[i]
		}
	}
	return nil
}

// mustStageOf is stageOf for a stage the test requires.
func mustStageOf(t *testing.T, fs protocol.FamilySide, kind protocol.StageKind) *protocol.Stage {
	t.Helper()
	st := stageOf(fs, kind)
	if st == nil {
		t.Fatalf("no %v stage: %s", kind, describe(fs))
	}
	return st
}

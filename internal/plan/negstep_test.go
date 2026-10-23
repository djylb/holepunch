package plan

import (
	"slices"
	"testing"

	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/protocol"
)

// A sequential allocator that counts down: the
// predict window follows it below 1024 into 65535, the plans of PDF × SEQ
// and SEQ × SEQ aim downwards at it, and the paired windows of a downward
// and an upward side each walk their peer's direction.

func TestPredictWindowWrapsDown(t *testing.T) {
	got := predictPortValues(1026, []int16{-1}, 8, func(p uint16) bool { return avoidPort(p, nil) })
	if len(got) != 8 {
		t.Fatalf("%d ports, want 8: %v", len(got), got)
	}
	for _, p := range got {
		if p < minUserPort {
			t.Fatalf("port %d below %d: %v", p, minUserPort, got)
		}
	}
	for _, p := range []uint16{1025, 1024, 65535} {
		if !slices.Contains(got, p) {
			t.Errorf("window %v lacks %d", got, p)
		}
	}
	if d := netaddr.PortDelta(1024, 65535); d != -1 {
		t.Errorf("portDelta(1024, 65535) = %d, want -1", d)
	}
	if d := netaddr.PortDelta(65535, 1024); d != 1 {
		t.Errorf("portDelta(65535, 1024) = %d, want 1", d)
	}
	// A whole-range window ends once both directions met.
	if n := len(predictPortValues(30000, []int16{-1}, 70000, nil)); n != portRange {
		t.Errorf("whole-range window has %d ports, want %d", n, portRange)
	}
}

func downTraits(fam protocol.Family) protocol.Traits {
	t := seqTraits(fam)
	t.PortStep = -1
	return t
}

func TestPDFSeqDownwards(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), downTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	if cl.PairClass != PairPDFSeq {
		t.Fatalf("pair class %q", cl.PairClass)
	}
	dec := p.Round(roundInput(cl, a, b, 1, nil))
	var pred *protocol.Stage
	for i, st := range dec.Sides[0][0].Stages {
		if st.Kind == protocol.StagePredict {
			pred = &dec.Sides[0][0].Stages[i]
		}
	}
	if pred == nil || !slices.Equal(pred.Steps, []int16{-1}) || pred.Anchor != b.PortAnchor {
		t.Fatalf("PDF side predict %+v, want steps [-1] from anchor %d", pred, b.PortAnchor)
	}
	if c := dec.Families[0].Center[0]; c != b.PortAnchor-1 {
		t.Errorf("center %d, want %d", c, b.PortAnchor-1)
	}
	ports := ExpandPredict(pred.Anchor, pred.Steps, int(pred.Span), ExpandInput{Seed: [8]byte{7}})
	if !slices.Contains(ports, b.PortAnchor-1) || !slices.Contains(ports, b.PortAnchor-2) {
		t.Errorf("window %v misses the next two downward ports below %d", ports, b.PortAnchor)
	}
}

func TestSeqSeqMixedDirections(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := downTraits(f), seqTraits(f)
	b.Observed = observedFor(f, 6)
	b.PortAnchor = b.Observed.Port()
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	if cl.PairClass != PairSeqSeq {
		t.Fatalf("pair class %q", cl.PairClass)
	}
	dec := p.Round(roundInput(cl, a, b, 1, nil))
	for role, peer := range []protocol.Traits{b, a} {
		var pred *protocol.Stage
		for i, st := range dec.Sides[role][0].Stages {
			if st.Kind == protocol.StagePredict {
				pred = &dec.Sides[role][0].Stages[i]
			}
		}
		if pred == nil || !pred.Pair || len(pred.Steps) == 0 || pred.Steps[0] != peer.PortStep {
			t.Fatalf("role %d: predict %+v, want a paired stage with the peer's step %d", role, pred, peer.PortStep)
		}
		ports := ExpandPaired(pred.Anchor, pred.Steps, int(pred.Span), ExpandInput{PairSeed: [8]byte{5}, Responder: role == 1})
		for _, q := range ports {
			if !ahead(q, pred.Anchor, int(peer.PortStep)) {
				t.Fatalf("role %d: port %d is not ahead of anchor %d in the peer's direction %d", role, q, pred.Anchor, peer.PortStep)
			}
		}
	}
}

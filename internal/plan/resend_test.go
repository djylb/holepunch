package plan

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// directTargets returns the targets of a side's Direct stages.
func directTargetsOf(fs protocol.FamilySide) []netip.AddrPort {
	var out []netip.AddrPort
	for _, st := range fs.Stages {
		if st.Kind == protocol.StageDirect {
			out = append(out, st.Targets...)
		}
	}
	return out
}

// TestPDFSeqResend: from the second round of pdf_x_seq on, the PDF
// side first sends the ports around the previous round's centre once more —
// at most four, one packet each, in allocation steps of the SEQ side,
// filtered like any target — in a Direct stage of its grant, so that the
// predict stage's exclusion of sent ports cannot leave the SEQ side's live
// mapping out. Not in the first round, not after a rescue round, not
// without the previous centre.
func TestPDFSeqResend(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	if cl.PairClass != PairPDFSeq || cl.SideA != protocol.RoleInitiator {
		t.Fatalf("pair %s, A %s", cl.PairClass, cl.SideA)
	}
	dec1 := p.Round(roundInput(cl, a, b, 1, nil))
	c := dec1.Families[0].Center[0]
	if c != b.PortAnchor+1 {
		t.Fatalf("round 1 centre %d, want %d", c, b.PortAnchor+1)
	}
	if got := directTargetsOf(dec1.Sides[0][0]); len(got) != 1 {
		t.Fatalf("round 1 Direct targets %v: no resend in the first round", got)
	}
	ip := b.Observed.Addr()
	at := func(ports ...uint16) []netip.AddrPort {
		var out []netip.AddrPort
		for _, p := range ports {
			out = append(out, netip.AddrPortFrom(ip, p))
		}
		return out
	}
	prev := []RoundOutcome{outcomeOf(1, dec1, RCNoContact)}
	dec2 := p.Round(roundInput(cl, a, b, 2, prev))
	if got, want := directTargetsOf(dec2.Sides[0][0]), at(c, c+1, c-1, c+2); !slices.Equal(got, want) {
		t.Fatalf("round 2 resend %v, want %v", got, want)
	}
	assertEmittable(t, dec2)
	// The resend is a Direct stage: the client's exclusion of sent ports
	// does not touch it.
	for _, st := range dec2.Sides[0][0].Stages {
		if st.Kind == protocol.StageDirect && (st.Repeats != 1 || len(ExpandStage(st, ExpandInput{Exclude: func(uint16) bool { return true }})) != 4) {
			t.Fatalf("resend stage %+v", st)
		}
	}

	// A step of 2 resends in steps of 2; a sensitive port is left out.
	b2 := b
	b2.PortStep, b2.PortAnchor = 2, 4495 // centre 4497: 4499, 4495, 4501 around it, 4500 never
	cl2 := p.Classify(classifyInput(a, b2))
	d1 := p.Round(roundInput(cl2, a, b2, 1, nil))
	d2 := p.Round(roundInput(cl2, a, b2, 2, []RoundOutcome{outcomeOf(1, d1, RCNoContact)}))
	if got, want := directTargetsOf(d2.Sides[0][0]), at(4497, 4499, 4495, 4501); !slices.Equal(got, want) {
		t.Fatalf("step 2: resend %v, want %v", got, want)
	}
	b2.PortStep, b2.PortAnchor = 1, 4499 // centre 4500 is sensitive (IPsec NAT-T)
	cl2 = p.Classify(classifyInput(a, b2))
	d1 = p.Round(roundInput(cl2, a, b2, 1, nil))
	d2 = p.Round(roundInput(cl2, a, b2, 2, []RoundOutcome{outcomeOf(1, d1, RCNoContact)}))
	if got, want := directTargetsOf(d2.Sides[0][0]), at(4501, 4499, 4502); !slices.Equal(got, want) {
		t.Fatalf("sensitive centre: resend %v, want %v", got, want)
	}

	// After a rescue round, or without the previous round's families, the
	// mapping's state is unknown: nothing is resent.
	rescue := RoundOutcome{Round: 2, Variant: vRescue, Class: RCOneWay, Rescue: true, Budget: protocol.BudgetLight,
		Families: []FamilyRound{{Family: f, Variant: vRescue, Center: dec1.Families[0].Center}}}
	in := roundInput(cl, a, b, 3, append(slices.Clone(prev), rescue))
	in.RescueUsed = true
	if got := directTargetsOf(p.Round(in).Sides[0][0]); len(got) != 0 {
		t.Errorf("after a rescue round: resend %v", got)
	}
	bare := []RoundOutcome{{Round: 1, Variant: dec1.Variant, Class: RCNoContact, Budget: dec1.Budget}}
	if got := directTargetsOf(p.Round(roundInput(cl, a, b, 2, bare)).Sides[0][0]); len(got) != 0 {
		t.Errorf("without the previous centre: resend %v", got)
	}
}

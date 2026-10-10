package plan

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// mediumEIM is a port-restricted cone that natprobe measured from one
// server IP: EIM at Medium confidence, its port kept (the usual e2e side).
func mediumEIM(n int) protocol.Traits {
	t := pdfTraits(protocol.FamilyUDP4)
	t.MappingConf, t.PortAllocConf = protocol.ConfMedium, protocol.ConfMedium
	t.Observed = observedFor(protocol.FamilyUDP4, 10+n)
	return t
}

// runRounds plans n rounds, each ended with the given per-family contact:
// class NoContact rounds carry FamilyRound.NoContact, the way the
// coordinator fills the outcome.
func runRounds(t *testing.T, cl Classification, a, b protocol.Traits, n int, class RoundClass) []RoundDecision {
	t.Helper()
	var prev []RoundOutcome
	var out []RoundDecision
	for round := 1; round <= n; round++ {
		in := roundInput(cl, a, b, round, prev)
		in.MaxRounds = 6
		dec := DefaultPlanner{}.Round(in)
		out = append(out, dec)
		if dec.Stop != "" {
			break
		}
		o := RoundOutcome{Round: round, Variant: dec.Variant, Class: class, Budget: dec.Budget, Families: slices.Clone(dec.Families)}
		for i := range o.Families {
			o.Families[i].NoContact = class == RCNoContact
		}
		prev = append(prev, o)
	}
	return out
}

func variantNames(decs []RoundDecision) []string {
	var out []string
	for _, d := range decs {
		out = append(out, d.VariantName)
	}
	return out
}

// TestNoContactEscalation checks the no-contact escalation: an easy pair whose
// sides natprobe saw as EIM at Medium confidence runs two easy rounds; when
// neither found any contact, the third plans the doubtful sides as endpoint
// dependent — both kept their port, so fresh sockets pair up (pres_x_pres) —
// with the plain-punching baseline of a first round, and the later rounds go on
// along the new ladder.
func TestNoContactEscalation(t *testing.T) {
	a, b := mediumEIM(1), mediumEIM(2)
	cl := DefaultPlanner{}.Classify(classifyInput(a, b))
	if cl.PairClass != PairEasy {
		t.Fatalf("class %s", cl.PairClass)
	}
	decs := runRounds(t, cl, a, b, 4, RCNoContact)
	got := variantNames(decs)
	if want := []string{"easy_r1_direct", "easy_r2_ttl", "pres_r1", "pres_r2"}; !slices.Equal(got, want) {
		t.Fatalf("rounds %v, want %v", got, want)
	}
	for r := range 2 {
		fs := decs[2].Sides[r][0]
		if !hasBaseline(fs, observedFor(protocol.FamilyUDP4, 12-r)) {
			t.Errorf("role %d: the first escalated round carries no baseline Direct: %+v", r, fs.Stages)
		}
		if !slices.ContainsFunc(fs.Stages, func(st protocol.Stage) bool { return st.Kind == protocol.StageFresh }) {
			t.Errorf("role %d: no fresh sockets in %+v", r, fs.Stages)
		}
	}

	// Rounds with contact, or a High conclusion, change nothing.
	if got := variantNames(runRounds(t, cl, a, b, 3, RCOneWay)); slices.Contains(got, "pres_r1") {
		t.Errorf("escalated after contact: %v", got)
	}
	hi, hj := pdfTraits(protocol.FamilyUDP4), mediumEIM(2)
	hj.MappingConf = protocol.ConfHigh
	clHigh := DefaultPlanner{}.Classify(classifyInput(hi, hj))
	if got := variantNames(runRounds(t, clHigh, hi, hj, 3, RCNoContact)); got[2] != "easy_r3_ttl" {
		t.Errorf("High sides escalated: %v", got)
	}
}

// hasBaseline reports whether fs has a normal-TTL Direct stage toward to.
func hasBaseline(fs protocol.FamilySide, to netip.AddrPort) bool {
	return slices.ContainsFunc(fs.Stages, func(st protocol.Stage) bool {
		return st.Kind == protocol.StageDirect && st.TTL == 0 && slices.Contains(st.Targets, to)
	})
}

// TestEscalatedSides checks which sides an escalation plans as endpoint
// dependent: every doubtful side when all of them kept their port, else
// the single most doubtful one without a kept port; High and NoNAT sides
// never.
func TestEscalatedSides(t *testing.T) {
	pres, rnd := mediumEIM(1), mediumEIM(2)
	rnd.PortAlloc, rnd.PortAllocConf = protocol.AllocUnknown, protocol.ConfNone
	low := rnd
	low.MappingConf = protocol.ConfLow
	high := pdfTraits(protocol.FamilyUDP4)
	nonat := protocol.Traits{NoNAT: protocol.TriTrue, Mapping: protocol.MapEIM, MappingConf: protocol.ConfMedium, Samples: 3}
	contra := rnd
	contra.PathDependent = true
	for _, c := range []struct {
		name string
		a, b protocol.Traits
		want [2]bool
	}{
		{"both kept", pres, pres, [2]bool{true, true}},
		{"one kept", pres, rnd, [2]bool{false, true}},
		{"neither, lower confidence", rnd, low, [2]bool{false, true}},
		{"neither, STUN contradicts", contra, low, [2]bool{true, false}},
		{"high", high, high, [2]bool{}},
		{"no NAT", nonat, high, [2]bool{}},
	} {
		if got := escalatedSides([2]protocol.Traits{c.a, c.b}, [2]bool{}); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestEscalationOnlyEasy checks that a family whose other side is endpoint
// dependent keeps its ladder after rounds without contact: its silence has
// that side to explain it.
func TestEscalationOnlyEasy(t *testing.T) {
	a, b := mediumEIM(1), seqTraits(protocol.FamilyUDP4)
	cl := DefaultPlanner{}.Classify(classifyInput(a, b))
	got := variantNames(runRounds(t, cl, a, b, 3, RCNoContact))
	if !slices.Equal(got, []string{"pdf_x_seq_r1", "pdf_x_seq_r2", "pdf_x_seq_r3"}) {
		t.Fatalf("rounds %v", got)
	}
}

// TestPathDependentPlannedEDM checks path-dependent mappings in the planner: a
// side whose EIM a STUN server contradicted is planned as random from the
// first round, whatever allocation natprobe saw on its own path; the views
// the round builds from carry the same traits; and the STUN mapping on the
// verified IP is a Direct target of the peer next to the server's.
func TestPathDependentPlannedEDM(t *testing.T) {
	a, b := mediumEIM(1), pdfTraits(protocol.FamilyUDP4)
	a.PathDependent = true
	in := classifyInput(a, b)
	stun := netip.AddrPortFrom(a.Observed.Addr(), a.Observed.Port()+7)
	in.Initiator.Families[0].Endpoints = append(in.Initiator.Families[0].Endpoints,
		protocol.Endpoint{Addr: stun, Source: protocol.EndpointSTUN},
		protocol.Endpoint{Addr: netip.MustParseAddrPort("198.18.0.1:5000"), Source: protocol.EndpointSTUN})
	cl := DefaultPlanner{}.Classify(in)
	if cl.PairClass != PairPDFRnd || cl.SideA != protocol.RoleResponder {
		t.Fatalf("class %s, A side %s; want %s with the initiator as the random side", cl.PairClass, cl.SideA, PairPDFRnd)
	}
	ri := roundInput(cl, a, b, 1, nil)
	ri.Views[0] = in.Initiator
	dec := DefaultPlanner{}.Round(ri)
	if dec.Stop != "" {
		t.Fatalf("stop %s", dec.Stop)
	}
	var direct []netip.AddrPort
	for _, st := range dec.Sides[1][0].Stages {
		if st.Kind == protocol.StageDirect {
			direct = append(direct, st.Targets...)
		}
	}
	if !slices.Contains(direct, a.Observed) || !slices.Contains(direct, stun) || slices.Contains(direct, netip.MustParseAddrPort("198.18.0.1:5000")) {
		t.Fatalf("responder's Direct targets %v", direct)
	}
	if slices.ContainsFunc(dec.Sides[0][0].Stages, func(st protocol.Stage) bool { return st.Kind == protocol.StageFresh }) {
		t.Fatalf("the path-dependent side binds fresh sockets: %+v", dec.Sides[0][0].Stages)
	}
	// Without a kept port the side is random too.
	a.PortAlloc, a.PortAllocConf = protocol.AllocUnknown, protocol.ConfNone
	if cl := (DefaultPlanner{}).Classify(classifyInput(a, b)); cl.PairClass != PairPDFRnd {
		t.Fatalf("class %s, want %s", cl.PairClass, PairPDFRnd)
	}
	// A High conclusion contradicted by STUN is not trusted either.
	h := pdfTraits(protocol.FamilyUDP4)
	h.PathDependent = true
	if cl := (DefaultPlanner{}).Classify(classifyInput(h, b)); cl.PairClass != PairPDFRnd {
		t.Fatalf("class %s, want %s", cl.PairClass, PairPDFRnd)
	}
	// Two silent rounds without STUN evidence still read a kept port as
	// PreserveFresh.
	if got := asEDM(mediumEIM(1)); got.PortAlloc != protocol.AllocPreserveFresh {
		t.Fatalf("escalated kept port: %s", got.PortAlloc)
	}
}

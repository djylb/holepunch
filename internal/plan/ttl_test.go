package plan

import (
	"net/netip"
	"testing"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// Every stage of every template — Direct, predict and random alike —
// reaches the wire with the template's ttl; with low TTL disabled none has
// one. The spray stages used to lose it (sprayReq carried no ttl). The
// templates are built as a second round runs them: a first round adds the
// plain-punching baseline (TestRound1Baseline).
func TestTemplateTTLKept(t *testing.T) {
	f := protocol.FamilyUDP4
	off := false
	// A sequential peer gives every stage what it needs: a verified Direct
	// target, a public IP to spray at and an anchor to predict from.
	peer := seqTraits(f)
	fp := familyPlan{Family: f, SideA: protocol.RoleInitiator, MaxTargets: maxDirectTargets}
	lim, _ := protocol.BudgetExtreme.Limits()
	sessB := protocol.TightenBudget(protocol.CeilingBudget())
	for _, lowTTL := range []bool{true, false} {
		in := roundInput(api.Classification{}, peer, peer, 2, nil)
		if !lowTTL {
			in.Policy.LowTTL = &off
		}
		withTTL := 0
		for id := VInvalid + 1; id < numVariants; id++ {
			vr, _ := variantOf(id)
			for role := range 2 {
				tmpl := roleTemplate(vr, fp.SideA, role)
				sb := buildSideTemplate(input{RoundInput: in}, fp, tmpl, vr, true, role, false, false)
				fs := emitFamilySide(sb, f, lim, sessB, int(tmpl.sockets), 0, 1<<20, 1<<20)
				for _, kind := range []protocol.StageKind{protocol.StageDirect, protocol.StagePredict, protocol.StageRandom} {
					var want []uint8
					for _, st := range tmpl.stages {
						if st.kind == kind {
							want = append(want, st.ttl)
						}
					}
					var got []uint8
					for _, st := range fs.Stages {
						if st.Kind == kind {
							got = append(got, st.TTL)
						}
					}
					if len(got) != len(want) {
						t.Fatalf("%s side %d: %d %s stages emitted, template has %d", vr.name, role, len(got), kind, len(want))
					}
					for i := range want {
						w := want[i]
						if !lowTTL {
							w = 0
						}
						if got[i] != w {
							t.Errorf("low TTL %v: %s side %d %s stage %d: ttl %d, template %d", lowTTL, vr.name, role, kind, i, got[i], want[i])
						}
						if got[i] != 0 {
							withTTL++
						}
					}
				}
			}
		}
		if lowTTL && withTTL == 0 {
			t.Fatal("setup: no template stage carries a ttl")
		}
	}
}

// The same through Round: seq_x_seq_r2's receiver predicts at ttl 4,
// and the rescue round's silent receiver keeps its template's ttl.
func TestSprayTTLOnWire(t *testing.T) {
	var p DefaultPlanner
	f := protocol.FamilyUDP4
	a, b := seqTraits(f), seqTraits(f)
	b.Observed = observedFor(f, 5)
	b.PortAnchor = b.Observed.Port()
	cl := p.Classify(classifyInput(a, b))
	if cl.PairClass != PairSeqSeq {
		t.Fatalf("pair class %q", cl.PairClass)
	}
	decs := chain(p, cl, a, b, 2, false, api.RoundNoContact, nil)
	if len(decs) != 2 || decs[1].Variant != vSeqSeq2 {
		t.Fatalf("round 2 is not seq_x_seq_r2: %+v", decs)
	}
	vr, _ := variantOf(vSeqSeq2)
	for role := range 2 {
		tmpl := roleTemplate(vr, cl.SideA, role)
		side := decs[1].Sides[role][0]
		if len(side.Stages) != 1 || side.Stages[0].Kind != protocol.StagePredict || side.Stages[0].TTL != tmpl.stages[0].ttl {
			t.Fatalf("side %d stages %+v, template ttl %d", role, side.Stages, tmpl.stages[0].ttl)
		}
	}

	// The rescue round: the silent side is the template's low-TTL receiver.
	in := roundInput(cl, a, b, 2, []api.RoundOutcome{{Round: 1, Variant: cl.Ladder[0], Class: api.RoundOneWay, Budget: protocol.BudgetBalanced}})
	in.Evidence.SeenFrom[0] = []netip.AddrPort{b.Observed}
	dec := p.Round(in)
	rv, _ := variantOf(vRescue)
	if !dec.Rescue || dec.Sides[0][0].Stages[0].TTL != rv.a.stages[0].ttl || dec.Sides[1][0].Stages[0].TTL != rv.b.stages[0].ttl || rv.b.stages[0].ttl == 0 {
		t.Fatalf("rescue ttl: %+v", dec.Sides)
	}
}

package plan

import (
	"net/netip"
	"testing"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// measured is natprobe's raw view of a side: its traits with the port
// allocation as natprobe measured it.
func measured(tr protocol.Traits, alloc protocol.PortAlloc, conf protocol.Conf) protocol.PeerView {
	tr.PortAlloc, tr.PortAllocConf = alloc, conf
	return view(tr)
}

// RND×RND whose port allocation natprobe measured as Random
// with High confidence on both sides ends at summary time, before a single
// punch, when no rung after the two cheap rounds can run (the default
// configuration: conservative tier, no two-sided birthday).
func TestSummaryVerdictMeasuredRandom(t *testing.T) {
	var p DefaultPlanner
	f := protocol.FamilyUDP4
	in := classifyInput(rndTraits(f), rndTraits(f))
	in.Measured = [2]protocol.PeerView{measured(rndTraits(f), protocol.AllocRandom, protocol.ConfHigh), measured(rndTraits(f), protocol.AllocRandom, protocol.ConfHigh)}
	cl := p.Classify(in)
	if cl.Reject != protocol.ReasonHardSymmetricRandom || cl.PairClass != PairRndRnd {
		t.Fatalf("reject %q pair class %q", cl.Reject, cl.PairClass)
	}

	// max_rounds 2 leaves no later rung even at the aggressive tier
	in.Policy.Budget.Birthday = protocol.BirthdayAggressive
	in.Timeouts.HandshakeTimeoutMs = 30000
	in.Timeouts.MaxRounds = CheapRounds
	if cl := p.Classify(in); cl.Reject != protocol.ReasonHardSymmetricRandom {
		t.Fatalf("max_rounds 2: reject %q", cl.Reject)
	}
	// both families hopeless: still a verdict
	in = classifyInput(rndTraits(f), rndTraits(f))
	in.Initiator, in.Responder = dual(rndTraits(f), rndTraits(protocol.FamilyUDP6)), dual(rndTraits(f), rndTraits(protocol.FamilyUDP6))
	in.Measured = [2]protocol.PeerView{in.Initiator, in.Responder}
	if cl := p.Classify(in); cl.Reject != protocol.ReasonHardSymmetricRandom || len(cl.Families) != 2 {
		t.Fatalf("dual-stack, both hopeless: reject %q families %v", cl.Reject, cl.Families)
	}
}

// Anything short of the server's high-confidence measurement on both
// sides runs the ladder's two cheap rounds, and the evidence ends it after
// them: hard_symmetric_random, with at most those rounds' grants sent.
func TestSummaryVerdictNeedsMeasuredHigh(t *testing.T) {
	var p DefaultPlanner
	f := protocol.FamilyUDP4
	high := measured(rndTraits(f), protocol.AllocRandom, protocol.ConfHigh)
	cases := []struct {
		name string
		mut  func(*api.ClassifyInput)
	}{
		{"one side medium", func(in *api.ClassifyInput) {
			in.Measured[1] = measured(rndTraits(f), protocol.AllocRandom, protocol.ConfMedium)
		}},
		{"one side a pool", func(in *api.ClassifyInput) {
			in.Measured[0] = measured(rndTraits(f), protocol.AllocPool, protocol.ConfLow)
		}},
		// the views say Random/High, but nobody measured it: self-reported
		// traits (NoObserver mode, an unobserved family) or a memory
		{"not measured", func(in *api.ClassifyInput) { in.Measured = [2]protocol.PeerView{} }},
		{"one side not measured", func(in *api.ClassifyInput) { in.Measured[1] = protocol.PeerView{} }},
		{"measured without samples", func(in *api.ClassifyInput) {
			tr := rndTraits(f)
			tr.Samples = 0
			in.Measured[0] = view(tr)
		}},
		// the two-sided birthday can still run: aggressive tier and a 30 s handshake
		{"two-sided birthday reachable", func(in *api.ClassifyInput) {
			in.Policy.Budget.Birthday = protocol.BirthdayAggressive
			in.Timeouts.HandshakeTimeoutMs = 30000
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := classifyInput(rndTraits(f), rndTraits(f))
			in.Measured = [2]protocol.PeerView{high, high}
			c.mut(&in)
			cl := p.Classify(in)
			if cl.Reject != "" || cl.PairClass != PairRndRnd {
				t.Fatalf("reject %q pair class %q", cl.Reject, cl.PairClass)
			}
			if c.name == "two-sided birthday reachable" {
				return // the ladder goes on to the two-sided birthday when the round input allows extreme
			}
			decs := chain(p, cl, rndTraits(f), rndTraits(f), 6, false, api.RoundNoContact, nil)
			if len(decs) != CheapRounds || !decs[CheapRounds-1].Final {
				t.Fatalf("ladder %v", decs)
			}
			var prev []api.RoundOutcome
			for i, d := range decs {
				prev = append(prev, api.RoundOutcome{Round: i + 1, Variant: d.Variant, Class: api.RoundNoContact, Budget: d.Budget})
			}
			in3 := roundInput(cl, rndTraits(f), rndTraits(f), CheapRounds+1, prev)
			in3.Evidence.Sent, in3.Evidence.Fired = [2]uint32{1, 1}, [2]bool{true, true}
			if d := p.Round(in3); d.Stop != protocol.ReasonHardSymmetricRandom {
				t.Fatalf("after the cheap rounds: stop %q", d.Stop)
			}
			for _, d := range decs {
				lim, _ := d.Budget.Limits()
				for role := range 2 {
					for _, s := range d.Sides[role] {
						if s.MaxPackets == 0 || s.MaxPackets > lim.MaxPackets {
							t.Fatalf("%s side %d max packets %d (class %s)", d.VariantName, role, s.MaxPackets, d.Budget)
						}
					}
				}
			}
		})
	}

	// The views decide the ladder: a memory that made one side sequential
	// leaves the pair seq_x_rnd, which is no RND×RND verdict.
	in := classifyInput(seqTraits(f), rndTraits(f))
	in.Measured = [2]protocol.PeerView{high, high}
	if cl := p.Classify(in); cl.Reject != "" {
		t.Fatalf("seq_x_rnd rejected: %q", cl.Reject)
	}
	// A dual-stack session with one hopeless family punches in the other.
	in = classifyInput(rndTraits(f), rndTraits(f))
	in.Initiator, in.Responder = dual(rndTraits(f), openTraits(protocol.FamilyUDP6)), dual(rndTraits(f), openTraits(protocol.FamilyUDP6))
	in.Measured = [2]protocol.PeerView{dual(rndTraits(f), openTraits(protocol.FamilyUDP6)), dual(rndTraits(f), openTraits(protocol.FamilyUDP6))}
	if cl := p.Classify(in); cl.Reject != "" {
		t.Fatalf("dual-stack with an open v6 rejected: %q", cl.Reject)
	}
}

// natprobe measured one side SEQ with APDF filtering and the other
// Random, both at High confidence. The ladder runs its two cheap rounds;
// when they found no contact it ends with hard_symmetric_random instead of
// the third rung. The third rung runs when the SEQ side's filtering admits
// more than the endpoint it opened (ADF), when a measurement is below High
// (here: coming from the client, not natprobe), or after contact.
func TestSeqRndVerdict(t *testing.T) {
	var p DefaultPlanner
	f := protocol.FamilyUDP4
	seq, rnd := seqTraits(f), rndTraits(f)
	run := func(seq protocol.Traits, measuredOK bool, contact bool) api.RoundDecision {
		in := classifyInput(seq, rnd)
		if measuredOK {
			in.Measured = [2]protocol.PeerView{view(seq), view(rnd)}
		}
		cl := p.Classify(in)
		if cl.PairClass != PairSeqRnd || cl.Reject != "" {
			t.Fatalf("pair %s reject %q", cl.PairClass, cl.Reject)
		}
		ledger := mappingLedger{}
		var prev []api.RoundOutcome
		for round := 1; round <= 2; round++ {
			dec := p.Round(classified(roundInput(cl, seq, rnd, round, prev), in))
			if dec.Stop != "" {
				t.Fatalf("round %d stopped: %s", round, dec.Stop)
			}
			prev = append(prev, ledger.outcome(round, dec, api.RoundNoContact))
		}
		in3 := classified(roundInput(cl, seq, rnd, 3, prev), in)
		in3.Evidence = api.Evidence{Fired: [2]bool{true, true}, Sent: [2]uint32{20, 20}}
		if contact {
			in3.Evidence.SeenFrom[0] = []netip.AddrPort{rnd.Observed}
			in3.RescueUsed = true
		}
		return p.Round(in3)
	}
	if dec := run(seq, true, false); dec.Stop != protocol.ReasonHardSymmetricRandom {
		t.Fatalf("SEQ(APDF) × RND measured High: round 3 %q stop %q, want hard_symmetric_random", dec.VariantName, dec.Stop)
	}
	adf := seq
	adf.Filtering = protocol.FiltADF
	for name, dec := range map[string]api.RoundDecision{
		"SEQ filtering ADF":     run(adf, true, false),
		"not measured":          run(seq, false, false),
		"contact in the rounds": run(seq, true, true),
	} {
		if dec.Stop != "" || dec.Variant != vSeqRnd3 {
			t.Errorf("%s: round 3 %q stop %q, want seq_x_rnd_r3", name, dec.VariantName, dec.Stop)
		}
	}
	if !SeqRndVerdict([2]protocol.PeerView{view(rnd), view(seq)}, f) {
		t.Error("the verdict is the same with the roles swapped")
	}
	medium := seq
	medium.FilteringConf = protocol.ConfMedium
	if SeqRndVerdict([2]protocol.PeerView{view(medium), view(rnd)}, f) {
		t.Error("a verdict on APDF at Medium confidence")
	}
}

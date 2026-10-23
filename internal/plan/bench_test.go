package plan

import (
	"testing"
	"time"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

func BenchmarkClassifyRound(b *testing.B) {
	f := protocol.FamilyUDP4
	a, peer := pdfTraits(f), rndTraits(f)
	var p DefaultPlanner
	in := classifyInput(a, peer)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cl := p.Classify(in)
		p.Round(roundInput(cl, a, peer, 2, []api.RoundOutcome{{Round: 1, Variant: cl.Ladder[0], Class: api.RoundNoContact, Budget: protocol.BudgetBalanced}}))
	}
}

func BenchmarkExpandRandom(b *testing.B) {
	in := ExpandInput{Seed: [8]byte{1, 2, 3}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ExpandRandom(0, 0, 368, in)
	}
}

// A paired window of the first rung: the pair orders' local search
// (coverShifts) runs on every seed.
func BenchmarkExpandPaired16(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		in := ExpandInput{PairSeed: [8]byte{byte(i), byte(i >> 8), byte(i >> 16)}}
		ExpandPaired(40000, []int16{1}, minPairSpan, in)
	}
}

// The random-stage capacity is constant time.
func BenchmarkRangeCapacity(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		RangeCapacity(0, 0, nil)
	}
}

// Classify and a one-sided birthday round of a dual-stack session with the endpoint sets
// natprobe hands over (target: ≤ 100 µs).
func BenchmarkClassifyRoundDualStack(b *testing.B) {
	a4, b4 := pdfTraits(protocol.FamilyUDP4), rndTraits(protocol.FamilyUDP4)
	a6, b6 := pdfTraits(protocol.FamilyUDP6), seqTraits(protocol.FamilyUDP6)
	views := [2]protocol.PeerView{
		{Families: append(siblingView(a6).Families, siblingView(a4).Families...)},
		{Families: append(apdmView(b6).Families, apdmView(b4).Families...)},
	}
	var p DefaultPlanner
	ci := api.ClassifyInput{Initiator: views[0], Responder: views[1], Policy: protocol.Policy{Budget: protocol.DefaultBudget()}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cl := p.Classify(ci)
		in := roundInput(cl, a4, b4, 2, []api.RoundOutcome{{Round: 1, Variant: cl.Ladder[0], Class: api.RoundNoContact, Budget: protocol.BudgetBalanced}})
		in.Views = views
		in.FireAt = 3 * time.Second
		p.Round(in)
	}
}

// Classify and round 2 in the shared-network situations: an unverified IPv6
// family beside a verified IPv4 one, and one shared LAN.
func BenchmarkClassifyRoundTopology(b *testing.B) {
	for _, name := range []string{"unverified_v6/pdf_x_rnd", "same_lan/pdf_x_seq"} {
		var c admissionCase
		for _, x := range admissionCases() {
			if x.name == name {
				c = x
			}
		}
		b.Run(name, func(b *testing.B) {
			var p DefaultPlanner
			ci := api.ClassifyInput{Initiator: c.views[0], Responder: c.views[1], Pair: c.pair, Policy: protocol.Policy{Budget: protocol.DefaultBudget()}}
			b.ReportAllocs()
			for b.Loop() {
				cl := p.Classify(ci)
				in := roundInput(cl, protocol.Traits{}, protocol.Traits{}, 2, []api.RoundOutcome{{Round: 1, Variant: cl.Ladder[0], Class: api.RoundNoContact,
					Budget: protocol.BudgetBalanced}})
				in.Views, in.Pair = c.views, c.pair
				p.Round(in)
			}
		})
	}
}

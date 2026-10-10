package plan

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Trait builders for each category. observedFor gives each a distinct
// verified public endpoint.

func observedFor(fam protocol.Family, n int) netip.AddrPort {
	if fam == protocol.FamilyUDP6 {
		return netip.MustParseAddrPort(fmt.Sprintf("[2001:db8::%d]:%d", n, 40000+n))
	}
	return netip.MustParseAddrPort(fmt.Sprintf("203.0.113.%d:%d", n, 40000+n))
}

func openTraits(fam protocol.Family) protocol.Traits {
	return protocol.Traits{
		Family: fam, Mapping: protocol.MapEIM, MappingConf: protocol.ConfHigh,
		Filtering: protocol.FiltEIF, FilteringConf: protocol.ConfHigh,
		PortAlloc: protocol.AllocPreserving, Observed: observedFor(fam, 1), Samples: 3,
	}
}

func pdfTraits(fam protocol.Family) protocol.Traits {
	t := openTraits(fam)
	t.Filtering = protocol.FiltPDF
	t.Observed = observedFor(fam, 2)
	return t
}

func seqTraits(fam protocol.Family) protocol.Traits {
	ob := observedFor(fam, 3)
	return protocol.Traits{
		Family: fam, Mapping: protocol.MapAPDM, MappingConf: protocol.ConfHigh,
		Filtering: protocol.FiltPDF, FilteringConf: protocol.ConfHigh,
		PortAlloc: protocol.AllocSequential, PortAllocConf: protocol.ConfHigh,
		PortStep: 1, PortAnchor: ob.Port(), Observed: ob, Samples: 4,
	}
}

func rndTraits(fam protocol.Family) protocol.Traits {
	return protocol.Traits{
		Family: fam, Mapping: protocol.MapAPDM, MappingConf: protocol.ConfHigh,
		Filtering: protocol.FiltPDF, FilteringConf: protocol.ConfHigh,
		PortAlloc: protocol.AllocRandom, PortAllocConf: protocol.ConfHigh,
		Observed: observedFor(fam, 4), Samples: 4,
	}
}

// presTraits is an APDM side whose fresh sockets keep their local port, found
// on both probing sockets.
func presTraits(fam protocol.Family) protocol.Traits {
	t := rndTraits(fam)
	t.PortAlloc, t.FirstPreserved, t.Observed = protocol.AllocPreserveFresh, true, observedFor(fam, 7)
	return t
}

// view builds a PeerView with one family whose verified endpoint equals the
// traits' observed address.
func view(tr protocol.Traits) protocol.PeerView {
	return protocol.PeerView{Families: []protocol.FamilyView{{
		Family: tr.Family,
		Traits: tr,
		Endpoints: []protocol.Endpoint{{
			Addr: tr.Observed, Source: protocol.EndpointServer, Verified: true,
		}},
	}}}
}

// apdmView is what natprobe's Merge hands over for a typical APDM peer
// (nat.ObsTable.Endpoints, internal/nat TestEndpointsVerifiedOnly): one
// verified endpoint per observer mapping of the primary socket (three
// observers) and of the second socket (three more), all on one public IP.
func apdmView(tr protocol.Traits) protocol.PeerView {
	v := protocol.PeerView{Families: []protocol.FamilyView{{Family: tr.Family, Traits: tr}}}
	ip := tr.Observed.Addr()
	primary, second := uint8(0), uint8(1)
	if tr.Family == protocol.FamilyUDP6 {
		primary, second = 0x80, 0x81
	}
	for i := range 3 {
		v.Families[0].Endpoints = append(v.Families[0].Endpoints, protocol.Endpoint{Addr: netip.AddrPortFrom(ip, tr.Observed.Port()+uint16(i)),
			Source: protocol.EndpointServer, Socket: primary, Verified: true})
	}
	for i := range 3 {
		v.Families[0].Endpoints = append(v.Families[0].Endpoints, protocol.Endpoint{Addr: netip.AddrPortFrom(ip, tr.Observed.Port()+10+uint16(i)),
			Source: protocol.EndpointSecond, Socket: second, Verified: true})
	}
	return v
}

// siblingView is an endpoint-independent peer with two sibling sockets: one
// verified endpoint per socket.
func siblingView(tr protocol.Traits) protocol.PeerView {
	v := view(tr)
	ip := tr.Observed.Addr()
	for i := range 2 {
		v.Families[0].Endpoints = append(v.Families[0].Endpoints, protocol.Endpoint{Addr: netip.AddrPortFrom(ip, tr.Observed.Port()+100+uint16(i)),
			Source: protocol.EndpointSibling, Socket: uint8(2 + i), Verified: true})
	}
	return v
}

// dual builds a PeerView with a v6 family then a v4 family.
func dual(tr4, tr6 protocol.Traits) protocol.PeerView {
	return protocol.PeerView{Families: append(view(tr6).Families, view(tr4).Families...)}
}

func classifyInput(initTr, respTr protocol.Traits) ClassifyInput {
	return ClassifyInput{
		Initiator: view(initTr),
		Responder: view(respTr),
		Pair:      protocol.PairFacts{SharedFamilies: []protocol.Family{initTr.Family}},
		Policy:    protocol.Policy{Budget: protocol.DefaultBudget()},
		Timeouts:  protocol.DefaultTimeouts(),
	}
}

func roundInput(cl Classification, initTr, respTr protocol.Traits, round int, prev []RoundOutcome) RoundInput {
	return RoundInput{
		Round:       round,
		Class:       cl,
		Prev:        prev,
		RTT:         [2]time.Duration{40 * time.Millisecond, 60 * time.Millisecond},
		Remaining:   30 * time.Second,
		D:           150 * time.Millisecond,
		BudgetLeft:  [2]int{3000, 3000},
		Views:       [2]protocol.PeerView{view(initTr), view(respTr)},
		Policy:      protocol.Policy{Budget: protocol.DefaultBudget()},
		MaxRounds:   5,
		HandshakeMs: 20000,
	}
}

// chain runs the planner for up to n rounds, feeding each decision's actual
// granted Budget back into the next round's Prev (so the escalation guard sees
// the real class). class is the RoundClass to report for each round.
func chain(p DefaultPlanner, cl Classification, a, b protocol.Traits, n int, allowExtreme bool, class RoundClass, mut func(*RoundInput)) []RoundDecision {
	var prev []RoundOutcome
	var out []RoundDecision
	for round := 1; round <= n; round++ {
		in := roundInput(cl, a, b, round, prev)
		in.AllowExtreme = allowExtreme
		in.MaxRounds = 6
		if mut != nil {
			mut(&in)
		}
		dec := p.Round(in)
		out = append(out, dec)
		if dec.Stop != "" {
			break
		}
		prev = append(prev, RoundOutcome{Round: round, Variant: dec.Variant, Class: class, Rescue: dec.Rescue, Budget: dec.Budget})
		if dec.Final {
			break
		}
	}
	return out
}

// carrier wraps one side's plan in the message that takes it to the client:
// probe_summary.plan.round1 for round 1, whose go carries no plan, and
// punch_go.plan for every later round. clamped reports whether the client's
// Normalize would change the message.
func carrier(rp protocol.RoundPlan) (m protocol.Message, clamped bool) {
	if rp.Round == 1 {
		sum := protocol.ProbeSummary{SessionID: "s1",
			Plan: protocol.PlanSpec{ID: "p1", RoundsMax: 1, Budget: protocol.DefaultBudget(), Round1: rp}}
		_, clamped = sum.Normalize()
		return sum, clamped
	}
	g := protocol.PunchGo{SessionID: "s1", Round: rp.Round, WindowMs: rp.WindowMs, Plan: &rp}
	_, clamped = g.Normalize()
	return g, clamped
}

// mappingLedger records, per family and role, how many sockets sent each
// Direct target so far: what the coordinator keeps to fill
// FamilyRound.Mapped.
type mappingLedger map[protocol.Family]*[2]map[netip.AddrPort]int

// outcome is the RoundOutcome the coordinator records for dec, ended with
// class: the decision's families, each side's Mapped counted from its plan
// as the coordinator counts it (SideMappings; no peer_targets, sandwich or
// re-observation here).
func (l mappingLedger) outcome(round int, dec RoundDecision, class RoundClass) RoundOutcome {
	o := RoundOutcome{Round: round, Variant: dec.Variant, Class: class, Rescue: dec.Rescue, Budget: dec.Budget,
		Families: slices.Clone(dec.Families)}
	for i := range o.Families {
		f := o.Families[i].Family
		if l[f] == nil {
			l[f] = &[2]map[netip.AddrPort]int{{}, {}}
		}
		for r := range 2 {
			for _, fs := range dec.Sides[r] {
				if fs.Family != f {
					continue
				}
				sent := l[f][r]
				direct, spray := SideMappings(fs, func(t netip.AddrPort) int { return sent[t] })
				o.Families[i].Mapped[r] = direct + spray
				for _, st := range fs.Stages {
					if st.Kind == protocol.StageDirect {
						for _, t := range st.Targets {
							sent[t] = max(sent[t], int(fs.Sockets))
						}
					}
				}
			}
		}
	}
	return o
}

// sandwichOf reports, by role, whether any family side of dec runs the
// sandwich probe.
func sandwichOf(dec RoundDecision) [2]bool {
	var out [2]bool
	for r, sides := range dec.Sides {
		for _, fs := range sides {
			out[r] = out[r] || fs.Sandwich
		}
	}
	return out
}

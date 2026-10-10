package holepunch

import (
	"net/netip"
	"testing"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// selfReported is the v6 family view a coordinator without a v6 observer
// builds from a report: the primary socket's address, unverified.
func selfReported(rep protocol.ProbeReport, f protocol.Family) (protocol.FamilyView, bool) {
	for _, fr := range rep.Families {
		if fr.Family == f && len(fr.Sockets) > 0 {
			return protocol.FamilyView{Family: f, Endpoints: []protocol.Endpoint{
				{Addr: fr.Sockets[0].Local, Source: protocol.EndpointServer}}}, true
		}
	}
	return protocol.FamilyView{}, false
}

// The server observes IPv4 only and both clients are dual stack: IPv6 runs
// unverified with Direct targets to the self-reported addresses, IPv6 first.
// Here IPv4 only replies, so the session must win on IPv6.
func TestDualStackUnverifiedV6(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	ps.pair = func(p *protocol.PairFacts, views *[2]protocol.PeerView, reports [2]protocol.ProbeReport) {
		p.SharedFamilies = []protocol.Family{protocol.FamilyUDP6, protocol.FamilyUDP4}
		p.Unverified = map[protocol.Family]bool{protocol.FamilyUDP6: true}
		for i := range 2 {
			v6, ok := selfReported(reports[i], protocol.FamilyUDP6)
			if !ok {
				t.Errorf("client %d did not report its IPv6 family", i)
				continue
			}
			var rest []protocol.FamilyView
			for _, fv := range views[i].Families {
				if fv.Family != protocol.FamilyUDP6 {
					rest = append(rest, fv)
				}
			}
			views[i].Families = append([]protocol.FamilyView{v6}, rest...)
		}
	}
	ps.round = func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
		peer := views[1-roleIndex(r)].Families[0].Endpoints[0].Addr
		return protocol.RoundPlan{Round: uint8(k), Variant: "v6_direct_r1", Budget: protocol.BudgetLight, WindowMs: 1200, Seed: 9,
			Sides: []protocol.FamilySide{
				{Family: protocol.FamilyUDP6, Role: protocol.SideBoth, Sockets: 1, MaxPackets: 40, MaxPPS: 80, MaxNewPerSec: 100, MaxDistinctPorts: 16,
					Stages: []protocol.Stage{
						{Kind: protocol.StageDirect, Targets: []netip.AddrPort{peer}, Repeats: 8},
						{Kind: protocol.StagePredict, IP: peer.Addr(), Anchor: peer.Port() + 1, Steps: []int16{1}, Span: 4}}},
				{Family: protocol.FamilyUDP4, Role: protocol.SideReplyOnly, Sockets: 1, Stages: []protocol.Stage{{Kind: protocol.StageReplyOnly}}},
			}}
	}
	hosts := [2]*nattest.Host{w.n.PublicHost(), w.n.PublicHost()}
	pr := runPairHosts(t, w, hosts, ps, nil)
	defer pr.closeAll()
	wantSuccess(t, pr)
	for i, r := range pr.res {
		if f := r.sess.Result().Path.Family; f != protocol.FamilyUDP6 {
			t.Fatalf("client %d won on %s", i, f)
		}
		d := r.sess.Diagnostics()
		found := false
		for _, x := range d.Warn {
			found = found || x == protocol.WarnUnverifiedTargets
		}
		if !found || d.Counters.TargetRejected == 0 || d.Counters.TxByStage["predict"] != 0 {
			t.Fatalf("client %d: warn %v counters %+v", i, d.Warn, d.Counters)
		}
	}
}

// Two homes behind one carrier NAT without hairpin: the same public IP but
// different LANs. The peers' LAN addresses are not admitted, the
// public path cannot loop back, and the home routers' mappings in the carrier
// network, pushed as peer_targets{source: portmap}, connect them.
func TestUpstreamLANCandidates(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	cg := nattest.CGNAT(nattest.PortRestricted(), nattest.FullCone())
	carrier := w.n.NAT(cg[0])
	homes := [2]*nattest.NAT{carrier.NAT(cg[1]), carrier.NAT(cg[1])}
	hosts := [2]*nattest.Host{homes[0].Host(), homes[1].Host()}
	var upstream [2]netip.AddrPort
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	ps.pair = func(p *protocol.PairFacts, views *[2]protocol.PeerView, reports [2]protocol.ProbeReport) {
		if !p.SamePublicIP[protocol.FamilyUDP4] || p.LikelySameLAN[protocol.FamilyUDP4] {
			t.Errorf("pair facts %+v", p)
		}
		for i := range 2 {
			local := reports[i].Families[0].Sockets[0].Local
			for _, m := range homes[i].Mappings() {
				if m.Internal == local {
					upstream[i] = m.External
				}
			}
		}
	}
	ps.round = func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
		p := directPlan(k, r, views)
		for _, e := range views[1-roleIndex(r)].Families[0].Endpoints {
			if e.Source == protocol.EndpointLAN {
				p.Sides[0].Stages[0].Targets = append(p.Sides[0].Stages[0].Targets, e.Addr)
			}
		}
		return p
	}
	ps.assistHook = func(k, i int) []protocol.Assist {
		return []protocol.Assist{{Kind: protocol.AssistPeerTargets, Round: uint8(k), Family: protocol.FamilyUDP4, From: protocol.RoleServer,
			Targets: []netip.AddrPort{upstream[1-i]}, Source: protocol.TargetsPortmap}}
	}
	pr := runPairHosts(t, w, hosts, ps, nil)
	defer pr.closeAll()
	wantSuccess(t, pr)
	for i, r := range pr.res {
		if got := r.sess.Result().Path.RemoteAddr; got != upstream[1-i] {
			t.Fatalf("client %d connected to %v, want the upstream candidate %v", i, got, upstream[1-i])
		}
		if r.sess.Diagnostics().Counters.TargetRejected == 0 {
			t.Fatalf("client %d admitted the peer's LAN address", i)
		}
	}
}

package coord

import (
	"maps"
	"net/netip"
	"slices"
	"testing"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

// Addresses of the shared-network cases: two hosts behind one upstream NAT, and two
// IPv6 hosts without NAT.
var (
	pubShared = netip.MustParseAddr("203.0.113.77")
	pubI6     = netip.MustParseAddrPort("[2001:db8:1::10]:40000")
	pubR6     = netip.MustParseAddrPort("[2001:db8:2::20]:50000")
)

// lanPlanner is the default planner that also aims round 1 at every
// endpoint of the peer's view, LAN ones included: admission decides.
type lanPlanner struct{ plan.DefaultPlanner }

func (p lanPlanner) Round(in RoundInput) RoundDecision {
	d := p.DefaultPlanner.Round(in)
	for r := range d.Sides {
		for i := range d.Sides[r] {
			fs := &d.Sides[r][i]
			fv, ok := familyView(in.Views[1-r], fs.Family)
			if !ok {
				continue
			}
			st := protocol.Stage{Kind: protocol.StageDirect, Repeats: 4}
			for _, e := range fv.Endpoints {
				st.Targets = append(st.Targets, e.Addr)
			}
			fs.Role, fs.Stages = protocol.SideBoth, append(fs.Stages, st)
		}
	}
	return d
}

// sharedNAT is side i's family behind the shared public IP with LAN address
// local.
func sharedNAT(i int, local netip.AddrPort) simclient.Family {
	pub := netip.AddrPortFrom(pubShared, uint16(40000+i))
	return simclient.Family{Family: protocol.FamilyUDP4, Local: local, Observed: []netip.AddrPort{pub},
		Traits: simclient.OpenTraits(pub)}
}

func targetsOf(rp protocol.RoundPlan) []netip.AddrPort {
	var out []netip.AddrPort
	for _, s := range rp.Sides {
		for _, st := range s.Stages {
			out = append(out, st.Targets...)
		}
	}
	return out
}

func hasSource(v protocol.PeerView, src protocol.EndpointSource) bool {
	for _, fv := range v.Families {
		for _, e := range fv.Endpoints {
			if e.Source == src {
				return true
			}
		}
	}
	return false
}

// TestLANNeedsSameLAN: a peer's private LAN address is shown and aimed at
// only when both sides share the public IP and their LAN prefixes
// intersect; the same public IP alone is not enough.
func TestLANNeedsSameLAN(t *testing.T) {
	cases := []struct {
		name    string
		lanR    netip.AddrPort
		sameLAN bool
	}{
		{"same upstream NAT, other LAN", mustAP("192.168.2.20:50000"), false},
		{"same LAN", mustAP("192.168.1.20:50000"), true},
	}
	lanI := mustAP("192.168.1.10:40000")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, func(cfg *Config) { cfg.Planner = lanPlanner{} })
			p := r.pair(SessionOptions{})
			p.report(0, sharedNAT(0, lanI))
			p.report(1, sharedNAT(1, c.lanR))
			sum := expect[protocol.ProbeSummary](t, p.cl[0])
			expect[protocol.ProbeSummary](t, p.cl[1])
			u4 := protocol.FamilyUDP4
			if !sum.Pair.SamePublicIP[u4] || sum.Pair.LikelySameLAN[u4] != c.sameLAN {
				t.Fatalf("pair %+v", sum.Pair)
			}
			if hasSource(sum.Peer, protocol.EndpointLAN) != c.sameLAN {
				t.Fatalf("peer view %+v", sum.Peer)
			}
			aimed := slices.Contains(targetsOf(sum.Plan.Round1), c.lanR)
			if aimed != c.sameLAN {
				t.Fatalf("LAN target aimed at: %v; plan %+v", aimed, sum.Plan.Round1)
			}
			if c.sameLAN {
				for _, st := range sum.Plan.Round1.Sides[0].Stages {
					if slices.Contains(st.Targets, c.lanR) && (st.Repeats > lanRepeats || len(st.Targets) != 1) {
						t.Fatalf("LAN stage %+v", st)
					}
				}
			} else {
				// Events reach the observer on a goroutine of their own.
				eventually(t, "a not_same_lan rejection", func() bool {
					return slices.ContainsFunc(r.eventsOf(EvTargetRejected), func(e Event) bool {
						d := e.Data.(TargetRejectedData)
						return d.Rule == "not_same_lan" && d.Addr == c.lanR
					})
				})
			}
			p.s.Abort(protocol.ReasonCanceled, "")
			r.wait(p.s)
		})
	}
}

// TestUpstreamPortMap: behind one upstream NAT on different LANs, the
// private external address of a side's downstream port mapping reaches its
// peer as an upstream-LAN candidate, peer_targets{source: portmap} after
// every go; peers behind different public IPs never see it.
func TestUpstreamPortMap(t *testing.T) {
	ext := mustAP("100.64.5.6:41000")
	t.Run("same public IP", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		fi := sharedNAT(0, mustAP("192.168.1.10:40000"))
		fi.PortMap = &protocol.PortMapReport{Method: protocol.PortMapUPnP, External: ext, Internal: fi.Local, LeaseSeconds: 60}
		p.report(0, fi)
		p.report(1, sharedNAT(1, mustAP("192.168.2.20:50000")))
		var sums [2]*protocol.ProbeSummary
		for i := range 2 {
			sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
		}
		if !hasSource(sums[1].Peer, protocol.EndpointPortmap) || hasSource(sums[1].Peer, protocol.EndpointLAN) {
			t.Fatalf("peer view %+v", sums[1].Peer)
		}
		for i := range 2 {
			send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 1))
		}
		g0 := expect[protocol.PunchGo](t, p.cl[0])
		g1 := expect[protocol.PunchGo](t, p.cl[1])
		got := expect[protocol.Assist](t, p.cl[1])
		if got.Kind != protocol.AssistPeerTargets || got.Source != protocol.TargetsPortmap || !slices.Equal(got.Targets, []netip.AddrPort{ext}) {
			t.Fatalf("peer_targets %+v", got)
		}
		checkPushed(t, p, g0, g1, 1)
		for i := range 2 {
			p.windowEnd(i, 1, simclient.Outcome{Sent: 4})
		}
		if g := expect[protocol.PunchGo](t, p.cl[1]); g.Round != 2 {
			t.Fatalf("go %+v", g)
		}
		if again := expect[protocol.Assist](t, p.cl[1]); again.Round != 2 || again.Source != protocol.TargetsPortmap ||
			!slices.Equal(again.Targets, []netip.AddrPort{ext}) {
			t.Fatalf("round 2 peer_targets %+v", again)
		}
		checkPushed(t, p, nil, nil, 2)
		p.s.Abort(protocol.ReasonCanceled, "")
		r.wait(p.s)
	})
	t.Run("different public IPs", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		fi := fam(0, simclient.OpenTraits)
		fi.PortMap = &protocol.PortMapReport{Method: protocol.PortMapUPnP, External: ext, Internal: localI, LeaseSeconds: 60}
		p.report(0, fi)
		p.report(1)
		var sums [2]*protocol.ProbeSummary
		for i := range 2 {
			sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
		}
		if hasSource(sums[1].Peer, protocol.EndpointPortmap) {
			t.Fatalf("peer view %+v", sums[1].Peer)
		}
		// A late private mapping is refused as well.
		ready := simclient.Ready(sums[0], protocol.RoleInitiator, 1)
		ready.Families[0].PortMap = &protocol.PortMapReport{Method: protocol.PortMapPCP, External: mustAP("10.9.9.9:41000"),
			Internal: localI, LeaseSeconds: 60}
		send(t, p.cl[0], &ready)
		send(t, p.cl[1], simclient.Ready(sums[1], protocol.RoleResponder, 1))
		expect[protocol.PunchGo](t, p.cl[1])
		p.s.Abort(protocol.ReasonCanceled, "")
		res := r.wait(p.s)
		if res.Counters.PeerTargets != 0 || res.Counters.TargetRejected == 0 {
			t.Fatalf("counters %+v", res.Counters)
		}
	})
	t.Run("late mapping, same public IP", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.report(0, sharedNAT(0, mustAP("192.168.1.10:40000")))
		p.report(1, sharedNAT(1, mustAP("192.168.2.20:50000")))
		var sums [2]*protocol.ProbeSummary
		for i := range 2 {
			sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
		}
		ready := simclient.Ready(sums[0], protocol.RoleInitiator, 1)
		ready.Families[0].PortMap = &protocol.PortMapReport{Method: protocol.PortMapPCP, External: ext,
			Internal: mustAP("192.168.1.10:40000"), LeaseSeconds: 60}
		send(t, p.cl[0], &ready)
		send(t, p.cl[1], simclient.Ready(sums[1], protocol.RoleResponder, 1))
		g0 := expect[protocol.PunchGo](t, p.cl[0])
		g1 := expect[protocol.PunchGo](t, p.cl[1])
		if got := expect[protocol.Assist](t, p.cl[1]); got.Source != protocol.TargetsPortmap || !slices.Equal(got.Targets, []netip.AddrPort{ext}) {
			t.Fatalf("peer_targets %+v", got)
		}
		checkPushed(t, p, g0, g1, 1)
		p.s.Abort(protocol.ReasonCanceled, "")
		r.wait(p.s)
	})
}

// checkPushed checks the charge for the upstream-LAN candidate pushed to the
// responder after each of the first n gos: two packets each, as push credit
// the audit pays out, while round 1's gos keep the summary's plans (the
// client sends pushed targets on a quota of their own).
func checkPushed(t *testing.T, p *pair, g0, g1 *protocol.PunchGo, n int) {
	t.Helper()
	if g0 != nil && (g0.Plan != nil || g1.Plan != nil) {
		t.Fatalf("round 1 go plans: initiator %v, responder %v", g0.Plan != nil, g1.Plan != nil)
	}
	eventually(t, "push charge", func() bool {
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		return p.s.st.credit == [2]int{0, n * pushPackets}
	})
}

// v6Host is side i's IPv6 family: a host without NAT, which no observer of
// a v4-only server sees.
func v6Host(i int) simclient.Family {
	pub := pubI6
	if i == 1 {
		pub = pubR6
	}
	other := netip.AddrFrom16(pub.Addr().As16())
	b := other.As16()
	b[15]++
	return simclient.Family{Family: protocol.FamilyUDP6, Local: pub, Traits: simclient.OpenTraits(pub),
		LocalAddrs: []netip.Addr{pub.Addr(), netip.AddrFrom16(b), netip.MustParseAddr("fe80::1")}}
}

// v4OnlyServer is a rig with a registry whose probe specs have IPv4
// observers only.
func v4OnlyServer(t *testing.T, opts ...rigOpt) *rig {
	return newRig(t, append([]rigOpt{withRegistry(natprobe.NewRegistry(natprobe.RegistryConfig{})), func(c *Config) {
		c.DefaultProbe = protocol.ProbeSpec{Observers: []protocol.ObserverSpec{{ID: 0, Addr: mustAP("192.0.2.9:3000")}}}
	}}, opts...)...)
}

// TestUnverifiedFamily: a family the server has no observer for runs in the
// restricted mode — Direct stages to at most four of the peer's
// self-reported global addresses, eight packets per target — marked in
// pair.unverified and warned; disabled, it is left out.
func TestUnverifiedFamily(t *testing.T) {
	u4, u6 := protocol.FamilyUDP4, protocol.FamilyUDP6
	t.Run("restricted", func(t *testing.T) {
		r := v4OnlyServer(t)
		p := r.pair(SessionOptions{})
		if got := p.s.unobserved; !slices.Equal(got, []protocol.Family{u6}) {
			t.Fatalf("unobserved %v", got)
		}
		for i := range 2 {
			p.report(i, v6Host(i), fam(i, simclient.OpenTraits))
		}
		var sums [2]*protocol.ProbeSummary
		for i := range 2 {
			sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
		}
		sum := sums[0]
		if !slices.Equal(sum.Pair.SharedFamilies, []protocol.Family{u6, u4}) ||
			!maps.Equal(sum.Pair.Unverified, map[protocol.Family]bool{u6: true}) {
			t.Fatalf("pair %+v", sum.Pair)
		}
		peer, _ := familyView(sum.Peer, u6)
		if len(peer.Endpoints) != 2 || peer.Endpoints[0].Addr != pubR6 || peer.Endpoints[0].Verified {
			t.Fatalf("peer v6 view %+v", peer)
		}
		var v6 *protocol.FamilySide
		for i, s := range sum.Plan.Round1.Sides {
			if s.Family == u6 {
				v6 = &sum.Plan.Round1.Sides[i]
			}
		}
		if v6 == nil {
			t.Fatalf("no v6 side: %+v", sum.Plan.Round1)
		}
		var targets []netip.AddrPort
		for _, st := range v6.Stages {
			if st.Kind != protocol.StageDirect && st.Kind != protocol.StageReplyOnly {
				t.Fatalf("stage %+v", st)
			}
			for _, a := range st.Targets {
				if a.Addr().Is4() || !slices.ContainsFunc(peer.Endpoints, func(e protocol.Endpoint) bool { return e.Addr == a }) {
					t.Fatalf("target %v", a)
				}
				if !slices.Contains(targets, a) {
					targets = append(targets, a)
				}
			}
		}
		if len(targets) == 0 || len(targets) > maxUnverifiedTargets || int(v6.MaxPackets) > unverifiedPerTarget*len(targets) {
			t.Fatalf("v6 side %+v", v6)
		}
		p.s.Abort(protocol.ReasonCanceled, "")
		if res := r.wait(p.s); !contains(res.Warn, protocol.WarnUnverifiedTargets) {
			t.Fatalf("warn %v", res.Warn)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		r := v4OnlyServer(t, func(c *Config) { c.DisableUnverifiedFamilies = true })
		p := r.pair(SessionOptions{})
		for i := range 2 {
			p.report(i, v6Host(i), fam(i, simclient.OpenTraits))
		}
		// The scripted clients cannot verify their v4 family either, so the
		// session ends; the pair it planned with has no v6.
		if res := r.wait(p.s); contains(res.Warn, protocol.WarnUnverifiedTargets) {
			t.Fatalf("warn %v", res.Warn)
		}
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		if pair := p.s.st.pair; !slices.Equal(pair.SharedFamilies, []protocol.Family{u4}) || pair.Unverified != nil {
			t.Fatalf("pair %+v", pair)
		}
		for r := range 2 {
			if _, ok := familyView(p.s.st.views[r], u6); ok {
				t.Fatalf("v6 view %+v", p.s.st.views[r])
			}
		}
	})
	t.Run("disabled, v6 only", func(t *testing.T) {
		r := v4OnlyServer(t, func(c *Config) { c.DisableUnverifiedFamilies = true })
		p := r.pair(SessionOptions{})
		p.report(0, v6Host(0))
		p.report(1, v6Host(1))
		if res := r.wait(p.s); res.Code != protocol.ReasonNoCommonFamily {
			t.Fatalf("result %+v", res)
		}
	})
}

// TestNoCommonFamily: a v4-only side and a v6-only side fail fast with
// no_common_family.
func TestNoCommonFamily(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.report(0)
	p.report(1, v6Host(1))
	for i := range 2 {
		if a := expectAbort(t, p.cl[i]); a.Code != protocol.ReasonNoCommonFamily {
			t.Fatalf("abort %+v", a)
		}
	}
	if res := r.wait(p.s); res.Code != protocol.ReasonNoCommonFamily || res.Outcome != OutcomeFailed {
		t.Fatalf("result %+v", res)
	}
}

func TestUnobservedFamilies(t *testing.T) {
	v4 := protocol.ObserverSpec{Addr: mustAP("192.0.2.9:3000")}
	v6 := protocol.ObserverSpec{Addr: mustAP("[2001:db8::9]:3000")}
	cases := []struct {
		specs [2][]protocol.ObserverSpec
		want  []protocol.Family
	}{
		{[2][]protocol.ObserverSpec{{v4, v6}, {v6, v4}}, nil},
		{[2][]protocol.ObserverSpec{{v4}, {v4}}, []protocol.Family{protocol.FamilyUDP6}},
		{[2][]protocol.ObserverSpec{{v4, v6}, {v4}}, []protocol.Family{protocol.FamilyUDP6}},
		{[2][]protocol.ObserverSpec{nil, nil}, []protocol.Family{protocol.FamilyUDP6, protocol.FamilyUDP4}},
	}
	for _, c := range cases {
		got := unobservedFamilies([2]protocol.ProbeSpec{{Observers: c.specs[0]}, {Observers: c.specs[1]}})
		if !slices.Equal(got, c.want) {
			t.Errorf("%v: %v, want %v", c.specs, got, c.want)
		}
	}
}

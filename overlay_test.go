package holepunch

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// TestHostAddrClassification checks the split of the host's addresses:
// tunnel and overlay interfaces, point-to-point links with private
// addresses and 100.64/10 are overlay; docker and virtual-machine bridges
// are ordinary LANs; a point-to-point uplink that carries the host's public
// address stays a LAN address; loopback and down interfaces are no
// candidates at all.
func TestHostAddrClassification(t *testing.T) {
	up := net.FlagUp | net.FlagRunning
	ifaces := []net.Interface{
		{Name: "eth0", Flags: up | net.FlagBroadcast},
		{Name: "tailscale0", Flags: up | net.FlagPointToPoint},
		{Name: "utun4", Flags: up | net.FlagPointToPoint},
		{Name: "wg0", Flags: up | net.FlagPointToPoint},
		{Name: "ztks54inm2", Flags: up | net.FlagBroadcast},
		{Name: "ZeroTier One [8056c2e21c000001]", Flags: up},
		{Name: "tun0", Flags: up | net.FlagPointToPoint},
		{Name: "docker0", Flags: up | net.FlagBroadcast},
		{Name: "br-5f0e1c2d3b4a", Flags: up | net.FlagBroadcast},
		{Name: "virbr0", Flags: up | net.FlagBroadcast},
		{Name: "vmnet8", Flags: up | net.FlagBroadcast},
		{Name: "ppp0", Flags: up | net.FlagPointToPoint},
		{Name: "gif0", Flags: up | net.FlagPointToPoint},
		{Name: "lo", Flags: up | net.FlagLoopback},
		{Name: "eth1", Flags: net.FlagBroadcast},
	}
	pfx := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, p := range s {
			out = append(out, netip.MustParsePrefix(p))
		}
		return out
	}
	addrs := [][]netip.Prefix{
		pfx("192.168.1.10/24", "100.72.1.2/24"),
		pfx("100.101.102.103/32", "fd7a:115c:a1e0::1/128"),
		pfx("10.6.0.2/32"),
		pfx("10.7.0.2/24"),
		pfx("10.147.17.4/24"),
		pfx("172.25.1.1/16"),
		pfx("10.8.0.6/24"),
		pfx("172.17.0.1/16"),
		pfx("172.18.0.1/16"),
		pfx("192.168.122.1/24"),
		pfx("192.168.200.1/24"),
		pfx("198.51.100.20/32"),
		pfx("10.99.0.1/32"),
		pfx("127.0.0.1/8"),
		pfx("192.168.2.10/24"),
	}
	want := map[string]struct{ live, overlay bool }{
		"192.168.1.10":      {true, false},
		"100.72.1.2":        {true, true}, // 100.64/10 on an Ethernet link: carrier or Tailscale space
		"100.101.102.103":   {true, true},
		"fd7a:115c:a1e0::1": {true, true},
		"10.6.0.2":          {true, true},
		"10.7.0.2":          {true, true},
		"10.147.17.4":       {true, true},
		"172.25.1.1":        {true, true},
		"10.8.0.6":          {true, true},
		"172.17.0.1":        {true, false},
		"172.18.0.1":        {true, false},
		"192.168.122.1":     {true, false},
		"192.168.200.1":     {true, false},
		"198.51.100.20":     {true, false}, // a PPPoE uplink's public address
		"10.99.0.1":         {true, true},  // another point-to-point link, private
		"127.0.0.1":         {false, false},
		"192.168.2.10":      {false, false},
	}
	hosts := hostAddrsOf(ifaces, addrs)
	if len(hosts) != len(want) {
		t.Fatalf("%d addresses, want %d", len(hosts), len(want))
	}
	for _, h := range hosts {
		w, ok := want[h.addr.String()]
		if !ok || h.live != w.live || h.overlay != w.overlay {
			t.Errorf("%s on %s: live %v overlay %v, want %+v", h.addr, h.iface, h.live, h.overlay, w)
		}
	}
	lan := localAddrs(protocol.FamilyUDP4, hosts)
	for _, a := range lan {
		if h := hosts[slices.IndexFunc(hosts, func(h hostAddr) bool { return h.addr == a })]; h.overlay {
			t.Errorf("overlay address %v among the LAN addresses", a)
		}
	}
	if !slices.Contains(lan, netip.MustParseAddr("172.17.0.1")) {
		t.Errorf("the docker bridge is no LAN address: %v", lan)
	}
	if g := globalAddr(protocol.FamilyUDP4, hosts); g != netip.MustParseAddr("198.51.100.20") {
		t.Errorf("global address %v", g)
	}
	if got := ifaceAddrs(hosts, "tailscale0"); len(got) != 2 {
		t.Errorf("tailscale0 addresses %v", got)
	}
}

// overlayNetwork is a nattest host that also lists a Tailscale interface
// and a docker bridge, as a laptop running both would.
type overlayNetwork struct {
	*nattest.Host
	ts4 netip.Addr
}

func (n overlayNetwork) InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error) {
	ifs, addrs, err := n.Host.InterfaceAddrs()
	if err != nil {
		return nil, nil, err
	}
	ifs = append(ifs, net.Interface{Index: 7, Name: "tailscale0", Flags: net.FlagUp | net.FlagPointToPoint},
		net.Interface{Index: 8, Name: "docker0", Flags: net.FlagUp | net.FlagBroadcast})
	addrs = append(addrs, []netip.Prefix{netip.PrefixFrom(n.ts4, 32)}, []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")})
	return ifs, addrs, nil
}

// TestReportOverlay checks what probe_report says of overlay addresses:
// included by default, apart from the LAN addresses and never as a
// sibling socket's address; none with Options.ExcludeOverlay.
func TestReportOverlay(t *testing.T) {
	t.Parallel()
	ts := netip.MustParseAddr("100.101.102.103")
	for _, exclude := range []bool{false, true} {
		w := newWorld(t)
		h := w.host(nil)
		so := newSoloOn(t, w, h, func(o *Options) {
			o.Network = overlayNetwork{Host: h, ts4: ts}
			o.ExcludeOverlay = exclude
		})
		so.start(testTimeouts())
		rep, view := so.report()
		fr := rep.Families[0]
		if slices.Contains(fr.LocalAddrs, ts) || !slices.Contains(fr.LocalAddrs, netip.MustParseAddr("172.17.0.1")) {
			t.Fatalf("exclude %v: local addrs %v", exclude, fr.LocalAddrs)
		}
		for _, sk := range fr.Sockets {
			if sk.Local.Addr() == ts {
				t.Fatalf("exclude %v: socket %d bound on the overlay address", exclude, sk.ID)
			}
		}
		wantOverlay := []netip.Addr{ts}
		if exclude {
			wantOverlay = nil
		}
		if !slices.Equal(fr.Overlay, wantOverlay) {
			t.Fatalf("exclude %v: overlay %v", exclude, fr.Overlay)
		}
		hasEndpoint := slices.ContainsFunc(view.Families[0].Endpoints, func(e protocol.Endpoint) bool {
			return e.Source == protocol.EndpointOverlay && e.Addr.Addr() == ts
		})
		if hasEndpoint == exclude {
			t.Fatalf("exclude %v: endpoints %+v", exclude, view.Families[0].Endpoints)
		}
		so.cancel()
		so.result(10 * time.Second)
	}
}

// TestOverlayAdmissionAndKind checks the client side of overlay endpoints: a peer's
// overlay endpoint is a Direct target only when both sides have an overlay
// and this side includes it, two packets a round like a LAN target; its
// pairs are overlay candidates and paths of kind overlay.
func TestOverlayAdmissionAndKind(t *testing.T) {
	_, h := simHost(t)
	ovl := netip.MustParseAddrPort("100.101.102.103:40000")
	pub := netip.MustParseAddrPort("198.51.100.7:40001")
	view := fakePeer(pub.String())
	view.Families[0].Endpoints = append(view.Families[0].Endpoints, protocol.Endpoint{Addr: ovl, Source: protocol.EndpointOverlay})
	for _, c := range []struct {
		name    string
		shared  bool
		exclude bool
		admit   bool
	}{{"shared", true, false, true}, {"peer only", false, false, false}, {"excluded here", true, true, false}} {
		rt := newTestRuntime(t, fakeClock(t), h)
		rt.opts.ExcludeOverlay = c.exclude
		w := testWorker(t, rt, protocol.ProbeSummary{Peer: view, Pair: protocol.PairFacts{SharedFamilies: []protocol.Family{protocol.FamilyUDP4},
			SharedOverlay: map[protocol.Family]bool{protocol.FamilyUDP4: c.shared}}})
		ok, per := w.admit(rt, ovl, protocol.StageDirect)
		if ok != c.admit || (ok && per != protocol.LANRepeats) {
			t.Errorf("%s: admit %v, %d packets", c.name, ok, per)
		}
		if ok, _ := w.admit(rt, ovl, protocol.StagePredict); ok {
			t.Errorf("%s: an overlay address is sprayed", c.name)
		}
		want := protocol.PathPublic
		if c.admit {
			want = protocol.PathOverlay
		}
		if got := rt.pathKind(protocol.FamilyUDP4, ovl, candidate.KindUnknown); got != want {
			t.Errorf("%s: path kind %s, want %s", c.name, got, want)
		}
		if got := rt.pathKind(protocol.FamilyUDP4, pub, candidate.KindObserved); got != protocol.PathPublic {
			t.Errorf("%s: public path kind %s", c.name, got)
		}
	}
}

// testWorker gives rt a primary IPv4 socket and the worker of sum.
func testWorker(t *testing.T, rt *runtime, sum protocol.ProbeSummary) *worker {
	t.Helper()
	fs := rt.fam(protocol.FamilyUDP4)
	s := openPrimary(t, rt)
	fs.primary = s
	fs.worker = newWorker(rt, fs, &sum)
	return fs.worker
}

// TestPathKindPortmapAndLAN checks the other path kinds: a peer endpoint
// the summary lists as a port mapping, or a target of a portmap assist, is
// a portmap path; a LAN candidate a lan path.
func TestPathKindPortmapAndLAN(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	pm := netip.MustParseAddrPort("198.51.100.7:5000")
	assisted := netip.MustParseAddrPort("198.51.100.7:5001")
	view := fakePeer("198.51.100.7:40001")
	view.Families[0].Endpoints = append(view.Families[0].Endpoints, protocol.Endpoint{Addr: pm, Source: protocol.EndpointPortmap})
	testWorker(t, rt, protocol.ProbeSummary{Peer: view})
	rt.punch.notePortmap(assisted)
	for _, c := range []struct {
		to   netip.AddrPort
		k    candidate.Kind
		want protocol.PathKind
	}{
		{pm, candidate.KindTargets, protocol.PathPortmap},
		{assisted, candidate.KindLAN, protocol.PathPortmap},
		{netip.MustParseAddrPort("192.168.1.20:4000"), candidate.KindLAN, protocol.PathLAN},
		{netip.MustParseAddrPort("198.51.100.7:40001"), candidate.KindObserved, protocol.PathPublic},
		{netip.MustParseAddrPort("198.51.100.7:40009"), candidate.KindPredicted, protocol.PathPublic},
	} {
		if got := rt.pathKind(protocol.FamilyUDP4, c.to, c.k); got != c.want {
			t.Errorf("%v (%v): %s, want %s", c.to, c.k, got, c.want)
		}
	}
}

// TestWrongLANGuessNeverConfirms checks what the address split claims about
// bridges: two hosts often number their docker bridges alike, so the server may
// take a peer's bridge address for a shared LAN and the client aims its LAN
// stage at a stranger on its own bridge. That costs the stage's packets and
// nothing else: the stranger's echo of them fails the role check, its own
// holepunch traffic of another session fails authentication, and the session
// confirms the real peer's public path.
func TestWrongLANGuessNeverConfirms(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	bridge := w.n.NAT(nattest.PortRestricted())
	h := bridge.Host()
	stranger := bridge.Host() // a container on the client's own bridge
	sc, err := stranger.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(stranger.Addrs()[0], 40000), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sc.Close() }()
	other, err := udpwire.NewCodec(protocol.NewToken(), protocol.NewRouteID(), udpwire.RoleResponder, udpwire.PadPolicy{Min: 60, Max: 160}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan int, 1)
	go func() {
		n := 0
		defer func() { got <- n }()
		buf := make([]byte, 2048)
		for {
			k, from, err := sc.ReadFrom(buf)
			if err != nil {
				return
			}
			n++
			_, _ = sc.WriteTo(buf[:k], from) // an echo service
			ph := udpwire.Header{Type: udpwire.TPunch, Role: udpwire.RoleResponder, Seq: other.NextSeq(), Cand: udpwire.NoCand}
			if pkt, err := other.Seal(nil, &ph, nil, 0); err == nil {
				_, _ = sc.WriteTo(pkt, from) // another session's punch
			}
		}
	}()

	so := newSoloOn(t, w, h, nil)
	peer := newUDPPeer(t, w, so.s, protocol.RoleResponder, so.s.token)
	so.start(testTimeouts())
	_, self := so.report()
	lan := netip.AddrPortFrom(stranger.Addrs()[0], 40000)
	pv := peer.view()
	pv.Families[0].Endpoints = append(pv.Families[0].Endpoints, protocol.Endpoint{Addr: lan, Source: protocol.EndpointLAN})
	r1 := directPlan(1, so.role, roleViews(so.role, self, pv))
	r1.Sides[0].Stages = append([]protocol.Stage{{Kind: protocol.StageDirect, Targets: []netip.AddrPort{lan}, Repeats: 2}}, r1.Sides[0].Stages...)
	so.link.send(protocol.ProbeSummary{
		SessionID: so.s.sid, Self: self, Peer: pv,
		Pair: protocol.PairFacts{SharedFamilies: []protocol.Family{protocol.FamilyUDP4},
			SamePublicIP: map[protocol.Family]bool{protocol.FamilyUDP4: true}, LikelySameLAN: map[protocol.Family]bool{protocol.FamilyUDP4: true}},
		Transport: protocol.TransportPick{Mode: "quic"}, Timeouts: testTimeouts(),
		Plan: protocol.PlanSpec{ID: "p", PairClass: "test", RoundsMax: 3, Budget: protocol.DefaultBudget(), Round1: r1},
	})
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, DelayMs: 5, WindowMs: r1.WindowMs})
	pk, ok := peer.expect(udpwire.TPunch, 5*time.Second)
	if !ok {
		t.Fatal("no punch")
	}
	time.Sleep(100 * time.Millisecond) // let the stranger's answers arrive first
	peer.send(pk.from, udpwire.Header{Type: udpwire.TSuccess, Round: 1, Cand: pk.h.Cand, EchoSeq: pk.h.Seq, EchoTS: pk.h.TS},
		&udpwire.TLVs{Observed: pk.from, HasRx: true, RxCount: 1})
	nom, ok := peer.expect(udpwire.TNominate, 5*time.Second)
	if !ok {
		t.Fatal("no nominate")
	}
	peer.send(nom.from, udpwire.Header{Type: udpwire.TAccept, Aux: nom.h.Aux, Cand: udpwire.NoCand}, &udpwire.TLVs{HasRx: true, RxCount: 2})
	if _, ok := peer.expect(udpwire.TReady, 5*time.Second); !ok {
		t.Fatal("no ready")
	}
	for range 3 {
		peer.send(nom.from, udpwire.Header{Type: udpwire.THandoverAck, Aux: nom.h.Aux, Cand: udpwire.NoCand}, &udpwire.TLVs{HasRx: true, RxCount: 1})
	}
	r := so.result(5 * time.Second)
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer func() { _ = r.sess.Close() }()
	res, d := r.sess.Result(), r.sess.Diagnostics()
	if res.Path.RemoteAddr != peer.addr || res.Path.Kind != protocol.PathPublic {
		t.Fatalf("confirmed %v (%s), want the peer's public %v", res.Path.RemoteAddr, res.Path.Kind, peer.addr)
	}
	_ = sc.Close()
	if n := <-got; n == 0 {
		t.Fatal("the LAN guess was never tried")
	}
	if d.Counters.Drops[protocol.DropRole] == 0 || d.Counters.Drops[protocol.DropAuth] == 0 {
		t.Fatalf("the stranger's datagrams were not refused: drops %v", d.Counters.Drops)
	}
}

// TestHostFirewallHint checks the host firewall hint: port-dependent filtering
// on an endpoint-independent mapping, or without NAT, suggests a host
// firewall, for either side; a symmetric NAT's own filtering does not, nor
// do weak conclusions.
func TestHostFirewallHint(t *testing.T) {
	cone := protocol.Traits{Mapping: protocol.MapEIM, MappingConf: protocol.ConfMedium, Filtering: protocol.FiltPDF, FilteringConf: protocol.ConfHigh, Samples: 3}
	open := cone
	open.Filtering = protocol.FiltEIF
	nonat := protocol.Traits{NoNAT: protocol.TriTrue, Filtering: protocol.FiltPDF, FilteringConf: protocol.ConfMedium, Samples: 3}
	apdm := cone
	apdm.Mapping = protocol.MapAPDM
	weak := cone
	weak.FilteringConf = protocol.ConfLow
	for _, c := range []struct {
		name       string
		self, peer protocol.Traits
		want       []Hint
	}{
		{"self", cone, open, []Hint{HintHostFirewall}},
		{"peer without NAT", open, nonat, []Hint{HintPeerHostFirewall}},
		{"both", cone, cone, []Hint{HintHostFirewall, HintPeerHostFirewall}},
		{"symmetric NAT", apdm, weak, nil},
	} {
		if got := familyHints(c.self, c.peer); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

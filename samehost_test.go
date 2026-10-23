package holepunch

import (
	"net/netip"
	"testing"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// A peer LAN address that is one of this host's own addresses is the peer
// on this host: admitted as a Direct LAN target, unless its port is one of
// this session's sockets.
func TestSameHostAdmission(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	s := openPrimary(t, rt)
	self := h.Addrs()[0]
	rt.localIPs = map[netip.Addr]struct{}{self: {}}
	w := &worker{fam: protocol.FamilyUDP4, fs: rt.fam(protocol.FamilyUDP4), verified: map[netip.Addr]bool{},
		endpoints: map[netip.AddrPort]bool{}, lan: map[netip.Addr]bool{}, reported: map[netip.Addr]bool{}}
	peer := netip.AddrPortFrom(self, s.local.Port()+1)
	if ok, _ := w.admit(rt, peer, protocol.StageDirect); ok {
		t.Fatal("an own address that is no LAN address of the peer")
	}
	w.lan[self] = true
	if ok, per := w.admit(rt, peer, protocol.StageDirect); !ok || per != protocol.LANRepeats {
		t.Fatalf("the peer on this host: %v %d", ok, per)
	}
	if ok, _ := w.admit(rt, s.local, protocol.StageDirect); ok {
		t.Fatal("this session's own socket")
	}
	if ok, _ := w.admit(rt, peer, protocol.StagePredict); ok {
		t.Fatal("a spray stage towards this host")
	}
	if ok, _ := w.admit(rt, netip.MustParseAddrPort("127.0.0.1:40000"), protocol.StageDirect); ok {
		t.Fatal("loopback")
	}
}

// Two clients on one host behind a NAT without hairpin: the public path
// cannot loop back, the peer's LAN address is the host's own, and the
// planner's LAN stage connects them.
func TestSameHostPeers(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	h := w.n.NAT(nattest.PortRestricted()).Host()
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	ps.round = func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
		return ps.plannerPlan(k, r, views, pairFacts(views))
	}
	pr := runPairHosts(t, w, [2]*nattest.Host{h, h}, ps, nil)
	defer pr.closeAll()
	wantSuccess(t, pr)
	for i, r := range pr.res {
		res := r.sess.Result()
		if res.Path.RemoteAddr.Addr() != h.Addrs()[0] || res.Path.RemoteAddr == res.Path.LocalAddr {
			t.Fatalf("client %d: %v -> %v", i, res.Path.LocalAddr, res.Path.RemoteAddr)
		}
	}
}

// admitStage is the one admission of a side's stages: punch_ready counts
// what it refuses, and the round schedule sends what it keeps.
func TestAdmitStage(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	pub := netip.MustParseAddr("203.0.113.7")
	w := &worker{fam: protocol.FamilyUDP4, fs: rt.fam(protocol.FamilyUDP4), verified: map[netip.Addr]bool{pub: true},
		endpoints: map[netip.AddrPort]bool{}, lan: map[netip.Addr]bool{}, reported: map[netip.Addr]bool{}}
	other := netip.MustParseAddr("198.51.100.9")
	side := protocol.FamilySide{Family: protocol.FamilyUDP4, Role: protocol.SideBoth, Stages: []protocol.Stage{
		{Kind: protocol.StageDirect, Targets: []netip.AddrPort{netip.AddrPortFrom(pub, 40000), netip.AddrPortFrom(other, 40000)}},
		{Kind: protocol.StagePredict, IP: pub, Anchor: 40000, Steps: []int16{1}, Span: 4},
		{Kind: protocol.StageRandom, IP: other, Count: 4},
		{Kind: protocol.StageFresh, IP: other, Count: 2, Targets: []netip.AddrPort{netip.AddrPortFrom(pub, 40001)}},
	}}
	want := []struct {
		targets  int
		ip       bool
		rejected int
	}{{1, false, 1}, {0, true, 0}, {0, false, 1}, {0, false, 1}}
	total := 0
	for i, st := range side.Stages {
		adm := w.admitStage(rt, side, st)
		if len(adm.targets) != want[i].targets || adm.ip.IsValid() != want[i].ip || adm.rejected != want[i].rejected {
			t.Errorf("stage %d: %d targets, ip %v, %d rejected", i, len(adm.targets), adm.ip, adm.rejected)
		}
		total += adm.rejected
	}
	if n := rt.countRejected(w, side); n != total || n != 3 {
		t.Fatalf("countRejected %d, stages %d", n, total)
	}
	// A reply-only side initiates nothing and refuses nothing; an
	// unverified family refuses its prediction stages whole.
	side.Role = protocol.SideReplyOnly
	if n := rt.countRejected(w, side); n != 0 {
		t.Fatalf("reply-only side: %d rejected", n)
	}
	side.Role, w.unverified = protocol.SideBoth, true
	if adm := w.admitStage(rt, side, side.Stages[1]); adm.rejected != 1 || adm.ip.IsValid() {
		t.Fatalf("unverified predict stage: %+v", adm)
	}
}

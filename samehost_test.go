package holepunch

import (
	"context"
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
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	self := h.Addrs()[0]
	rt.localIPs = map[netip.Addr]struct{}{self: {}}
	w := &worker{fam: protocol.FamilyUDP4, fs: rt.fam(protocol.FamilyUDP4), verified: map[netip.Addr]bool{},
		endpoints: map[netip.AddrPort]bool{}, lan: map[netip.Addr]bool{}, reported: map[netip.Addr]bool{}}
	peer := netip.AddrPortFrom(self, s.local.Port()+1)
	if ok, _ := w.admit(rt, peer, protocol.StageDirect); ok {
		t.Fatal("an own address that is no LAN address of the peer")
	}
	w.lan[self] = true
	if ok, per := w.admit(rt, peer, protocol.StageDirect); !ok || per != lanPacketsPerRound {
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

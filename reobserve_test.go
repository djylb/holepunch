package holepunch

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// primarySlot is natprobe's slot of role's primary socket at observer obs.
func primarySlot(t *testing.T, h nat.ProbeHandle, role protocol.Role, obs uint8) nat.Observation {
	t.Helper()
	for _, o := range h.Observations(role) {
		if o.Socket == nat.SocketID(protocol.FamilyUDP4, nat.IndexPrimary) && o.Observer == obs {
			return o
		}
	}
	t.Fatalf("no slot of the primary socket at observer %d", obs)
	return nat.Observation{}
}

// TestReobserveReportsRemap: the client's NAT changes its external IP
// between ready and go. Halfway through the silent round 1 the client
// re-observes its primary mapping, and round_result carries the new mapping
// with the cookie natprobe drew for it; round 2 does not report it again;
// a final round does not re-observe at all.
func TestReobserveReportsRemap(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	fc := w.n.NAT(nattest.FullCone())
	so := newSoloOn(t, w, fc.Host(), nil)
	to := testTimeouts()
	to.GoWaitMs = 1000
	so.startWith(to, nil)
	_, self := so.report()
	r1 := so.summary(self, fakePeer(silentPeer), to)
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	before := fc.ExternalIPs()
	fc.Rebind(nil)
	after := fc.ExternalIPs()
	if slices.Equal(before, after) {
		t.Fatalf("external IPs kept: %v", after)
	}
	round := func(k uint8, final bool) protocol.FamilyOutcome {
		t.Helper()
		g := protocol.PunchGo{SessionID: so.s.sid, Round: k, DelayMs: 5, WindowMs: r1.WindowMs, Final: final}
		if k > 1 {
			p := r1
			p.Round, p.Final = k, final
			g.Plan = &p
		}
		so.link.send(g)
		m, ok := so.link.next(5*time.Second, protocol.MsgRoundResult)
		if !ok {
			t.Fatalf("no round_result %d", k)
		}
		return m.(*protocol.RoundResult).Families[0]
	}

	f := round(1, false)
	rm := f.Remap
	if rm == nil || !f.Drift || !slices.Contains(after, rm.Observed.Addr()) {
		t.Fatalf("round 1: %+v remap %+v, want the new IP %v", f, rm, after)
	}
	slot := primarySlot(t, so.s.h, so.role, rm.Observer)
	if slot.Observed != rm.Observed || slot.Cookie != rm.Cookie || slot.Changes == 0 {
		t.Fatalf("remap %+v, natprobe slot %+v", rm, slot)
	}

	if f := round(2, false); f.Remap != nil {
		t.Fatalf("round 2 reported the known mapping again: %+v", f.Remap)
	}
	count := primarySlot(t, so.s.h, so.role, rm.Observer).Count
	if f := round(3, true); f.Remap != nil {
		t.Fatalf("final round: %+v", f.Remap)
	}
	if n := primarySlot(t, so.s.h, so.role, rm.Observer).Count; n != count {
		t.Fatalf("a final round re-observed: %d probes, was %d", n, count)
	}
}

// remapPush is the coordinator's part: the latest remap side i
// reported, pushed to the other side as peer_targets{source: drift}.
func remapPush(ps *pairScript, i int) []protocol.Assist {
	for k := len(ps.rounds[i]) - 1; k >= 0; k-- {
		for _, f := range ps.rounds[i][k].Families {
			if f.Remap != nil {
				return []protocol.Assist{{From: protocol.RoleServer, Kind: protocol.AssistPeerTargets,
					Round: ps.rounds[i][k].Round + 1, Family: f.Family, Source: protocol.TargetsDrift,
					Targets: []netip.AddrPort{f.Remap.Observed}}}
			}
		}
	}
	return nil
}

// rebindScript runs a port-restricted initiator and a full-cone responder
// against the scripted coordinator, which pushes the responder's remap to
// the initiator with the go of round push. move changes the responder's
// NAT before the go of a round. It checks that the initiator connected to
// the NAT's new IP in round push, refusing no target, and returns the run.
func rebindScript(t *testing.T, push int, move func(k int, fc *nattest.NAT)) *pairRun {
	t.Helper()
	w := newWorld(t)
	fc := w.n.NAT(nattest.FullCone())
	hosts := [2]*nattest.Host{w.n.NAT(nattest.PortRestricted()).Host(), fc.Host()}
	before := fc.ExternalIPs()
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	ps.beforeGo = func(k int) { move(k, fc) }
	ps.assistHook = func(k, i int) []protocol.Assist {
		if k == push && i == 0 {
			return remapPush(ps, 1)
		}
		return nil
	}
	pr := runPairHosts(t, w, hosts, ps, nil)
	t.Cleanup(pr.closeAll)
	after := fc.ExternalIPs()
	for i, r := range pr.res {
		if r.err != nil {
			t.Fatalf("client %d: %v (script: %v)", i, r.err, pr.scriptE)
		}
		if d := r.sess.Diagnostics(); d.Counters.TargetRejected != 0 {
			t.Fatalf("client %d refused %d targets", i, d.Counters.TargetRejected)
		}
	}
	if slices.Equal(before, after) {
		t.Fatalf("external IPs kept: %v", after)
	}
	if got := pr.res[0].sess.Result().Path.RemoteAddr.Addr(); !slices.Contains(after, got) {
		t.Fatalf("initiator connected to %v, want the new IP %v", got, after)
	}
	if got := pr.res[0].sess.Diagnostics().Path; got == nil || int(got.Round) != push {
		t.Fatalf("path %+v, want round %d", got, push)
	}
	for k, rr := range ps.rounds[0] {
		if rr.Families[0].Remap != nil {
			t.Fatalf("initiator reported a remap in round %d: %+v", k+1, rr.Families[0].Remap)
		}
	}
	return pr
}

// TestRebindBeforeGo (the e2e cell rebind/PRC-FC): the full-cone
// side's NAT moves to a new IP before the first go. Round 1 is silent both
// ways; the full-cone side's remap, pushed as peer_targets{drift}, is a new
// IP the initiator admits, and round 2 connects there.
func TestRebindBeforeGo(t *testing.T) {
	t.Parallel()
	rebindScript(t, 2, func(k int, fc *nattest.NAT) {
		if k == 1 {
			fc.Rebind(nil)
		}
	})
}

// TestRebindWhilePunching: the full-cone side's uplink is down for
// round 1 and comes back with a new IP for round 2, as after a WAN
// reconnect. Round 2's re-observation finds the new mapping and round 3
// connects to it.
func TestRebindWhilePunching(t *testing.T) {
	t.Parallel()
	rebindScript(t, 3, func(k int, fc *nattest.NAT) {
		switch k {
		case 1:
			fc.Blackhole(time.Hour)
		case 2:
			fc.Blackhole(0)
			fc.Rebind(nil)
		}
	})
}

// TestAdoptRemap: a drifted mapping the server pushes makes its IP a
// verified one for later admission — Direct and spray stages alike, the
// exact endpoint exempt from the low-port filter — while other sources
// adopt nothing, private and shared addresses are never adopted and the
// list is bounded.
func TestAdoptRemap(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	u4 := protocol.FamilyUDP4
	w := &worker{fam: u4, fs: rt.fam(u4), verified: map[netip.Addr]bool{netip.MustParseAddr("198.51.100.7"): true},
		endpoints: map[netip.AddrPort]bool{}, lan: map[netip.Addr]bool{}, reported: map[netip.Addr]bool{}}
	rt.fam(u4).worker = w
	moved := netipAP("198.51.100.77", 40000)
	push := func(src protocol.TargetSource, targets ...netip.AddrPort) (int, int) {
		out, rej := rt.peerTargets(protocol.Assist{Kind: protocol.AssistPeerTargets, Family: u4, Source: src, Targets: targets})
		return len(out), rej
	}
	if ok, _ := w.admit(rt, moved, protocol.StageDirect); ok {
		t.Fatal("an unverified IP was admitted")
	}
	if n, rej := push(protocol.TargetsInject, moved); n != 0 || rej != 1 {
		t.Fatalf("inject: %d admitted, %d refused", n, rej)
	}
	if n, rej := push(protocol.TargetsDrift, moved); n != 1 || rej != 0 {
		t.Fatalf("drift: %d admitted, %d refused", n, rej)
	}
	for _, c := range []struct {
		ap   netip.AddrPort
		kind protocol.StageKind
		want bool
	}{
		{moved, protocol.StageDirect, true},
		{netipAP("198.51.100.77", 41000), protocol.StagePredict, true},
		{netipAP("198.51.100.77", 53), protocol.StageDirect, false},
		{netipAP("198.51.100.78", 40000), protocol.StageDirect, false},
	} {
		if ok, _ := w.admit(rt, c.ap, c.kind); ok != c.want {
			t.Errorf("%v %s: admitted %v, want %v", c.ap, c.kind, ok, c.want)
		}
	}
	if n, _ := push(protocol.TargetsDrift, netipAP("198.51.100.77", 53)); n != 1 {
		t.Fatal("a pushed drifted endpoint on a low port was refused")
	}
	for _, a := range []netip.AddrPort{netipAP("100.64.1.2", 5000), netipAP("10.0.0.9", 5000)} {
		if n, _ := push(protocol.TargetsDrift, a); n != 0 || w.verifiedIP(a.Addr()) {
			t.Fatalf("%v adopted", a)
		}
	}
	for p := range maxRemapped + 4 {
		w.adoptRemap(netipAP("198.51.100.79", 20000+p))
	}
	if n := len(*w.remapped.Load()); n != maxRemapped {
		t.Fatalf("%d remapped kept", n)
	}
}

package coord

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

func peerSeen(p *pair, i int, round uint8, remote netip.AddrPort) *protocol.Assist {
	return &protocol.Assist{SessionID: p.s.ID(), Role: roleOf(i), Kind: protocol.AssistPeerSeen, Round: round,
		Family: protocol.FamilyUDP4, Remote: remote, Local: localI, Sock: 3, Cand: 4097, Type: 6, First: true}
}

// TestAssistRewrite: a forwarded peer_seen names its sender in from and
// loses local and every server-only field; other kinds are refused; nothing
// is forwarded once confirming.
func TestAssistRewrite(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	a := peerSeen(p, 0, 1, pubR)
	a.Targets = []netip.AddrPort{mustAP("8.8.8.8:53")}
	a.Window = &protocol.PortWindow{IP: netip.MustParseAddr("8.8.8.8"), Lo: 1, Hi: 2}
	a.Source = protocol.TargetsInject
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.cl[0].SendFrame(ctx(t), controlwire.TypeAssist, raw); err != nil {
		t.Fatal(err)
	}
	got := expect[protocol.Assist](t, p.cl[1])
	if got.From != protocol.RoleInitiator || got.Role != "" || got.Local.IsValid() || got.Targets != nil ||
		got.Window != nil || got.Source != "" || got.Remote != pubR || got.Cand != 4097 {
		t.Fatalf("forwarded %+v", got)
	}
	if raw, err = json.Marshal(&protocol.Assist{SessionID: p.s.ID(), Role: protocol.RoleInitiator, Kind: protocol.AssistPeerTargets,
		Round: 1, Family: protocol.FamilyUDP4, Targets: []netip.AddrPort{pubR}}); err != nil {
		t.Fatal(err)
	}
	if err := p.cl[0].SendFrame(ctx(t), controlwire.TypeAssist, raw); err != nil {
		t.Fatal(err)
	}
	send(t, p.cl[0], peerSeen(p, 0, 3, pubR)) // a future round
	p.confirm(1, 1)
	p.state(StateConfirming)
	send(t, p.cl[0], peerSeen(p, 0, 1, pubR))
	p.waitCounters(func(c Counters) bool { return c.AssistDropped == 1 })
	p.confirm(0, 1)
	p.succeed(0, 1)
	p.succeed(1, 1)
	res := r.wait(p.s)
	if res.Counters.AssistForwarded != 1 || res.Counters.AssistRejected != 3 || res.Counters.AssistDropped != 1 {
		t.Fatalf("counters %+v", res.Counters)
	}
}

// TestAssistLimits: peer_seen beyond the per-round quota or the rates is
// dropped and counted, never fatal.
func TestAssistLimits(t *testing.T) {
	t.Run("per round", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.Limits.AssistPerRound = 2 })
		p := r.pair(SessionOptions{})
		p.punching()
		for range 4 {
			send(t, p.cl[0], peerSeen(p, 0, 1, pubR))
		}
		for range 2 {
			expect[protocol.Assist](t, p.cl[1])
		}
		p.waitCounters(func(c Counters) bool { return c.AssistDropped == 2 })
		p.s.Abort(protocol.ReasonCanceled, "")
		if res := r.wait(p.s); res.Counters.AssistForwarded != 2 || res.Counters.AssistDropped != 2 {
			t.Fatalf("counters %+v", res.Counters)
		}
	})
	t.Run("rates", func(t *testing.T) {
		r := newRig(t, func(c *Config) {
			c.Limits.AssistIn = Rate{PerSec: 1, Burst: 3}
			c.Limits.AssistRelay = Rate{PerSec: 1, Burst: 2}
		})
		p := r.pair(SessionOptions{})
		p.punching()
		for range 5 {
			send(t, p.cl[0], peerSeen(p, 0, 1, pubR))
		}
		p.waitCounters(func(c Counters) bool { return c.AssistForwarded+c.AssistDropped == 5 })
		p.s.Abort(protocol.ReasonCanceled, "")
		if res := r.wait(p.s); res.Counters.AssistForwarded != 2 || res.Counters.AssistDropped != 3 {
			t.Fatalf("counters %+v", res.Counters)
		}
	})
	t.Run("peer gone", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		_ = p.cl[1].Close()
		eventually(t, "gone", func() bool {
			p.s.mu.Lock()
			defer p.s.mu.Unlock()
			return p.s.st.gone[1]
		})
		send(t, p.cl[0], peerSeen(p, 0, 1, pubR))
		p.waitCounters(func(c Counters) bool { return c.AssistDropped == 1 })
		p.s.Abort(protocol.ReasonCanceled, "")
		if res := r.wait(p.s); res.Counters.AssistDropped != 1 {
			t.Fatalf("counters %+v", res.Counters)
		}
	})
	t.Run("evidence", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		send(t, p.cl[1], peerSeen(p, 1, 1, pubI))
		expect[protocol.Assist](t, p.cl[0])
		p.s.mu.Lock()
		ev := p.s.st.ev
		p.s.mu.Unlock()
		if len(ev.SeenFrom[1]) != 1 || ev.SeenFrom[1][0] != pubI || !ev.PeerSeenUs[0] {
			t.Fatalf("evidence %+v", ev)
		}
		p.s.Abort(protocol.ReasonCanceled, "")
		r.wait(p.s)
	})
}

// TestInject: injected targets pass admission and the per-round limit and
// go out as peer_targets{source: inject}; only while punching.
func TestInject(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Limits.TargetsPerRound = 1 })
	p := r.pair(SessionOptions{})
	a := protocol.Assist{Family: protocol.FamilyUDP4, Targets: []netip.AddrPort{netip.AddrPortFrom(pubR.Addr(), 7000)}}
	if err := p.s.Inject(protocol.RoleInitiator, a); !invalidArgument(err) {
		t.Fatalf("before punching: %v", err)
	}
	if err := p.s.Inject("x", a); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("bad role: %v", err)
	}
	p.punching()
	if err := p.s.Inject(protocol.RoleInitiator, protocol.Assist{Family: protocol.FamilyUDP4,
		Targets: []netip.AddrPort{mustAP("8.8.8.8:53")}}); !invalidArgument(err) {
		t.Fatalf("third-party target: %v", err)
	}
	if err := p.s.Inject(protocol.RoleInitiator, protocol.Assist{Family: "x"}); !invalidArgument(err) {
		t.Fatalf("bad family: %v", err)
	}
	// Nothing left of the session budget: nothing to push.
	p.s.mu.Lock()
	granted := p.s.st.granted[0]
	p.s.st.granted[0] = int(p.s.budget.MaxPackets)
	p.s.mu.Unlock()
	if err := p.s.Inject(protocol.RoleInitiator, a); !errors.Is(err, ErrBusy) || !strings.Contains(err.Error(), "packets") {
		t.Fatalf("without budget: %v", err)
	}
	p.s.mu.Lock()
	p.s.st.granted[0] = granted
	p.s.mu.Unlock()
	if err := p.s.Inject(protocol.RoleInitiator, a); err != nil {
		t.Fatal(err)
	}
	got := expect[protocol.Assist](t, p.cl[0])
	if got.Kind != protocol.AssistPeerTargets || got.From != protocol.RoleServer || got.Source != protocol.TargetsInject ||
		len(got.Targets) != 1 || got.Round != 1 {
		t.Fatalf("peer_targets %+v", got)
	}
	if err := p.s.Inject(protocol.RoleInitiator, a); !errors.Is(err, ErrBusy) {
		t.Fatalf("over the round limit: %v", err)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	res := r.wait(p.s)
	if err := p.s.Inject(protocol.RoleInitiator, a); !errors.Is(err, ErrSessionDone) {
		t.Fatalf("after the end: %v", err)
	}
	if res.Counters.PeerTargets != 1 || len(r.waitEvents(EvPeerTargets, 1)) != 1 {
		t.Fatalf("counters %+v", res.Counters)
	}
}

// TestInjectBounds: an injected window at the top of the port range is
// cut to 64 ports without wrapping around, and a malformed Meta is the
// caller's invalid argument, not a busy link.
func TestInjectBounds(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	p.s.mu.Lock()
	p.s.st.pair.Unverified = nil // as with a registry: a window needs a verified family
	p.s.mu.Unlock()
	bad := protocol.Assist{Family: protocol.FamilyUDP4, Targets: []netip.AddrPort{pubR}, Meta: map[string]string{"": "x"}}
	if err := p.s.Inject(protocol.RoleInitiator, bad); !invalidArgument(err) {
		t.Fatalf("malformed meta: %v", err)
	}
	top := protocol.Assist{Family: protocol.FamilyUDP4, Window: &protocol.PortWindow{IP: pubR.Addr(), Lo: 65500, Hi: 65535}}
	if err := p.s.Inject(protocol.RoleInitiator, top); err != nil {
		t.Fatal(err)
	}
	got := expect[protocol.Assist](t, p.cl[0])
	if w := got.Window; w == nil || w.Lo != 65500 || w.Hi != 65535 {
		t.Fatalf("window %+v", got.Window)
	}
	if err := got.ValidateRelayed(); err != nil {
		t.Fatalf("the client refuses the push: %v", err)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

func TestSandwichWindow(t *testing.T) {
	cases := []struct{ a, b, lo, hi uint16 }{
		{1000, 1004, 1001, 1003},
		{1004, 1000, 1001, 1003},
		{1000, 1001, 0, 0},
		{1000, 2000, 1500 - 31, 1500 - 31 + 63},
		{1, 1000, 500 - 31, 500 - 31 + 63},
	}
	for _, c := range cases {
		lo, hi := sandwichWindow(c.a, c.b)
		if lo != c.lo || hi != c.hi {
			t.Errorf("window(%d, %d) = [%d, %d], want [%d, %d]", c.a, c.b, lo, hi, c.lo, c.hi)
		}
	}
}

// TestSandwichEvents: the two sandwich probes of the predicted side become a
// window pushed to the other side; events of other rounds, roles without a
// sandwich and a full mailbox are dropped without blocking the sink.
func TestSandwichEvents(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	p.s.mu.Lock()
	p.s.st.cur.sandwich[1][0] = true // the responder runs the sandwich probe in IPv4
	p.s.st.pair.Unverified = nil     // as with a registry: a window needs a verified family
	p.s.mu.Unlock()
	ip := pubR.Addr()
	ev := func(role protocol.Role, round, phase uint8, port uint16) nat.SandwichEvent {
		return nat.SandwichEvent{Role: role, Round: round, Phase: phase, Observed: netip.AddrPortFrom(ip, port), At: r.clk.Now()}
	}
	p.s.onSandwich(ev(protocol.RoleInitiator, 1, nat.SandwichBefore, 100)) // no sandwich for the initiator
	p.s.onSandwich(ev(protocol.RoleResponder, 2, nat.SandwichBefore, 100)) // another round
	p.s.onSandwich(ev(protocol.RoleResponder, 1, nat.SandwichBefore, 61000))
	p.s.onSandwich(ev(protocol.RoleResponder, 1, nat.SandwichAfter, 61004))
	for range 10 {
		p.s.onSandwich(ev(protocol.RoleResponder, 1, nat.SandwichAfter, 61004)) // the mailbox holds 8
	}
	r.clk.Advance(0)
	got := expect[protocol.Assist](t, p.cl[0])
	if got.Source != protocol.TargetsSandwich || got.Window == nil || got.Window.IP != ip ||
		got.Window.Lo != 61001 || got.Window.Hi != 61003 {
		t.Fatalf("sandwich targets %+v", got)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
	p.s.onSandwich(ev(protocol.RoleResponder, 1, nat.SandwichBefore, 1)) // after the end: ignored
}

// TestSandwichPerFamily: a dual-stack side runs the sandwich in both families;
// the probes interleave, and each family's pair still brackets its own punches
// — an IPv6 probe never completes an IPv4 half.
func TestSandwichPerFamily(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	p.s.mu.Lock()
	p.s.st.cur.sandwich[1] = [2]bool{true, true}
	p.s.st.pair.Unverified = nil
	p.s.mu.Unlock()
	v4, v6 := pubR.Addr(), netip.MustParseAddr("2001:db8::77")
	for _, e := range []struct {
		ip    netip.Addr
		phase uint8
		port  uint16
	}{{v4, nat.SandwichBefore, 61000}, {v6, nat.SandwichBefore, 7000}, {v4, nat.SandwichAfter, 61004}, {v6, nat.SandwichAfter, 9000}} {
		p.s.onSandwich(nat.SandwichEvent{Role: protocol.RoleResponder, Round: 1, Phase: e.phase,
			Observed: netip.AddrPortFrom(e.ip, e.port), At: r.clk.Now()})
	}
	r.clk.Advance(0)
	got := expect[protocol.Assist](t, p.cl[0])
	if got.Window == nil || got.Window.IP != v4 || got.Window.Lo != 61001 || got.Window.Hi != 61003 {
		t.Fatalf("sandwich targets %+v", got)
	}
	p.s.mu.Lock()
	h4, h6 := p.s.st.sandHalf[1][0], p.s.st.sandHalf[1][1]
	p.s.mu.Unlock()
	if !h4.sent || h4.before.Addr() != v4 || h4.after.Addr() != v4 || h6.before.Addr() != v6 || h6.after.Addr() != v6 {
		t.Fatalf("halves v4 %+v v6 %+v", h4, h6)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

// TestLatePortMap: a port mapping that finished after the report goes to
// the peer as peer_targets{source: portmap} after the first go, when its IP
// is verified.
func TestLatePortMap(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	sums := p.summaries()
	ready := simclient.Ready(sums[0], protocol.RoleInitiator, 1)
	ready.Families[0].PortMap = &protocol.PortMapReport{Method: protocol.PortMapUPnP,
		External: netip.AddrPortFrom(pubI.Addr(), 41000), Internal: localI, LeaseSeconds: 60}
	send(t, p.cl[0], &ready)
	send(t, p.cl[1], simclient.Ready(sums[1], protocol.RoleResponder, 1))
	expect[protocol.PunchGo](t, p.cl[1])
	got := expect[protocol.Assist](t, p.cl[1])
	if got.Source != protocol.TargetsPortmap || len(got.Targets) != 1 || got.Targets[0].Port() != 41000 {
		t.Fatalf("portmap targets %+v", got)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

// TestLatePortMapOnce: a second late public mapping of a family that already
// has one queued is dropped, and drift is pushed only for a side's verified
// IPs.
func TestLatePortMapOnce(t *testing.T) {
	_, s := testSession(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	u4 := protocol.FamilyUDP4
	for _, port := range []uint16{41000, 41001} {
		s.latePortMapLocked(0, u4, protocol.PortMapReport{Method: protocol.PortMapUPnP,
			External: netip.AddrPortFrom(pubI.Addr(), port), Internal: localI, LeaseSeconds: 60}, 0)
	}
	if q := s.st.portmap[1]; len(q) != 1 || q[0].Targets[0].Port() != 41000 {
		t.Fatalf("queued %+v", q)
	}
	if s.st.knownIP(0, u4, mustAP("192.0.2.200:1").Addr()) || !s.st.knownIP(0, u4, pubI.Addr()) {
		t.Fatal("knownIP")
	}
}

// TestSandwichAdjacent: two sandwich probes on adjacent ports leave no port
// between them: no window is pushed and the half stays open for the round.
func TestSandwichAdjacent(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	p.s.mu.Lock()
	p.s.st.cur.sandwich[1][0] = true
	p.s.st.pair.Unverified = nil
	p.s.mu.Unlock()
	for phase, port := range map[uint8]uint16{nat.SandwichBefore: 500, nat.SandwichAfter: 501} {
		p.s.onSandwich(nat.SandwichEvent{Role: protocol.RoleResponder, Round: 1, Phase: phase,
			Observed: netip.AddrPortFrom(pubR.Addr(), port), At: r.clk.Now()})
	}
	r.clk.Advance(0)
	eventually(t, "sandwich handled", func() bool {
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		h := p.s.st.sandHalf[1][0]
		return len(p.s.st.sandBox) == 0 && h.before.IsValid() && h.after.IsValid()
	})
	p.s.mu.Lock()
	sent, pushed := p.s.st.sandHalf[1][0].sent, p.s.st.ctr.PeerTargets
	p.s.mu.Unlock()
	if sent || pushed != 0 {
		t.Fatalf("window pushed: sent %v, peer_targets %d", sent, pushed)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

// TestDriftVerification: a moved primary mapping on an IP the side
// was verified on is pushed as it is; one on another IP only after the side
// echoed the slot's cookie for that very value, and never a private one;
// what the peer has in its summary, or was pushed before, is not pushed.
func TestDriftVerification(t *testing.T) {
	_, s := testSession(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	u4 := protocol.FamilyUDP4
	primary := nat.SocketID(u4, nat.IndexPrimary)
	st.views[0] = protocol.PeerView{Families: []protocol.FamilyView{{Family: u4,
		Endpoints: []protocol.Endpoint{{Addr: pubI, Source: protocol.EndpointServer, Verified: true}}}}}
	slot := func(a netip.AddrPort, cookie uint32) natprobe.ServerObservation {
		return natprobe.ServerObservation{Socket: primary, Observer: 1, Observed: a, Changes: 1, Cookie: cookie}
	}
	take := func(o natprobe.ServerObservation) []netip.AddrPort {
		t.Helper()
		st.pending[1] = nil
		s.takeDriftLocked([2][]natprobe.ServerObservation{{o}, nil})
		var out []netip.AddrPort
		for _, a := range st.pending[1] {
			if a.Source != protocol.TargetsDrift || a.Family != u4 {
				t.Fatalf("queued %+v", a)
			}
			out = append(out, a.Targets...)
		}
		return out
	}
	port := netip.AddrPortFrom(pubI.Addr(), 41000)
	moved := mustAP("198.51.100.77:40000")
	cgn := mustAP("100.64.3.4:5000")
	steps := []struct {
		name string
		echo *protocol.Remap
		o    natprobe.ServerObservation
		want int
	}{
		{"in the summary", nil, slot(pubI, 5), 0},
		{"new port, verified IP", nil, slot(port, 0), 1},
		{"pushed before", nil, slot(port, 0), 0},
		{"new IP, no echo", nil, slot(moved, 9), 0},
		{"echo of another cookie", &protocol.Remap{Observer: 1, Observed: moved, Cookie: 8}, slot(moved, 9), 0},
		{"echo at another observer", &protocol.Remap{Observer: 2, Observed: moved, Cookie: 9}, slot(moved, 9), 0},
		{"echo", &protocol.Remap{Observer: 1, Observed: moved, Cookie: 9}, slot(moved, 9), 1},
		{"shared address space", &protocol.Remap{Observer: 1, Observed: cgn, Cookie: 3}, slot(cgn, 3), 0},
	}
	for _, c := range steps {
		st.remaps[0][0] = c.echo
		if got := take(c.o); len(got) != c.want || c.want == 1 && got[0] != c.o.Observed {
			t.Fatalf("%s: pushed %v", c.name, got)
		}
	}
	if !st.knownIP(0, u4, moved.Addr()) || st.knownIP(0, u4, cgn.Addr()) {
		t.Fatalf("verified %v", st.verified[0][u4])
	}
}

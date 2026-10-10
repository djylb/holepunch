package holepunch

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/clock"
	"github.com/djylb/holepunch/internal/leak"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// countingClock counts every use of the clock, to prove that an idle session
// does not poll.
type countingClock struct {
	inner Clock
	calls atomic.Int64
}

func (c *countingClock) Now() time.Time { c.calls.Add(1); return c.inner.Now() }
func (c *countingClock) NewTimer(d time.Duration) Timer {
	c.calls.Add(1)
	return c.inner.NewTimer(d)
}
func (c *countingClock) AfterFunc(d time.Duration, f func()) Timer {
	c.calls.Add(1)
	return c.inner.AfterFunc(d, f)
}

// While it waits for the server, a session wakes for nothing: no clock use,
// no timer, no read deadline (no polling).
func TestIdleZeroPolling(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	cc := &countingClock{inner: clock.System{}}
	so := newSolo(t, w, nil, func(o *Options) { o.Clock = cc })
	to := testTimeouts()
	to.GoWaitMs = 15000
	so.start(to)
	_, self := so.report()
	idle := func(what string) {
		time.Sleep(150 * time.Millisecond) // let the phase settle
		before := cc.calls.Load()
		time.Sleep(time.Second)
		if d := cc.calls.Load() - before; d != 0 {
			t.Fatalf("%s: %d clock calls in an idle second", what, d)
		}
	}
	idle("waiting for summary")
	so.summary(self, fakePeer("203.0.113.99:4000"), to)
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	idle("waiting for go")
	so.cancel()
	so.wantFailure(so.result(5*time.Second), protocol.ReasonCanceled)
}

// The local budget caps the session: with nothing heard back the session
// reports budget_exhausted and fails with packet_budget_exceeded.
func TestBudgetExceeded(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, func(o *Options) {
		o.Policy = &protocol.Policy{Budget: protocol.Budget{MaxPackets: 3}}
	})
	to := testTimeouts()
	to.GoWaitMs = 500
	so.start(to)
	_, self := so.report()
	r1 := so.summary(self, fakePeer("203.0.113.99:4000"), to)
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, WindowMs: r1.WindowMs})
	m, ok := so.link.next(5*time.Second, protocol.MsgRoundResult)
	if !ok {
		t.Fatal("no round_result")
	}
	rr := m.(*protocol.RoundResult)
	if rr.Status != protocol.RoundBudgetExhausted || rr.Families[0].Sent != 3 || !rr.Families[0].BudgetHit {
		t.Fatalf("round_result %+v", rr)
	}
	e := so.wantError(so.result(5*time.Second), protocol.ReasonPacketBudgetExceeded)
	if e.Diagnostics.Counters.BudgetUsedPct != 100 || e.Diagnostics.Counters.TxPackets != 3 {
		t.Fatalf("counters %+v", e.Diagnostics.Counters)
	}
}

// Every probe write fails: udp_blocked within the probe timeout.
func TestProbeUDPBlocked(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	so.host.FailWrites("", -1, syscall.EPERM)
	so.start(testTimeouts())
	pr := so.punchResult()
	if pr.Code != protocol.ReasonUDPBlocked {
		t.Fatalf("punch_result %+v", pr)
	}
	so.wantFailure(so.result(5*time.Second), protocol.ReasonUDPBlocked)
}

// Observers that never answer and no send error: probe_timeout.
func TestProbeTimeout(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	ps := w.startFor(so.s, so.role, testTimeouts(), nil)
	for i := range ps.Probe.Observers {
		ps.Probe.Observers[i].Addr = netipAP("192.0.2.200", 3478+i)
	}
	so.open().send(ps)
	if pr := so.punchResult(); pr.Code != protocol.ReasonProbeTimeout {
		t.Fatalf("punch_result %+v", pr)
	}
	so.wantFailure(so.result(5*time.Second), protocol.ReasonProbeTimeout)
}

// Two hosts behind one NAT: same public IP, so LAN targets are admitted and
// the hairpin self-test runs; the session connects.
func TestSameNATPair(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	cfg := nattest.PortRestricted()
	cfg.Hairpin = true
	nat := w.n.NAT(cfg)
	hosts := [2]*nattest.Host{nat.Host(), nat.Host()}
	ps := &pairScript{w: w, timeouts: testTimeouts(), round: func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
		p := directPlan(k, r, views)
		for _, e := range views[1-roleIndex(r)].Families[0].Endpoints {
			if e.Source == protocol.EndpointLAN {
				p.Sides[0].Stages[0].Targets = append(p.Sides[0].Stages[0].Targets, e.Addr)
			}
		}
		return p
	}}
	pr := runPairHosts(t, w, hosts, ps, nil)
	defer pr.closeAll()
	wantSuccess(t, pr)
}

// Real sockets end to end through probing: a session on the OS network
// leaves no descriptor behind.
func TestSystemNetworkNoFDLeak(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	srv, err := natprobe.NewServer(natprobe.ServerConfig{Registry: reg, Groups: []natprobe.ObserverGroup{{Bind: lo}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Skip("no loopback observer:", err)
	}
	defer func() { _ = srv.Close() }()
	run := func() {
		sid, token, wire := protocol.NewSessionID(), protocol.NewToken(), protocol.NewWireSpec()
		h, err := reg.Register(natprobe.Registration{SessionID: sid, Route: wire.RouteID, Token: token, TTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		a, b := net.Pipe()
		defer func() { _ = a.Close() }()
		defer func() { _ = b.Close() }()
		tn := leak.NewTrackingNetwork(SystemNetwork())
		res := runClient(context.Background(), a, Options{ControlSecurity: protocol.ControlSecurityDeclared, Network: tn, LocalAddr: lo})
		l := newSrvLink(t, b, protocol.RoleInitiator, sid)
		defer l.close()
		to := testTimeouts()
		to.SummaryWaitMs = 1000
		l.send(protocol.PunchStart{SessionID: sid, Role: protocol.RoleInitiator, Token: token, Wire: wire, Control: protocol.DefaultControlSpec(),
			Probe: protocol.ProbeSpec{V: protocol.ProbeSpecVersion, Observers: srv.Observers(protocol.FamilyUDP4)}, Timeouts: to})
		if _, ok := l.next(10*time.Second, protocol.MsgProbeReport); !ok {
			t.Fatal("no report on the OS network")
		}
		r := <-res
		if r.err == nil {
			t.Fatal("expected the summary timeout")
		}
		if err := tn.CheckOpen(0); err != nil {
			t.Fatal(err)
		}
	}
	run() // warm the runtime's poller descriptors
	base, err := leak.OpenFDs()
	if err != nil {
		t.Skip(err)
	}
	run()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := leak.CheckFDs(ctx, base); err != nil {
		t.Fatal(err)
	}
}

// A TLS control connection passes the default security check.
func TestTLSControlAccepted(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	h := w.host(nil)
	c, s := w.pipe(h, 0)
	defer func() { _ = s.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	res := runClient(ctx, tlsDone{c}, Options{Network: h})
	time.Sleep(50 * time.Millisecond)
	cancel()
	r := <-res
	var e *Error
	if !errors.As(r.err, &e) || e.Reason != protocol.ReasonCanceled {
		t.Fatalf("got %v", r.err)
	}
}

// tlsDone is a connection that reports a completed TLS handshake.
type tlsDone struct{ net.Conn }

func (tlsDone) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{HandshakeComplete: true}
}

// The session deadline and the waits mirroring server deadlines (+2 s); T is
// compressed to 150 s by shrinking summary_wait and handshake.
func TestComputeWaits(t *testing.T) {
	rt := &runtime{timeouts: protocol.DefaultTimeouts().Normalize()}
	rt.computeWaits()
	if rt.waits.total+startWait != 71*time.Second || rt.waits.summary != 22*time.Second ||
		rt.waits.goWait != 7*time.Second || rt.waits.handshake != 20*time.Second {
		t.Fatalf("defaults %+v", rt.waits)
	}
	rt.timeouts = protocol.Timeouts{ProbeTimeoutMs: 10000, SummaryWaitMs: 60000, GoWaitMs: 15000, HandshakeTimeoutMs: 60000,
		HandoverTimeoutMs: 10000, TransportTimeoutMs: 10000, MaxRounds: 6}
	rt.computeWaits()
	if got := rt.waits.total + startWait; got > maxTotal || got < maxTotal-time.Second {
		t.Fatalf("compressed T %v", got)
	}
	if rt.waits.handshake >= 60*time.Second || rt.waits.summary >= 62*time.Second {
		t.Fatalf("not compressed %+v", rt.waits)
	}
}

// Relay-only mode: the peer's self-reported public endpoint is a
// direct target, spray stages are refused, and the warning is set; a large
// clock offset is diagnosed too.
func TestUnverifiedModeAndClockSkew(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	to.GoWaitMs = 500
	so.start(to)
	_, self := so.report()
	peer := fakePeer("203.0.113.99:4000")
	peer.Families[0].Endpoints[0].Verified = false
	r1 := protocol.RoundPlan{Round: 1, Variant: "relay", Budget: protocol.BudgetLight, WindowMs: 800,
		Sides: []protocol.FamilySide{{Family: protocol.FamilyUDP4, Role: protocol.SideBoth, Sockets: 1, MaxPackets: 40, MaxPPS: 80,
			MaxNewPerSec: 100, MaxDistinctPorts: 16, Stages: []protocol.Stage{
				{Kind: protocol.StageDirect, Targets: []netip.AddrPort{netipAP("203.0.113.99", 4000), netipAP("203.0.113.98", 4000)}, Repeats: 3},
				{Kind: protocol.StageRandom, IP: netip.MustParseAddr("203.0.113.99"), Count: 10}}}}}
	so.link.send(protocol.ProbeSummary{SessionID: so.s.sid, Self: self, Peer: peer,
		Pair: protocol.PairFacts{SharedFamilies: []protocol.Family{protocol.FamilyUDP4}, Unverified: map[protocol.Family]bool{protocol.FamilyUDP4: true},
			ClockOffsetMs: map[protocol.Role]int64{protocol.RoleInitiator: 400000}},
		Timeouts: to, Plan: protocol.PlanSpec{ID: "p", PairClass: "test", RoundsMax: 1, Budget: protocol.DefaultBudget(), Round1: r1}})
	m, ok := so.link.next(5*time.Second, protocol.MsgPunchReady)
	if !ok || m.(*protocol.PunchReady).Families[0].Rejected != 2 {
		t.Fatalf("ready %+v", m)
	}
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, WindowMs: r1.WindowMs})
	e := so.wantError(so.result(10*time.Second), protocol.ReasonCandidateTimeout)
	c := e.Diagnostics.Counters
	if c.TxByStage["direct"] != 3 || c.TxByStage["random"] != 0 || c.TargetRejected < 2 {
		t.Fatalf("counters %+v", c)
	}
	warn := map[string]bool{}
	for _, x := range e.Diagnostics.Warn {
		warn[x] = true
	}
	if !warn[protocol.WarnUnverifiedTargets] || !warn[protocol.WarnClockSkew] {
		t.Fatalf("warn %v", e.Diagnostics.Warn)
	}
}

// Options.LocalAddr binds the primary socket on that address.
func TestLocalAddrOption(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	var want [2]netip.Addr
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, &pairScript{w: w, timeouts: testTimeouts()}, func(i int, o *Options) {
		want[i] = o.Network.(*nattest.Host).Addrs()[0]
		o.LocalAddr = want[i]
	})
	defer pr.closeAll()
	wantSuccess(t, pr)
	for i := range 2 {
		if got := pr.res[i].sess.Result().Path.LocalAddr.Addr(); got != want[i] {
			t.Fatalf("client %d local %v want %v", i, got, want[i])
		}
	}
}

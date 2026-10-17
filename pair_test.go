package holepunch

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/leak"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

func prc() *nattest.NATConfig { return natCfg(nattest.PortRestricted()) }

func wantSuccess(t *testing.T, pr *pairRun) {
	t.Helper()
	for i, r := range pr.res {
		if r.err != nil {
			t.Fatalf("client %d: %v (script: %v)", i, r.err, pr.scriptE)
		}
	}
}

// The winning socket is clean when handed over and the library never
// touches it again; the socket accounting balances.
func TestHandoverZeroTouch(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	var tracks [2]*leak.TrackingNetwork
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(i int, o *Options) {
		tracks[i] = leak.NewTrackingNetwork(o.Network)
		o.Network = tracks[i]
	})
	defer pr.closeAll()
	wantSuccess(t, pr)
	var app [2]net.PacketConn
	for i, r := range pr.res {
		if err := tracks[i].CheckOpen(1); err != nil {
			t.Fatal(err)
		}
		c, err := pr.hosts[i].MarkHandover(r.sess.Result().Path.LocalAddr)
		if err != nil {
			t.Fatal(err)
		}
		app[i] = c
		if r.sess.PacketConn() == nil || !slices.Equal(r.sess.codec.Peers(), []netip.AddrPort{r.sess.Result().Path.RemoteAddr}) {
			t.Fatalf("client %d: residual filter not bound to the peer", i)
		}
		if ps.results[i] == nil || !ps.results[i].OK || ps.results[i].Path == nil || ps.results[i].Path.ConfirmedBy == "" {
			t.Fatalf("client %d punch_result %+v", i, ps.results[i])
		}
	}
	// A read without deadline gets the peer's packet.
	got := make(chan error, 1)
	go func() {
		b := make([]byte, 1500)
		_, _, err := app[1].ReadFrom(b)
		got <- err
	}()
	if _, err := app[0].WriteTo([]byte("upper layer"), net.UDPAddrFromAddrPort(pr.res[0].sess.Result().Path.RemoteAddr)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handed-over socket did not receive")
	}
	time.Sleep(300 * time.Millisecond)
	for i := range 2 {
		if n := pr.hosts[i].Stats().WritesAfterHandover; n != 0 {
			t.Fatalf("client %d: %d library calls after handover", i, n)
		}
	}
	pr.closeAll()
	for i := range 2 {
		if err := tracks[i].CheckClosed(); err != nil {
			t.Fatal(err)
		}
		if err := pr.res[i].sess.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	}
}

// The server closes both control links right after the confirmations;
// both clients still hand over over UDP.
func TestServerGoneAfterConfirm(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts(), stopAfterConfirm: true}
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, nil)
	defer pr.closeAll()
	wantSuccess(t, pr)
}

// Handover under 30 % loss in both directions: the four-step
// handshake recovers through its retransmissions and the quiet inference.
func TestHandoverUnderLoss(t *testing.T) {
	t.Parallel()
	ok := 0
	const runs = 6
	for i := range runs {
		w := newWorld(t, nattest.WithSeed(int64(100+i)), nattest.WithCoreLink(nattest.LinkConfig{Loss: 0.3, Delay: 10 * time.Millisecond}))
		ps := &pairScript{w: w, timeouts: testTimeouts(), round: directPlan}
		pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, nil)
		if pr.res[0].err == nil && pr.res[1].err == nil {
			ok++
		} else {
			t.Logf("run %d: %v / %v", i, pr.res[0].err, pr.res[1].err)
		}
		pr.closeAll()
	}
	if ok < runs-1 {
		t.Fatalf("%d/%d sessions succeeded under 30%% loss", ok, runs)
	}
}

// A symmetric NAT against a port-restricted cone: the planner's predict
// stages and extra sockets do the work.
func TestPairSymmetricSequential(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	pr := runPair(t, w, [2]*nattest.NATConfig{natCfg(nattest.SymmetricSeq(1)), prc()}, ps, nil)
	defer pr.closeAll()
	wantSuccess(t, pr)
	d := pr.res[0].sess.Diagnostics()
	if d.Counters.TxPackets == 0 || len(d.Families) != 1 || d.Families[0].Strategy == "" {
		t.Fatalf("diagnostics %+v", d)
	}
}

// Progress reaches the callback in order, a panicking callback is counted
// and the session goes on; no call happens after Punch returns.
func TestProgressCallback(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	var mu sync.Mutex
	var stages []string
	var after atomic.Bool
	var returned atomic.Bool
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(i int, o *Options) {
		if i != 0 {
			return
		}
		o.OnProgress = func(p protocol.Progress) {
			if returned.Load() {
				after.Store(true)
			}
			mu.Lock()
			stages = append(stages, p.Stage)
			mu.Unlock()
			if p.Meta["insecure"] != "1" || p.Meta["session_phase"] == "" {
				panic("meta missing")
			}
			if p.Stage == stageFire {
				panic("callback panic")
			}
		}
	})
	returned.Store(true)
	defer pr.closeAll()
	wantSuccess(t, pr)
	time.Sleep(50 * time.Millisecond)
	if after.Load() {
		t.Fatal("callback after return")
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{stageProbeStarted, stageProbeDone, stageSummaryReceived, stageReadySent, stageGoReceived, stageFire, stageConfirmed, stageHandoverDone}
	for _, s := range want {
		found := false
		for _, g := range stages {
			found = found || g == s
		}
		if !found {
			t.Fatalf("stage %s missing from %v", s, stages)
		}
	}
	d := pr.res[0].sess.Diagnostics()
	if d.Counters.CallbackPanics == 0 {
		t.Fatal("callback panic not counted")
	}
	if d.Warn[0] != protocol.WarnInsecureControlForTesting {
		t.Fatalf("warn %v", d.Warn)
	}
}

// fakeMapper is a PortMapper that maps every socket to a fixed external
// address and counts releases.
type fakeMapper struct {
	ext      netip.AddrPort
	mapped   atomic.Int32
	released atomic.Int32
	delay    time.Duration
}

func (m *fakeMapper) Map(ctx context.Context, _ net.PacketConn, _ protocol.PortMappingPolicy) (protocol.PortMappingInfo, func() error, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return protocol.PortMappingInfo{}, nil, ctx.Err()
		}
	}
	m.mapped.Add(1)
	var once sync.Once
	return protocol.PortMappingInfo{Method: protocol.PortMapPCP, External: m.ext, Lease: time.Hour},
		func() error { once.Do(func() { m.released.Add(1) }); return nil }, nil
}

// A port mapping is reported in probe_report, the losing sockets release
// theirs at the end, and the winner's moves to Session.Close.
func TestPortMapping(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	var maps [2]*fakeMapper
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(i int, o *Options) {
		maps[i] = &fakeMapper{ext: netip.MustParseAddrPort("198.51.100.200:30000")}
		if i == 1 {
			maps[i].delay = 120 * time.Millisecond // finishes after probe_report
		}
		o.PortMapper = maps[i]
	})
	defer pr.closeAll()
	wantSuccess(t, pr)
	for i := range 2 {
		if maps[i].mapped.Load() != 1 || maps[i].released.Load() != 0 {
			t.Fatalf("client %d: mapped %d released %d", i, maps[i].mapped.Load(), maps[i].released.Load())
		}
		res := pr.res[i].sess.Result()
		if res.Path.PortMapping == nil || res.Path.Keepalive.Reason != KeepalivePortmapped {
			t.Fatalf("client %d result %+v", i, res)
		}
	}
	pr.closeAll()
	for i := range 2 {
		if maps[i].released.Load() != 1 {
			t.Fatalf("client %d: winner mapping not released by Close", i)
		}
	}
}

// Multi-socket rounds with random stages (a birthday-style round), the
// sandwich probe and peer_targets: everything goes through the gate.
func TestMultiSocketRoundAndAssists(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	to := testTimeouts()
	to.MaxRounds = 2
	var targets [2]netip.AddrPort
	ps := &pairScript{w: w, timeouts: to, round: func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
		p := directPlan(k, r, views)
		peer := views[1-roleIndex(r)].Families[0].Endpoints[0].Addr
		targets[roleIndex(r)] = peer
		p.Sides[0].Sandwich = true
		p.Budget = protocol.BudgetBalanced
		p.Sides[0].Sockets = 4
		p.Sides[0].MaxPackets = 400
		p.Sides[0].MaxDistinctPorts = 64
		p.Sides[0].Stages = append(p.Sides[0].Stages,
			protocol.Stage{Kind: protocol.StageRandom, IP: peer.Addr(), Count: 24, Lo: 40000, Hi: 40100},
			protocol.Stage{Kind: protocol.StagePredict, IP: peer.Addr(), Anchor: 41000, Steps: []int16{1}, Span: 8, AtMs: 20})
		return p
	}, assistHook: func(k, i int) []protocol.Assist {
		if i != 0 {
			return nil
		}
		return []protocol.Assist{{Kind: protocol.AssistPeerTargets, Round: uint8(k), Family: protocol.FamilyUDP4, From: protocol.RoleServer,
			Targets: []netip.AddrPort{targets[0]}, Source: protocol.TargetsInject}}
	}}
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, nil)
	defer pr.closeAll()
	wantSuccess(t, pr)
	st := pr.hosts[0].Stats()
	if st.SocketsByPurpose[PurposeBirthday] == 0 {
		t.Fatalf("no birthday sockets: %v", st.SocketsByPurpose)
	}
	if st.MaxConsecutiveRun > 3 {
		t.Fatalf("consecutive ports %d", st.MaxConsecutiveRun)
	}
}

// A larger go preempts a running round: no round_result for the preempted
// one.
func TestRoundPreemption(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	to.GoWaitMs = 500
	so.start(to)
	_, self := so.report()
	r1 := so.summary(self, fakePeer("203.0.113.99:4000"), to)
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, WindowMs: r1.WindowMs})
	time.Sleep(150 * time.Millisecond)
	r2 := r1
	r2.Round = 2
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 2, WindowMs: r2.WindowMs, Plan: &r2})
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, WindowMs: r1.WindowMs}) // stale: ignored
	m, ok := so.link.next(5*time.Second, protocol.MsgRoundResult)
	if !ok || m.(*protocol.RoundResult).Round != 2 {
		t.Fatalf("first round_result %+v", m)
	}
	e := so.wantError(so.result(10*time.Second), protocol.ReasonCandidateTimeout)
	if len(e.Diagnostics.Rounds) != 2 || e.Round != 2 {
		t.Fatalf("rounds %d round %d", len(e.Diagnostics.Rounds), e.Round)
	}
}

// Low TTL through a HopLimiter that refuses: the session degrades to normal
// TTL, warns once and still punches.
func TestLowTTLDegrades(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts(), round: func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
		p := directPlan(k, r, views)
		if r == protocol.RoleResponder {
			p.Sides[0].Stages[0].TTL = 4
		}
		return p
	}}
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(i int, o *Options) {
		if i == 1 {
			o.Network = refuseTTL{o.Network.(*nattest.Host)}
		}
	})
	defer pr.closeAll()
	wantSuccess(t, pr)
	d := pr.res[1].sess.Diagnostics()
	found := false
	for _, x := range d.Warn {
		found = found || x == protocol.WarnLowTTLUnsupported
	}
	if !found {
		t.Fatalf("warn %v", d.Warn)
	}
}

// refuseTTL is a Network whose sockets refuse hop-limit changes.
type refuseTTL struct{ *nattest.Host }

func (r refuseTTL) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	c, err := r.Host.ListenPacket(ctx, network, laddr, purpose)
	if err != nil {
		return nil, err
	}
	return badHop{c}, nil
}

type badHop struct{ net.PacketConn }

func (badHop) SetHopLimit(int) error { return syscall.ENOPROTOOPT }

// The residual filter recognises the session's packets on the handed-over
// socket and lets the upper layer's through.
func TestResidualFilter(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, nil)
	defer pr.closeAll()
	wantSuccess(t, pr)
	s := pr.res[1].sess
	if !slices.Equal(s.codec.Peers(), []netip.AddrPort{s.Result().Path.RemoteAddr}) {
		t.Fatalf("filter bound to %v", s.codec.Peers())
	}
	if fc := s.FilterResidual(s.PacketConn()); fc == nil || fc.Dropped() != 0 {
		t.Fatal("FilterResidual returned no filter")
	}
}

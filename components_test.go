package holepunch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/clock"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

func TestKeepaliveTable(t *testing.T) {
	eim := protocol.Traits{Mapping: protocol.MapEIM, MappingConf: protocol.ConfHigh, Filtering: protocol.FiltEIF, FilteringConf: protocol.ConfMedium, Samples: 3}
	pdf := eim
	pdf.Filtering = protocol.FiltPDF
	apdm := eim
	apdm.Mapping = protocol.MapAPDM
	cg := eim
	cg.CGNAT = protocol.TriTrue
	open := protocol.Traits{NoNAT: protocol.TriTrue, Filtering: protocol.FiltEIF, Samples: 3}
	fw := protocol.Traits{NoNAT: protocol.TriTrue, Filtering: protocol.FiltPDF, Samples: 3}
	cases := []struct {
		name       string
		fam        protocol.Family
		kind       protocol.PathKind
		self, peer protocol.Traits
		pm         *protocol.PortMappingInfo
		iv         time.Duration
		reason     string
	}{
		{"lan", protocol.FamilyUDP4, protocol.PathLAN, pdf, apdm, nil, 30 * time.Second, keepNoNAT},
		{"overlay", protocol.FamilyUDP4, protocol.PathOverlay, pdf, apdm, nil, 30 * time.Second, keepNoNAT},
		{"no nat open", protocol.FamilyUDP4, protocol.PathPublic, open, open, nil, 30 * time.Second, keepNoNAT},
		{"v6 firewall", protocol.FamilyUDP6, protocol.PathPublic, fw, open, nil, 25 * time.Second, keepNoNAT},
		{"eim known", protocol.FamilyUDP4, protocol.PathPublic, eim, eim, nil, 20 * time.Second, keepEIMKnown},
		{"pdf", protocol.FamilyUDP4, protocol.PathPublic, eim, pdf, nil, 15 * time.Second, keepRestricted},
		{"edm", protocol.FamilyUDP4, protocol.PathPublic, apdm, eim, nil, 15 * time.Second, keepRestricted},
		{"cgnat", protocol.FamilyUDP4, protocol.PathPublic, cg, eim, nil, 10 * time.Second, keepCGNAT},
		{"unknown", protocol.FamilyUDP4, protocol.PathPublic, protocol.Traits{}, eim, nil, 15 * time.Second, keepUnknown},
		{"portmap", protocol.FamilyUDP4, protocol.PathPublic, eim, eim, &protocol.PortMappingInfo{Lease: 30 * time.Second}, 10 * time.Second, keepPortmapped},
		{"portmap short lease clamps", protocol.FamilyUDP4, protocol.PathPublic, eim, eim, &protocol.PortMappingInfo{Lease: 6 * time.Second}, 5 * time.Second, keepPortmapped},
	}
	for _, c := range cases {
		a := keepaliveFor(c.fam, c.kind, c.self, c.peer, c.pm)
		if a.Interval != c.iv || a.Reason != c.reason || a.Timeout != 3*a.Interval {
			t.Errorf("%s: %+v", c.name, a)
		}
	}
}

func TestPhaseTracker(t *testing.T) {
	p := newPhaseTracker()
	now := time.Now()
	if !p.advance(protocol.PhaseProbing, "a", now) || p.advance(protocol.PhaseCreated, "b", now) {
		t.Fatal("monotonic")
	}
	if !p.advanceFamily(protocol.FamilyUDP4, protocol.PhasePunching, "c", now) || p.current() != protocol.PhasePunching {
		t.Fatal("family pushes session")
	}
	if p.advanceFamily(protocol.FamilyUDP4, protocol.PhasePlanned, "d", now) {
		t.Fatal("family monotonic")
	}
	p.advance(protocol.PhaseFailed, "e", now)
	if p.advance(protocol.PhaseDone, "f", now) {
		t.Fatal("terminal is final")
	}
	for range 2 * maxTimeline {
		p.note("x")
	}
	for i := range 100 {
		p.advanceFamily(protocol.Family("f"+strconv.Itoa(i)), protocol.PhasePlanned, "g", now)
	}
	_, tl, last := p.snapshot()
	if len(tl) != maxTimeline || last != "g" || p.lastEvent() != "g" {
		t.Fatalf("timeline %d last %q", len(tl), last)
	}
	if phaseRank("bogus") != -1 {
		t.Fatal("unknown phase rank")
	}
}

func TestDiagnosticsCloneIsDeep(t *testing.T) {
	plan := protocol.PlanSpec{Ladder: []string{"a"}, Round1: protocol.RoundPlan{Sides: []protocol.FamilySide{{Stages: []protocol.Stage{{Targets: []netip.AddrPort{netipAP("192.0.2.1", 1)}, Steps: []int16{1}}}}}}}
	d := Diagnostics{
		Timeline: []Transition{{Event: "x"}}, Self: []protocol.Traits{{}}, Plan: &plan, Rounds: []protocol.RoundPlan{plan.Round1},
		Path:     &protocol.PathInfo{Epoch: 1},
		Families: []FamilyDiagnostics{{Candidates: map[string]int{"a": 1}, Counters: Counters{Drops: map[string]int{"auth": 1}}}},
		Counters: Counters{TxByStage: map[string]int{"direct": 1}}, Warn: []string{"w"},
	}
	c := d.clone()
	c.Plan.Round1.Sides[0].Stages[0].Targets[0] = netip.AddrPort{}
	c.Rounds[0].Sides[0].Stages[0].Steps[0] = 9
	c.Families[0].Candidates["a"] = 7
	c.Families[0].Counters.Drops["auth"] = 7
	c.Counters.TxByStage["direct"] = 7
	c.Path.Epoch = 7
	c.Timeline[0].Event = "y"
	if d.Plan.Round1.Sides[0].Stages[0].Targets[0] == (netip.AddrPort{}) || d.Rounds[0].Sides[0].Stages[0].Steps[0] != 1 ||
		d.Families[0].Candidates["a"] != 1 || d.Families[0].Counters.Drops["auth"] != 1 || d.Counters.TxByStage["direct"] != 1 ||
		d.Path.Epoch != 1 || d.Timeline[0].Event != "x" {
		t.Fatal("clone shares memory")
	}
	if (Diagnostics{}).clone().Families != nil {
		t.Fatal("nil families stay nil")
	}
}

func TestDropMapping(t *testing.T) {
	for _, e := range []udpwire.DecodeError{udpwire.ErrShort, udpwire.ErrForeign, udpwire.ErrRate, udpwire.ErrAuth, udpwire.ErrPayload, udpwire.ErrRole, udpwire.ErrReplay} {
		k, ok := dropOf(e)
		if !ok || dropNames[k] != e.String() {
			t.Errorf("%v -> %v %v", e, k, ok)
		}
	}
	if _, ok := dropOf(udpwire.ErrRoute); ok {
		t.Fatal("route is not a client drop")
	}
	if len(protocol.DropKeys()) != int(numDrops) {
		t.Fatal("drop keys out of sync")
	}
}

// Session.Close is idempotent, concurrent, and returns the first error.
func TestSessionClose(t *testing.T) {
	_, h := simHost(t)
	c, err := h.ListenPacket(context.Background(), "udp4", netip.AddrPort{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	relErr := errors.New("release failed")
	n := 0
	s := &Session{conn: c, releases: []func() error{func() error { n++; return relErr }}}
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = s.Close() }()
	}
	wg.Wait()
	for _, e := range errs {
		if !errors.Is(e, relErr) {
			t.Fatalf("Close: %v", e)
		}
	}
	if n != 1 {
		t.Fatalf("release ran %d times", n)
	}
	p := &Session{conn: c, releases: []func() error{func() error { panic("x") }}}
	if err := p.Close(); err == nil {
		t.Fatal("panicking release must report")
	}
}

// uncomparableConn is a conn whose dynamic type == cannot compare.
type uncomparableConn struct {
	_ [0]func() // makes the type uncomparable
	net.PacketConn
}

// Session.Close takes every conn a Network may return, one whose type ==
// cannot compare among them, also when it serves two paths.
func TestSessionCloseUncomparableConn(t *testing.T) {
	_, h := simHost(t)
	c, err := h.ListenPacket(context.Background(), "udp4", netip.AddrPort{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	u := uncomparableConn{PacketConn: c}
	s := &Session{conn: u, extra: []net.PacketConn{u}}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := c.WriteTo([]byte{1}, net.UDPAddrFromAddrPort(netipAP("192.0.2.1", 9))); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("conn still open: %v", err)
	}
}

// The OS network: loopback sockets, interface addresses, resolution, TTL
// through syscall.Conn.
func TestSystemNetwork(t *testing.T) {
	nw := SystemNetwork()
	c, err := nw.ListenPacket(context.Background(), "udp4", netipAP("127.0.0.1", 0), PurposeProbe)
	if err != nil {
		t.Skip("no IPv4 loopback:", err)
	}
	defer func() { _ = c.Close() }()
	h := newHopCtl(c, false, new(atomic.Int64))
	if !h.ok || h.orig <= 0 {
		t.Fatalf("hop control %+v", h)
	}
	if err := h.set(3); err != nil {
		t.Fatal(err)
	}
	if v, _ := rawHopLimit(h.rc, false); v != 3 {
		t.Fatalf("ttl %d", v)
	}
	if err := h.set(0); err != nil {
		t.Fatal(err)
	}
	if v, _ := rawHopLimit(h.rc, false); v != h.orig {
		t.Fatalf("restored %d want %d", v, h.orig)
	}
	wildcard, err := nw.ListenPacket(context.Background(), "udp4", netip.AddrPort{}, PurposeProbe)
	if err != nil {
		t.Fatal(err)
	}
	_ = wildcard.Close()
	ifaces, addrs, err := nw.InterfaceAddrs()
	if err != nil || len(ifaces) == 0 || len(addrs) != len(ifaces) {
		t.Fatalf("interfaces %v addrs %v %v", ifaces, addrs, err)
	}
	ips, err := nw.LookupNetIP(context.Background(), "ip", "localhost")
	if err != nil || len(ips) == 0 {
		t.Fatalf("lookup %v %v", ips, err)
	}
	if a, err := nw.OutboundAddr(context.Background(), "udp4"); err == nil && !a.Is4() {
		t.Fatalf("outbound %v", a)
	}
	_, _ = nw.OutboundAddr(context.Background(), "udp6")
	if listenAddr(netip.AddrPort{}) != ":0" || listenAddr(netipAP("10.0.0.1", 5)) != "10.0.0.1:5" {
		t.Fatal("listenAddr")
	}
	hosts := hostAddrsOf(ifaces, addrs)
	if a := ifaceAddrs(hosts, "no-such-interface-x"); a != nil {
		t.Fatal("unknown interface")
	}
	if ifs := loopbackName(); ifs != "" && len(ifaceAddrs(hosts, ifs)) == 0 {
		t.Fatalf("loopback %s has no addresses", ifs)
	}
	for _, h := range hosts {
		if h.addr.IsLoopback() && h.live {
			t.Fatalf("loopback %v is a candidate address", h.addr)
		}
	}
	var none hopCtl
	if none.set(4) == nil {
		t.Fatal("no hop control must refuse")
	}
}

// loopbackName finds the loopback interface for the test (tests may use
// package net directly).
func loopbackName() string {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	return ""
}

// The dispatcher drops what is not this session's peer traffic and counts
// it by class, and ICMP notes reach the round evidence.
func TestDispatchDrops(t *testing.T) {
	fc := fakeClock(t)
	_, h := simHost(t)
	rt := newTestRuntime(t, fc, h)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	from := netipAP("198.51.100.7", 4000)
	rt.dispatch(s, []byte{1, 2, 3}, from)
	rt.dispatch(s, append([]byte{0x40}, make([]byte, 80)...), from)
	junk := append([]byte{0x05}, make([]byte, 80)...)
	rt.dispatch(s, junk, from)
	// a packet of this session's own role is a reflection: role drop
	h1 := udpwire.Header{Type: udpwire.TPunch, Role: udpwire.RoleInitiator, Seq: 9, Cand: 1}
	own, _ := rt.codec.Seal(nil, &h1, nil, 0)
	rt.dispatch(s, own, from)
	c := rt.fam(protocol.FamilyUDP4).cnt.snapshot()
	for _, k := range []string{protocol.DropShort, protocol.DropForeign, protocol.DropAuth, protocol.DropRole} {
		if c.Drops[k] != 1 {
			t.Errorf("drop %s = %d (%v)", k, c.Drops[k], c.Drops)
		}
	}
	if c.RxPackets != 4 {
		t.Fatalf("rx %d", c.RxPackets)
	}
	// STUN goes to the prober only
	rt.dispatch(s, []byte{0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42, 0, 0, 0, 0}, from)
	// ICMP becomes round evidence once punching
	rt.punch.active.Store(true)
	rt.punch.newRound(1, []protocol.Family{protocol.FamilyUDP4})
	rt.noteICMP(s)
	if rt.punch.icmpMax != 1 {
		t.Fatal("icmp not counted")
	}
	// pre-AEAD rate limit
	for range preRateBurst {
		s.preRateAllow(fc.Now())
	}
	rt.dispatch(s, junk, from)
	if rt.fam(protocol.FamilyUDP4).cnt.drops[dropRate].Load() != 1 {
		t.Fatal("rate drop")
	}
	if rt.socks.byID(protocol.FamilyUDP4, s.id) != s || rt.socks.byAddr(s.local) != s || rt.socks.byID(protocol.FamilyUDP6, s.id) != nil {
		t.Fatal("pool lookups")
	}
}

// The state machine's own handover-timeout Fail action ends the session as
// well.
func TestHandoverFailedAction(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	rt.nom.perform(context.Background(), []candidate.Action{{Kind: candidate.Fail, Reason: protocol.ReasonHandoverTimeout}})
	if _, failed := rt.punch.outcome(); !failed {
		t.Fatal("fail not recorded")
	}
	select {
	case <-rt.punch.wake:
	default:
		t.Fatal("orchestrator not woken")
	}
}

// A round whose fire instant lies past the handshake deadline is stopped
// there and never fires, though its fire instant comes within the
// confirmation grace: no fire progress, no punching phase, no evidence that
// it ran. Meanwhile the loop waits for the grace's end without spinning on
// the passed deadline.
func TestStoppedRoundNeverFires(t *testing.T) {
	fc := fakeClock(t)
	_, h := simHost(t)
	rt := newTestRuntime(t, fc, h)
	rt.summary.Plan.Round1 = protocol.RoundPlan{Round: 1, Budget: protocol.BudgetLight, WindowMs: 3000}
	t0 := fc.Now()
	done := runPunchLoop(t, rt)
	hs := t0.Add(rt.waits.handshake)

	rt.ctl.goCh <- stamped[protocol.PunchGo]{msg: protocol.PunchGo{SessionID: "unit", Round: 1}, at: t0}
	waitArmed(t, fc, t0, t0.Add(3*time.Second).Equal) // round 1 fired at once and runs to its window's end
	// Round 2's go comes with the longest delay so late that it would fire
	// 400 ms past the handshake deadline, within the 500 ms grace.
	fc.AdvanceTo(hs.Add(400 * time.Millisecond).Add(-maxGoDelay))
	r2 := protocol.RoundPlan{Round: 2, Budget: protocol.BudgetLight, WindowMs: 1000}
	go2 := protocol.PunchGo{SessionID: "unit", Round: 2, DelayMs: uint16(maxGoDelay / time.Millisecond), Plan: &r2}
	rt.ctl.goCh <- stamped[protocol.PunchGo]{msg: go2, at: fc.Now()}
	waitArmed(t, fc, t0, hs.Equal) // round 2 preempted round 1 and waits for its fire instant
	fc.AdvanceTo(hs)
	// The handshake timeout stopped round 2: only the grace is left to wait
	// for, neither round 2's fire instant nor the passed handshake deadline.
	grace := hs.Add(confirmGrace)
	waitArmed(t, fc, t0, grace.Equal)
	fc.AdvanceTo(grace)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the punching ended without an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the punch loop did not end at the grace's end")
	}
	if run := rt.curRound.Load(); run.plan.Round != 2 || run.fired {
		t.Fatalf("round %d fired: %v", run.plan.Round, run.fired)
	}
}

// A Confirm before the first go leaves only the handover timeout to wait for.
// The keepalive is renewed only while the go is awaited: left armed, it
// would hold the timer at zero from its instant on until the handover ends.
func TestConfirmBeforeGo(t *testing.T) {
	fc := fakeClock(t)
	_, h := simHost(t)
	rt := newTestRuntime(t, fc, h)
	rt.timeouts.GoWaitMs = 15000 // the go deadline comes after the first keepalive
	t0 := fc.Now()
	done := runPunchLoop(t, rt)
	goDeadline := rt.readyAt.Add(rt.waits.goWait)
	keepalive := waitArmed(t, fc, t0, func(d time.Time) bool { return !d.After(goDeadline) }) // the loop's first wait
	if !keepalive.Before(goDeadline) {
		t.Fatalf("first wait ends at %v, want the keepalive before the go deadline", keepalive.Sub(t0))
	}
	// The handover started a second before the keepalive would be due and
	// runs past it.
	fc.AdvanceTo(keepalive.Add(-time.Second))
	st := rt.punch
	st.mu.Lock()
	st.confirmAt = fc.Now()
	st.mu.Unlock()
	st.confirmed.Store(true)
	st.notify()
	handover := fc.Now().Add(time.Duration(rt.timeouts.HandoverTimeoutMs) * time.Millisecond)
	if !handover.After(keepalive) {
		t.Fatalf("the handover timeout %v ends before the keepalive", handover.Sub(t0))
	}
	waitArmed(t, fc, t0, handover.Equal)
	fc.AdvanceTo(handover)
	select {
	case err := <-done:
		var f *failure
		if !errors.As(err, &f) || f.reason != protocol.ReasonHandoverTimeout {
			t.Fatalf("got %v, want handover_timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the punch loop did not end at the handover timeout")
	}
}

// runPunchLoop runs rt's punching phase, from a punch_ready at the clock's
// current instant, on its own goroutine over a control link nobody answers;
// the channel receives the loop's error.
func runPunchLoop(t *testing.T, rt *runtime) <-chan error {
	t.Helper()
	rt.computeWaits()
	a, b := net.Pipe()
	t.Cleanup(func() { _, _ = a.Close(), b.Close() })
	if err := rt.ctl.open(a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.ctl.conn.Close() })
	rt.pg = life.New(rt.g.Context())
	t.Cleanup(func() { _ = rt.pg.Close(time.Second) })
	rt.readyAt = rt.clk.Now()
	done := make(chan error, 1)
	go func() {
		_, err := rt.punchLoop()
		done <- err
	}()
	return done
}

// waitArmed waits, in real time, until the earliest timer of fc is due at a
// deadline want accepts — the code under test armed it — and returns that
// deadline. origin is the instant failures report the deadline from.
func waitArmed(t *testing.T, fc *clock.Fake, origin time.Time, want func(time.Time) bool) time.Time {
	t.Helper()
	limit := time.Now().Add(5 * time.Second)
	for {
		next, ok := fc.Next()
		if ok && want(next) {
			return next
		}
		if time.Now().After(limit) {
			t.Fatalf("the timer is due at %v (armed %v)", next.Sub(origin), ok)
		}
		time.Sleep(time.Millisecond)
	}
}

// Keepalive probes leave every probing socket towards observer 0.
func TestKeepaliveProbes(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	fs := rt.fam(protocol.FamilyUDP4)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	fs.primary = s
	fs.siblings = []*udpSock{s}
	fs.observers = []protocol.ObserverSpec{{ID: 0, Addr: netipAP("198.51.100.1", 3478)}}
	rt.sendKeepalive()
	if got := fs.cnt.byStage[txProbe].Load(); got != 2 {
		t.Fatalf("keepalives %d", got)
	}
}

// A panicking HopLimiter is an error of the call and a counted callback
// panic, like every other user implementation's.
func TestHopLimiterPanicCounted(t *testing.T) {
	var n atomic.Int64
	h := newHopCtl(panicHop{}, false, &n)
	if err := h.set(4); err == nil || n.Load() != 1 {
		t.Fatalf("err %v, panics %d", err, n.Load())
	}
}

type panicHop struct{ net.PacketConn }

func (panicHop) SetHopLimit(int) error { panic("hop limiter") }

// Panics in a conn's LocalAddr, SetReadBuffer and SyscallConn — user
// implementations too — are recovered and counted; the socket still opens.
func TestConnPanicsCounted(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), panicConnNet{h})
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil || s == nil {
		t.Fatalf("open: %v", err)
	}
	if got := rt.cnt.callbackPanics.Load(); got != 3 {
		t.Fatalf("callback panics %d", got)
	}
}

type panicConnNet struct{ *nattest.Host }

func (n panicConnNet) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	c, err := n.Host.ListenPacket(ctx, network, laddr, purpose)
	return panicConn{c}, err
}

type panicConn struct{ net.PacketConn }

func (panicConn) LocalAddr() net.Addr                   { panic("local addr") }
func (panicConn) SetReadBuffer(int) error               { panic("read buffer") }
func (panicConn) SyscallConn() (syscall.RawConn, error) { panic("syscall conn") }

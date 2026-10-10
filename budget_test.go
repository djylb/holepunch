package holepunch

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// gateRig is a runtime with one public socket, a fake clock and a round
// meter, for exercising the send gate. The meter's class ceiling has the
// given distinct ports per IP and leaves no peer_targets packets until a
// test sets g.m.ceil.packets.
type gateRig struct {
	t    *testing.T
	rt   *runtime
	sock *udpSock
	m    *roundMeter
	clk  interface {
		Now() time.Time
		Advance(time.Duration) int
		WaitPending(context.Context, int) error
	}
}

func newGateRig(t *testing.T, b protocol.Budget, side protocol.FamilySide, classPorts int) *gateRig {
	t.Helper()
	fc := fakeClock(t)
	_, h := simHost(t)
	rt := newTestRuntime(t, fc, h)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	rt.sender.setBudget(b)
	side.Family = protocol.FamilyUDP4
	m := newRoundMeter(protocol.FamilyUDP4, 1, side, &roundCeiling{ports: classPorts})
	rt.sender.startRound(fc.Now(), classPorts)
	return &gateRig{t: t, rt: rt, sock: s, m: m, clk: fc}
}

func (g *gateRig) punch(to string) error { return g.send(to, quotaPlan) }

func (g *gateRig) send(to string, q sendQuota) error {
	h := udpwire.Header{Type: udpwire.TPunch, Round: 1}
	return g.rt.sender.Send(context.Background(), g.sock, netip.MustParseAddrPort(to), &h, nil,
		sendOpt{class: classInitiate, stage: txDirect, round: g.m, quota: q})
}

func bigBudget() protocol.Budget {
	return protocol.Budget{MaxPackets: 1000, MaxPPS: 1500, MaxDistinctTargets: 1000, MaxSockets: 40, MaxNewPerSec: 256}
}

func bigSide() protocol.FamilySide {
	return protocol.FamilySide{MaxPackets: 1000, MaxPPS: 1500, MaxNewPerSec: 256, MaxDistinctPorts: 1000, Sockets: 1}
}

func TestGateBeforeSummary(t *testing.T) {
	g := newGateRig(t, bigBudget(), bigSide(), 0)
	g.rt.sender.setBudget(protocol.Budget{})
	if err := g.punch("198.51.100.1:5000"); !errors.Is(err, errNoBudgetYet) {
		t.Fatalf("got %v", err)
	}
}

func TestGateSessionAndRoundPackets(t *testing.T) {
	b := bigBudget()
	b.MaxPackets = 3
	g := newGateRig(t, b, bigSide(), 0)
	for i := range 3 {
		if err := g.punch("198.51.100.1:5000"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if err := g.punch("198.51.100.1:5000"); !errors.Is(err, errBudget) {
		t.Fatalf("4th: %v", err)
	}
	if !g.m.budgetHit {
		t.Fatal("budget hit not recorded")
	}
	side := bigSide()
	side.MaxPackets = 2
	g2 := newGateRig(t, bigBudget(), side, 0)
	_ = g2.punch("198.51.100.1:5000")
	_ = g2.punch("198.51.100.1:5000")
	if err := g2.punch("198.51.100.1:5000"); !errors.Is(err, errBudget) {
		t.Fatalf("round cap: %v", err)
	}
	if got := g2.rt.fam(protocol.FamilyUDP4).cnt.drops[dropBudget].Load(); got != 1 {
		t.Fatalf("budget drops %d", got)
	}
	_, _, pct := g.rt.sender.usage()
	if pct != 100 {
		t.Fatalf("usage %d%%", pct)
	}
}

func TestGateDistinctTargetsAndPorts(t *testing.T) {
	b := bigBudget()
	b.MaxDistinctTargets = 2
	g := newGateRig(t, b, bigSide(), 0)
	_ = g.punch("198.51.100.1:5000")
	_ = g.punch("198.51.100.1:5010")
	if err := g.punch("198.51.100.1:5020"); !errors.Is(err, errRejected) {
		t.Fatalf("3rd target: %v", err)
	}
	if err := g.punch("198.51.100.1:5010"); err != nil {
		t.Fatalf("known target: %v", err)
	}
	if got := g.rt.fam(protocol.FamilyUDP4).cnt.targetRejected.Load(); got != 1 {
		t.Fatalf("rejected %d", got)
	}

	side := bigSide()
	side.MaxDistinctPorts = 2
	g2 := newGateRig(t, bigBudget(), side, 0)
	_ = g2.punch("198.51.100.1:6000")
	_ = g2.punch("198.51.100.1:6010")
	if err := g2.punch("198.51.100.1:6020"); !errors.Is(err, errRejected) {
		t.Fatalf("3rd port to one IP: %v", err)
	}
	if err := g2.punch("198.51.100.2:6020"); err != nil {
		t.Fatalf("other IP: %v", err)
	}
	if got := g2.m.distinctPorts(); got != 2 {
		t.Fatalf("distinct ports %d", got)
	}
}

// The 10 s sliding window bounds the ports to one IP across rounds.
func TestGateSlidingPortWindow(t *testing.T) {
	g := newGateRig(t, bigBudget(), bigSide(), 2)
	_ = g.punch("198.51.100.1:7000")
	_ = g.punch("198.51.100.1:7010")
	// a new round with a fresh per-round meter: the window still holds
	g.m = newRoundMeter(protocol.FamilyUDP4, 2, bigSide(), &roundCeiling{ports: 2})
	g.rt.sender.startRound(g.clk.Now(), 2)
	if err := g.punch("198.51.100.1:7020"); !errors.Is(err, errRejected) {
		t.Fatalf("within window: %v", err)
	}
	g.clk.Advance(11 * time.Second)
	if err := g.punch("198.51.100.1:7020"); err != nil {
		t.Fatalf("after window: %v", err)
	}
	if ports := g.rt.sender.sentPorts(netip.MustParseAddr("198.51.100.1")); len(ports) != 3 {
		t.Fatalf("sent ports %v", ports)
	}
}

// peer_targets have their own packet quota under the class ceiling: they
// never spend the plan's grant, and only a planned packet refused for
// packets is budget_hit. Follow-ups spend the grant without it.
func TestGateTargetsQuota(t *testing.T) {
	side := bigSide()
	side.MaxPackets = 2
	g := newGateRig(t, bigBudget(), side, 0)
	g.m.ceil.packets = 3
	for i := range 3 {
		if err := g.send("198.51.100.1:5000", quotaTargets); err != nil {
			t.Fatalf("target %d: %v", i, err)
		}
	}
	if err := g.send("198.51.100.1:5000", quotaTargets); !errors.Is(err, errBudget) || g.m.budgetHit {
		t.Fatalf("4th target: %v, budget hit %v", err, g.m.budgetHit)
	}
	for i := range 2 {
		if err := g.punch("198.51.100.1:5000"); err != nil {
			t.Fatalf("planned %d after targets: %v", i, err)
		}
	}
	if err := g.punch("198.51.100.1:5000"); !errors.Is(err, errBudget) || !g.m.budgetHit {
		t.Fatalf("3rd planned: %v, budget hit %v", err, g.m.budgetHit)
	}
	if g.m.sent != 5 || g.m.granted != 2 || g.m.ceil.packets != 0 {
		t.Fatalf("sent %d granted %d ceiling left %d", g.m.sent, g.m.granted, g.m.ceil.packets)
	}

	side.MaxPackets = 1
	g = newGateRig(t, bigBudget(), side, 0)
	if err := g.send("198.51.100.1:5000", quotaFollowUp); err != nil {
		t.Fatal(err)
	}
	if err := g.send("198.51.100.1:5000", quotaFollowUp); !errors.Is(err, errBudget) || g.m.budgetHit {
		t.Fatalf("follow-up over the grant: %v, budget hit %v", err, g.m.budgetHit)
	}
	if err := g.punch("198.51.100.1:5000"); !errors.Is(err, errBudget) || !g.m.budgetHit {
		t.Fatalf("planned after follow-ups spent the grant: %v, budget hit %v", err, g.m.budgetHit)
	}

	// The session budget binds both quotas; a plan it cuts short is budget_hit.
	b := bigBudget()
	b.MaxPackets = 2
	g = newGateRig(t, b, bigSide(), 0)
	g.m.ceil.packets = 10
	_ = g.send("198.51.100.1:5000", quotaTargets)
	_ = g.send("198.51.100.1:5000", quotaTargets)
	if err := g.send("198.51.100.1:5000", quotaTargets); !errors.Is(err, errBudget) || g.m.budgetHit {
		t.Fatalf("target past the session budget: %v, budget hit %v", err, g.m.budgetHit)
	}
	if err := g.punch("198.51.100.1:5000"); !errors.Is(err, errBudget) || !g.m.budgetHit {
		t.Fatalf("planned past the session budget: %v, budget hit %v", err, g.m.budgetHit)
	}
}

// Distinct ports per peer IP: planned packets count their own ports
// against the family's port grant, peer_targets every port of the round
// against the class's.
func TestGateTargetsPorts(t *testing.T) {
	side := bigSide()
	side.MaxDistinctPorts = 2
	g := newGateRig(t, bigBudget(), side, 4)
	g.m.ceil.packets = 100
	steps := []struct {
		port string
		q    sendQuota
		ok   bool
	}{
		{"6000", quotaPlan, true},
		{"6001", quotaPlan, true},
		{"6002", quotaPlan, false},   // the plan's two ports are used
		{"6000", quotaTargets, true}, // a port already sent to costs nothing
		{"6002", quotaTargets, true}, // 3 of the class's 4
		{"6003", quotaTargets, true}, // 4 of 4
		{"6004", quotaTargets, false},
		{"6002", quotaPlan, false}, // a port only peer_targets used is new to the plan
		{"6001", quotaFollowUp, true},
		{"6004", quotaPlan, false},
	}
	for i, st := range steps {
		err := g.send("198.51.100.1:"+st.port, st.q)
		if (err == nil) != st.ok {
			t.Fatalf("step %d (%s quota %d): %v", i, st.port, st.q, err)
		}
	}
	if got := g.m.distinctPorts(); got != 4 {
		t.Fatalf("distinct ports %d", got)
	}

	// A port peer_targets opened, later planned, is one port of the plan.
	side.MaxDistinctPorts = 1
	g = newGateRig(t, bigBudget(), side, 4)
	g.m.ceil.packets = 100
	for i, st := range []struct {
		port string
		q    sendQuota
		ok   bool
	}{
		{"7000", quotaTargets, true},
		{"7000", quotaPlan, true},
		{"7001", quotaPlan, false},
		{"7001", quotaTargets, true},
		{"7000", quotaPlan, true},
	} {
		if err := g.send("198.51.100.1:"+st.port, st.q); (err == nil) != st.ok {
			t.Fatalf("step %d: %v", i, err)
		}
	}
}

// The room a round leaves to peer_targets is the class's packets minus the
// families' grants.
func TestRoundCeiling(t *testing.T) {
	lim, _ := protocol.BudgetLight.Limits()
	c := newRoundCeiling(lim, []protocol.FamilySide{{MaxPackets: 100}, {MaxPackets: 40}})
	if c.packets != 10 || c.ports != 16 {
		t.Fatalf("ceiling %+v", c)
	}
	if c = newRoundCeiling(lim, []protocol.FamilySide{{MaxPackets: 140}, {MaxPackets: 40}}); c.packets != 0 {
		t.Fatalf("over-granted round %+v", c)
	}
	m := newRoundMeter(protocol.FamilyUDP4, 1, protocol.FamilySide{}, c)
	if m.maxPorts != 16 {
		t.Fatalf("unset port grant takes the class's: %d", m.maxPorts)
	}
}

// pps tokens are waited for, on the session clock, and cancellation is
// immediate.
func TestGateRateWaits(t *testing.T) {
	b := bigBudget()
	b.MaxPPS = 10 // bucket depth max(10/10, 8) = 8
	g := newGateRig(t, b, bigSide(), 0)
	for i := range 8 {
		if err := g.punch("198.51.100.1:5000"); err != nil {
			t.Fatalf("burst %d: %v", i, err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- g.punch("198.51.100.1:5000") }()
	if err := g.clk.WaitPending(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("9th did not wait: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	g.clk.Advance(200 * time.Millisecond)
	if err := <-done; err != nil {
		t.Fatalf("after tokens: %v", err)
	}
	if _, peak, _ := g.rt.sender.usage(); peak < 8 {
		t.Fatalf("peak pps %d", peak)
	}
	g = newGateRig(t, b, bigSide(), 0)
	for range 8 {
		_ = g.punch("198.51.100.1:5000")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		h := udpwire.Header{Type: udpwire.TPunch}
		done <- g.rt.sender.Send(ctx, g.sock, netip.MustParseAddrPort("198.51.100.1:5000"), &h, nil, sendOpt{class: classInitiate, round: g.m})
	}()
	if err := g.clk.WaitPending(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait: %v", err)
	}
}

func TestGateReplyHandshakeStopDetach(t *testing.T) {
	g := newGateRig(t, bigBudget(), bigSide(), 0)
	to := netip.MustParseAddrPort("198.51.100.9:4000")
	reply := func() error {
		h := udpwire.Header{Type: udpwire.TSuccess, EchoSeq: 1}
		tl := udpwire.TLVs{Observed: to}
		return g.rt.sender.Send(context.Background(), g.sock, to, &h, &tl, sendOpt{class: classReply, stage: txReply})
	}
	if err := reply(); err != nil {
		t.Fatal(err)
	}
	if err := reply(); !errors.Is(err, errSuppressed) {
		t.Fatalf("second reply within 20 ms: %v", err)
	}
	g.clk.Advance(25 * time.Millisecond)
	if err := reply(); err != nil {
		t.Fatalf("after gap: %v", err)
	}
	hs := func() error {
		h := udpwire.Header{Type: udpwire.TNominate, Aux: 1, Cand: udpwire.NoCand}
		return g.rt.sender.Send(context.Background(), g.sock, to, &h, nil, sendOpt{class: classHandshake, stage: txHandshake})
	}
	for i := range handshakeReserve {
		if err := hs(); err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
	}
	if err := hs(); !errors.Is(err, errBudget) {
		t.Fatalf("handshake reserve: %v", err)
	}
	g.rt.sender.stop()
	if err := g.punch("198.51.100.1:5000"); !errors.Is(err, errStopped) {
		t.Fatalf("after stop: %v", err)
	}
	// handshakes never fail on rate but do spend pps tokens: let them refill
	g.clk.Advance(300 * time.Millisecond)
	if err := reply(); err != nil {
		t.Fatalf("replies continue after stop: %v", err)
	}
	if !g.sock.detach() {
		t.Fatal("detach")
	}
	g.clk.Advance(25 * time.Millisecond)
	if err := reply(); !errors.Is(err, errDetached) {
		t.Fatalf("after detach: %v", err)
	}
	c := g.rt.fam(protocol.FamilyUDP4).cnt.snapshot()
	if c.TxByStage["reply"] != 3 || c.TxByStage["handshake"] != handshakeReserve {
		t.Fatalf("by stage %v", c.TxByStage)
	}
}

// Every write failing for a second is the punching-time udp_blocked signal.
func TestGateWriteBlocked(t *testing.T) {
	g := newGateRig(t, bigBudget(), bigSide(), 0)
	host := g.rt.netw.(interface {
		FailWrites(string, int, error)
	})
	host.FailWrites("", -1, syscall.EPERM)
	if err := g.punch("198.51.100.1:5000"); err == nil {
		t.Fatal("injected failure not seen")
	}
	if g.rt.sender.writeBlocked(g.clk.Now()) {
		t.Fatal("blocked too early")
	}
	g.clk.Advance(1100 * time.Millisecond)
	_ = g.punch("198.51.100.1:5000")
	if !g.rt.sender.writeBlocked(g.clk.Now()) {
		t.Fatal("not blocked after 1 s of failures")
	}
	host.FailWrites("", 0, nil)
	if err := g.punch("198.51.100.1:5000"); err != nil {
		t.Fatal(err)
	}
	if g.rt.sender.writeBlocked(g.clk.Now()) {
		t.Fatal("a success clears the signal")
	}
	if got := g.rt.fam(protocol.FamilyUDP4).cnt.drops[dropSendErr].Load(); got != 2 {
		t.Fatalf("send_err %d", got)
	}
	host.FailWrites("", 1, syscall.EHOSTUNREACH)
	if err := g.punch("198.51.100.1:5000"); !errors.Is(err, errUnreachable) {
		t.Fatalf("unreachable: %v", err)
	}
}

// The ICMP report of an earlier datagram, delivered on a write (Windows with
// the reports on, or a connected conn), is a soft signal: a send error and an
// ICMP note, but the target stays and the socket never looks blocked.
func TestGateWriteReport(t *testing.T) {
	g := newGateRig(t, bigBudget(), bigSide(), 0)
	host := g.rt.netw.(interface {
		FailWrites(string, int, error)
	})
	g.rt.punch.active.Store(true)
	g.rt.punch.newRound(1, []protocol.Family{protocol.FamilyUDP4})
	host.FailWrites("", -1, syscall.ECONNRESET)
	if err := g.punch("198.51.100.1:5000"); err == nil || errors.Is(err, errUnreachable) {
		t.Fatalf("first report: %v", err)
	}
	g.clk.Advance(1100 * time.Millisecond)
	if err := g.punch("198.51.100.1:5000"); err == nil || errors.Is(err, errUnreachable) {
		t.Fatalf("second report: %v", err)
	}
	if g.rt.sender.writeBlocked(g.clk.Now()) {
		t.Fatal("reports made the socket look blocked")
	}
	if got := g.rt.fam(protocol.FamilyUDP4).cnt.drops[dropSendErr].Load(); got != 2 {
		t.Fatalf("send_err %d", got)
	}
	if g.rt.punch.icmpMax != 2 {
		t.Fatalf("icmp %d", g.rt.punch.icmpMax)
	}
}

func TestBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newBucket(10, 2)
	if b.reserve(now) != 0 || b.reserve(now) != 0 {
		t.Fatal("burst")
	}
	if w := b.reserve(now); w != 100*time.Millisecond {
		t.Fatalf("wait %v", w)
	}
	if b.take(now, 0) {
		t.Fatal("take without debt")
	}
	if !b.take(now.Add(time.Second), 0) {
		t.Fatal("refill")
	}
	var u bucket
	if u.reserve(now) != 0 || !u.take(now, 0) {
		t.Fatal("zero rate is unlimited")
	}
}

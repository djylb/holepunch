package nattest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/internal/life"
)

func TestCloseSemantics(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	n := NewNetwork(WithCoreLink(LinkConfig{Delay: time.Hour}))
	_, o := observer(t, n, 1000)
	nat := n.NAT(PortRestricted())
	h := nat.Host()
	c := listen(t, h, 4000)
	send(t, c, addrOf(o), "stuck in flight")
	pa, pb := n.Pipe(PipeConfig{})
	readErr := make(chan error, 1)
	go func() { _, err := pb.Read(make([]byte, 1)); readErr <- err }()

	// 100 concurrent calls: none panics, all return the same nil result.
	var wg sync.WaitGroup
	errs := make([]error, 100)
	for i := range errs {
		wg.Go(func() { errs[i] = n.Close() })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	if err := <-readErr; !isClosedErr(err) {
		t.Fatalf("pipe read after Close: %v", err)
	}
	if _, err := c.WriteToUDPAddrPort([]byte("x"), addrOf(o)); !isClosedErr(err) {
		t.Fatalf("write after Close: %v", err)
	}
	if _, err := h.ListenPacket(context.Background(), "udp", netip.AddrPort{}, "x"); !isClosedErr(err) {
		t.Fatalf("listen after Close: %v", err)
	}
	if _, _, err := h.InterfaceAddrs(); !isClosedErr(err) {
		t.Fatalf("InterfaceAddrs after Close: %v", err)
	}
	if _, err := h.OutboundAddr(context.Background(), "udp"); !isClosedErr(err) {
		t.Fatalf("OutboundAddr after Close: %v", err)
	}
	if _, err := h.LookupNetIP(context.Background(), "ip", "localhost"); !isClosedErr(err) {
		t.Fatalf("LookupNetIP after Close: %v", err)
	}
	if _, err := pa.Write([]byte("x")); !isClosedErr(err) {
		t.Fatalf("pipe write after Close: %v", err)
	}
	if _, err := h.MarkHandover(addrOf(c)); !isClosedErr(err) {
		t.Fatalf("MarkHandover after Close: %v", err)
	}
	// Objects created after Close are inert, never nil.
	late := n.NAT(FullCone())
	if _, err := late.Host().Listen("udp4", netip.AddrPort{}); !isClosedErr(err) {
		t.Fatalf("late host: %v", err)
	}
	if _, err := late.NAT(FullCone()).Host().Listen("udp4", netip.AddrPort{}); !isClosedErr(err) {
		t.Fatalf("host behind a late NAT: %v", err)
	}
	if _, err := n.PublicHost().Listen("udp", netip.AddrPort{}); !isClosedErr(err) {
		t.Fatalf("late public host: %v", err)
	}
	la, _ := n.Pipe(PipeConfig{})
	if _, err := la.Write([]byte("x")); !isClosedErr(err) {
		t.Fatalf("late pipe: %v", err)
	}
	late.ExpireAll()
	late.Rebind(nil)
	late.Blackhole(time.Second)
	nat.Rebind(nil)
	h.Crash()
	h.FailWrites("", 1, nil)
	if st := late.Stats(); st.MappingsActive != 0 || len(late.ExternalIPs()) != 0 {
		t.Fatalf("late NAT %+v", st)
	}
	// Statistics and the dump stay available for a post-mortem.
	if st := n.Stats(); st.Dropped.Closed != 1 || st.EventsPending != 0 {
		t.Fatalf("the packet in flight is not accounted: %+v", st)
	}
	if err := n.Dump(io.Discard); err != nil {
		t.Fatalf("Dump after Close: %v", err)
	}
	if h.OpenSockets() != 0 {
		t.Fatal("sockets left open")
	}
}

// TestCloseJoinBound: Close waits at most one second for a stuck scheduler
// goroutine and reports it; every caller gets
// the same error.
func TestCloseJoinBound(t *testing.T) {
	n := NewNetwork()
	h := n.PublicHost()
	// Holding the event log's lock blocks the scheduler as soon as it handles
	// the packet below; Close itself never needs that lock.
	p := newPacket([]byte("x"))
	p.act, p.host, p.dst = actDeliver, h, netip.AddrPortFrom(h.Addrs()[0], 9)
	n.log.mu.Lock()
	if !n.sched.push(event{at: n.now(), p: p}) {
		t.Fatal("push refused")
	}
	waitFor(t, func() bool { return n.sched.pending() == 0 })
	start := time.Now()
	errs := make(chan error, 2)
	for range 2 {
		go func() { errs <- n.Close() }()
	}
	err1, err2 := <-errs, <-errs
	el := time.Since(start)
	n.log.mu.Unlock()
	if err1 == nil || !errors.Is(err1, err2) {
		t.Fatalf("Close = %v and %v, want the same error", err1, err2)
	}
	// The upper bound only tells a bounded wait from an unbounded one; it
	// leaves room for a loaded machine.
	if el < closeJoin || el > 5*closeJoin {
		t.Fatalf("Close returned after %v, want about %v", el, closeJoin)
	}
	if err := n.Close(); !errors.Is(err, err1) {
		t.Fatalf("a later Close returned %v", err)
	}
	waitFor(t, func() bool { return n.sched.group.Stats().Running == 0 })
}

// TestClosePanicErr: a panic of the scheduler goroutine is recovered and
// Close reports it.
func TestClosePanicErr(t *testing.T) {
	n := NewNetwork()
	// A pipe chunk without its pipe makes handle dereference nil.
	n.sched.push(event{at: n.now(), pc: &pipeChunk{}})
	waitFor(t, func() bool { return n.sched.group.Context().Err() != nil })
	err := n.Close()
	var perr *life.PanicError
	if !errors.As(err, &perr) || perr.Where() != "nattest.scheduler" {
		t.Fatalf("Close = %v, want the scheduler's panic", err)
	}
}

func TestClosedNetworkCountsLateEvents(t *testing.T) {
	n, clk := fakeNet(t, WithCoreLink(LinkConfig{Delay: time.Millisecond}))
	_, o := observer(t, n, 1)
	c := listen(t, n.NAT(FullCone()).Host(), 2)
	pa, _ := n.Pipe(PipeConfig{DelayAB: time.Millisecond})
	send(t, c, addrOf(o), "x")
	if _, err := pa.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Second)
	if st := n.Stats(); st.Dropped.Closed != 2 {
		t.Fatalf("Dropped.Closed = %d, want 2", st.Dropped.Closed)
	}
	// A hop that is queued after Close is dropped as well.
	n.schedule(newPacket([]byte("z")), time.Millisecond)
	before := pa.tx.pending
	ch := &pipeChunk{pipe: pa.p, dir: pa.tx, data: []byte("w")}
	pa.p.mu.Lock()
	pa.tx.pending++
	pa.p.emit(ch, n.now()+time.Millisecond)
	pa.p.mu.Unlock()
	if pa.tx.pending != before {
		t.Fatal("a refused pipe chunk kept its buffer space")
	}
	if st := n.Stats(); st.Dropped.Closed != 3 {
		t.Fatalf("Dropped.Closed = %d, want 3", st.Dropped.Closed)
	}
}

func TestDump(t *testing.T) {
	n := newNet(t, WithSeed(99), WithEventLog(16))
	_, o := observer(t, n, 3478)
	cg := CGNAT(SymmetricSeq(1), PortRestricted())
	cg[0].Name = "carrier"
	cg[0].IPv6 = &IPv6Config{Mode: NAT66}
	nat := n.NAT(cg[0]).NAT(cg[1])
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, o)
	send(t, o, netip.AddrPortFrom(m.Addr(), m.Port()+1), "filtered")
	for range 20 {
		send(t, c, addrOf(o), "x")
		drain(o)
	}
	var buf bytes.Buffer
	if err := n.Dump(&buf); err != nil {
		t.Fatal(err)
	}
	var doc dumpDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("the dump is not JSON: %v", err)
	}
	if doc.Seed != 99 || len(doc.NATs) != 2 || len(doc.Hosts) != 2 {
		t.Fatalf("%+v", doc)
	}
	carrier, home := doc.NATs[0], doc.NATs[1]
	if carrier.Name != "carrier" || carrier.Parent != "core" || carrier.IPv6 != "NAT66" || home.Parent != "carrier" || home.Mapping != "EIM" || home.Filtering != "APDF" {
		t.Fatalf("NATs %+v", doc.NATs)
	}
	if len(home.Mappings) != 1 || home.Stats.FilteredInbound != 0 || carrier.Stats.FilteredInbound != 1 {
		t.Fatalf("home %+v carrier %+v", home, carrier)
	}
	if len(doc.Events) != 16 || doc.EventsTotal < 60 {
		t.Fatalf("events %d total %d", len(doc.Events), doc.EventsTotal)
	}
	last := doc.Events[len(doc.Events)-1]
	if last.Kind != "deliver" || last.B0 != 'x' || last.Len != 1 {
		t.Fatalf("last event %+v", last)
	}
	if doc.Hosts[1].NAT != home.Name || len(doc.Hosts[1].Stats.Sockets) != 1 {
		t.Fatalf("host %+v", doc.Hosts[1])
	}
	// The event log can be disabled.
	n2 := newNet(t, WithEventLog(0))
	var b2 bytes.Buffer
	if err := n2.Dump(&b2); err != nil || !bytes.Contains(b2.Bytes(), []byte(`"events": []`)) {
		t.Fatalf("a disabled log dumps events: %v", err)
	}
}

// waitFor polls cond in real time for up to five seconds.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestDeadlineAfterCloseArmsNoTimer: a deadline set after its conn closed,
// as a SetDeadline racing with Close does, leaves no timer on the clock.
func TestDeadlineAfterCloseArmsNoTimer(t *testing.T) {
	n, clk := fakeNet(t)
	d := newDeadline()
	d.set(n, clk.Now().Add(time.Hour))
	d.stop()
	d.set(n, clk.Now().Add(time.Hour))
	if p := clk.Pending(); p != 0 {
		t.Fatalf("%d timers left after stop", p)
	}
}

// TestCloseWhileDelivering: packets that race with a socket's Close are
// either read, dropped as having no socket, or drained by the Close; none is
// left in the queue of the closed socket.
func TestCloseWhileDelivering(t *testing.T) {
	n := newNet(t)
	srv := n.PublicHost(netip.IPv4Unspecified())
	cl := n.PublicHost(netip.IPv4Unspecified())
	for i := range 200 {
		port := uint16(1000 + i)
		pc, err := srv.Listen("udp4", netip.AddrPortFrom(netip.Addr{}, port))
		if err != nil {
			t.Fatal(err)
		}
		c := pc.(*conn)
		dst := netip.AddrPortFrom(srv.Addrs()[0], port)
		var senders sync.WaitGroup
		for k := range 4 {
			senders.Go(func() {
				s, err := cl.Listen("udp4", netip.AddrPortFrom(netip.Addr{}, uint16(10000+4*i+k)))
				if err != nil {
					t.Error(err)
					return
				}
				defer func() { _ = s.Close() }()
				for range 50 {
					_, _ = s.(*conn).writeTo([]byte("x"), dst)
				}
			})
		}
		_ = c.Close()
		senders.Wait()
		if k := len(c.inbox); k != 0 {
			t.Fatalf("round %d: %d packets left in the queue of a closed socket", i, k)
		}
	}
}

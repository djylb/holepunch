package nattest

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/clock"
)

func TestDelayedDeliveryRealClock(t *testing.T) {
	n := newNet(t, WithCoreLink(LinkConfig{Delay: 30 * time.Millisecond}))
	_, o := observer(t, n, 1000)
	nat := n.NAT(NATConfig{Uplink: LinkConfig{Delay: 10 * time.Millisecond}})
	c := listen(t, nat.Host(), 4000)
	start := time.Now()
	send(t, c, addrOf(o), "1")
	send(t, c, addrOf(o), "2")
	if s, _ := recvWait(t, o, 5*time.Second); s != "1" {
		t.Fatalf("order: %q", s)
	}
	if el := time.Since(start); el < 40*time.Millisecond {
		t.Fatalf("delivered after %v, want >= 40ms", el)
	}
	if s, _ := recvWait(t, o, 5*time.Second); s != "2" {
		t.Fatalf("order: %q", s)
	}
	if st := n.Stats(); st.EventsScheduled < 4 || st.EventsPending != 0 {
		t.Fatalf("scheduler not used: %+v", st)
	}
}

// TestFakeClockIsEventDriven: under a fake clock nothing moves until the
// clock advances, and each hop is judged when the packet reaches it.
func TestFakeClockIsEventDriven(t *testing.T) {
	n, clk := fakeNet(t, WithCoreLink(LinkConfig{Delay: 50 * time.Millisecond}))
	_, o := observer(t, n, 1000)
	natA, natB := n.NAT(PortRestricted()), n.NAT(PortRestricted())
	a := listen(t, natA.Host(), 4000)
	b := listen(t, natB.Host(), 4000)
	ma, mb := srcAtAfter(t, clk, a, o), srcAtAfter(t, clk, b, o)

	// A fires first; B opens its side 30 ms later, before A's packet reaches
	// NAT B at 50 ms: a physical simultaneous open must succeed.
	send(t, a, mb, "from-a")
	clk.Advance(30 * time.Millisecond)
	send(t, b, ma, "from-b")
	expectNone(t, b)
	clk.Advance(19 * time.Millisecond)
	expectNone(t, b)
	clk.Advance(time.Millisecond)
	if s, _ := recvNow(t, b); s != "from-a" {
		t.Fatal(s)
	}
	clk.Advance(30 * time.Millisecond)
	if s, _ := recvNow(t, a); s != "from-b" {
		t.Fatal(s)
	}
	// Deadlines follow the fake clock.
	_ = a.SetReadDeadline(clk.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, _, err := a.ReadFrom(make([]byte, 8)); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("read returned before the clock advanced: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	clk.Advance(time.Second)
	if err := <-done; !isTimeout(err) {
		t.Fatalf("fake deadline: %v", err)
	}
}

// TestFakeClockStartsNoGoroutine: a network on a fake clock runs entirely on
// the goroutines of the test.
func TestFakeClockStartsNoGoroutine(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	clk := clock.NewFake(t, time.Time{})
	n := NewNetwork(WithClock(clk), WithCoreLink(LinkConfig{Delay: time.Millisecond}))
	if n.sched.group != nil {
		t.Fatal("scheduler goroutine started on a fake clock")
	}
	_, o := observer(t, n, 1)
	c := listen(t, n.NAT(FullCone()).Host(), 2)
	srcAtAfter(t, clk, c, o)
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if clk.Pending() != 0 {
		t.Fatalf("%d timers left on the clock", clk.Pending())
	}
}

// TestFakeClockChainedDelays: a packet crossing several delayed links in one
// Advance passes every hop in that Advance, at the right times.
func TestFakeClockChainedDelays(t *testing.T) {
	n, clk := fakeNet(t, WithCoreLink(LinkConfig{Delay: 10 * time.Millisecond}))
	_, o := observer(t, n, 1)
	cg := CGNAT(NATConfig{Uplink: LinkConfig{Delay: 5 * time.Millisecond}}, NATConfig{Uplink: LinkConfig{Delay: 3 * time.Millisecond}})
	c := listen(t, n.NAT(cg[0]).NAT(cg[1]).Host(), 1)
	send(t, c, addrOf(o), "x")
	clk.Advance(17 * time.Millisecond)
	expectNone(t, o)
	clk.Advance(time.Millisecond)
	recvNow(t, o)
	if st := n.Stats(); st.EventsScheduled != 3 || st.EventsPending != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestEventHeapOrder(t *testing.T) {
	var h eventHeap
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 500 {
		h.push(event{at: time.Duration(r.IntN(50)), seq: uint64(i)})
	}
	prev := event{at: -1}
	for len(h) > 0 {
		e := h.pop()
		if e.at < prev.at || (e.at == prev.at && e.seq < prev.seq) {
			t.Fatalf("heap order broken: %+v after %+v", e, prev)
		}
		prev = e
	}
}

func TestConcurrentTraffic(t *testing.T) {
	n := newNet(t, WithCoreLink(LinkConfig{Delay: time.Millisecond, Jitter: time.Millisecond, Loss: 0.01}))
	srv := n.PublicHost(netip.IPv4Unspecified())
	sc := listenOn(t, srv, "udp4", netip.AddrPortFrom(srv.Addrs()[0], 3478))
	var readers sync.WaitGroup
	readers.Go(func() { // echo server
		b := make([]byte, 1500)
		for {
			k, src, err := sc.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			_, _ = sc.WriteToUDPAddrPort(b[:k], src)
		}
	})
	nats := []*NAT{n.NAT(FullCone()), n.NAT(SymmetricRandom()), n.NAT(SymmetricSeq(1))}
	var clients sync.WaitGroup
	for i := range 12 {
		nat := nats[i%len(nats)]
		c := listen(t, nat.Host(), 0)
		clients.Go(func() {
			for k := range 200 {
				_, _ = c.WriteToUDPAddrPort([]byte{byte(k)}, addrOf(sc))
				if k%50 == 0 {
					nat.Stats()
					nat.Mappings()
					n.Stats()
				}
			}
		})
		readers.Go(func() {
			b := make([]byte, 10)
			for {
				if _, _, err := c.ReadFromUDPAddrPort(b); err != nil {
					return
				}
			}
		})
	}
	clients.Wait()
	time.Sleep(20 * time.Millisecond)
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
	if st := n.Stats(); st.PacketsSent < 2400 || st.PacketsDelivered == 0 {
		t.Fatalf("stats %+v", st)
	}
}

// TestDeterministicReplay: the same seed on a fake clock replays a lossy,
// jittery, noisy run packet by packet.
func TestDeterministicReplay(t *testing.T) {
	run := func() string {
		clk := clock.NewFake(t, time.Time{})
		n := NewNetwork(WithSeed(5), WithClock(clk), WithCoreLink(LinkConfig{Delay: 10 * time.Millisecond, Jitter: 5 * time.Millisecond, Loss: 0.1}))
		defer func() { _ = n.Close() }()
		_, o := observer(t, n, 1)
		cfg := SymmetricRandom()
		cfg.PortNoisePPS = 5
		nat := n.NAT(cfg)
		c := listen(t, nat.Host(), 0)
		for i := range 50 {
			_, _ = c.WriteToUDPAddrPort([]byte{byte(i)}, netip.AddrPortFrom(addrOf(o).Addr(), uint16(100+i)))
			clk.Advance(3 * time.Millisecond)
		}
		clk.Advance(time.Second)
		var b bytes.Buffer
		if err := n.Dump(&b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	a, b := run(), run()
	if a != b {
		t.Fatal("the same seed on a fake clock must replay identically")
	}
	var doc dumpDoc
	if err := json.Unmarshal([]byte(a), &doc); err != nil || doc.Stats.Dropped.Loss == 0 || len(doc.NATs[0].Mappings) == 0 {
		t.Fatalf("replayed run did not exercise loss and mappings: %v %+v", err, doc.Stats)
	}
}

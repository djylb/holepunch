package nattest

import (
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// benchPath sends b.N packets from a host behind a port-restricted NAT to a
// public server and reports the packets delivered per second; sender,
// scheduler and reader each run on their own goroutine. With delay > 0 every
// packet waits on the core link and is delivered by the scheduler goroutine.
func benchPath(b *testing.B, delay time.Duration, opts ...Option) {
	const maxInflight = 1 << 15
	n := NewNetwork(append([]Option{WithCoreLink(LinkConfig{Delay: delay})}, opts...)...)
	defer func() { _ = n.Close() }()
	// A deep receive queue keeps a reader that is briefly descheduled from
	// turning the measurement into one of drops.
	n.queue = 2 * maxInflight
	srv := n.PublicHost(netip.IPv4Unspecified())
	sc, err := srv.Listen("udp4", netip.AddrPortFrom(srv.Addrs()[0], 3478))
	if err != nil {
		b.Fatal(err)
	}
	cl, err := n.NAT(PortRestricted()).Host().Listen("udp4", netip.AddrPortFrom(netip.Addr{}, 4000))
	if err != nil {
		b.Fatal(err)
	}
	s, c := sc.(*conn), cl.(*conn)
	dst := s.localAP()
	payload := make([]byte, 64)
	var got atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			if _, _, err := s.readFrom(buf); err != nil {
				return
			}
			got.Add(1)
		}
	}()
	lost := func() int64 { return int64(srv.stats.inboxFull.Load()) }
	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	for i := range b.N {
		payload[0] = byte(i)
		if _, err := c.writeTo(payload, dst); err != nil {
			b.Fatal(err)
		}
		if i&1023 == 0 {
			for int64(i)-got.Load()-lost() > maxInflight {
				runtime.Gosched()
			}
		}
	}
	for spins := 0; got.Load()+lost() < int64(b.N); spins++ {
		if spins&1023 == 0 && time.Since(start) > time.Minute {
			b.Fatalf("only %d/%d delivered", got.Load(), b.N)
		}
		runtime.Gosched()
	}
	el := time.Since(start)
	b.StopTimer()
	b.ReportMetric(float64(got.Load())/el.Seconds(), "pkts/s")
	b.ReportMetric(float64(lost())/float64(b.N)*100, "drop%")
	b.ReportMetric(float64(n.sched.scheduled.Load())/float64(b.N), "events/pkt")
	_ = sc.Close()
	<-done
}

// BenchmarkScheduler: every packet is delayed by 1 ms on the core link and
// delivered by the scheduler goroutine; it should reach at least 500k
// packets per second.
func BenchmarkScheduler(b *testing.B) { benchPath(b, time.Millisecond, WithEventLog(0)) }

// BenchmarkSchedulerEventLog is BenchmarkScheduler with the default event
// log of 10000 events.
func BenchmarkSchedulerEventLog(b *testing.B) { benchPath(b, time.Millisecond) }

// BenchmarkFastPath: zero-delay packets are delivered inside WriteTo.
func BenchmarkFastPath(b *testing.B) { benchPath(b, 0, WithEventLog(0)) }

// BenchmarkHeap measures one push and one pop of the scheduler heap.
func BenchmarkHeap(b *testing.B) {
	var h eventHeap
	for i := range 1024 {
		h.push(event{at: time.Duration(i * 7919 % 1024), seq: uint64(i)})
	}
	b.ResetTimer()
	for i := range b.N {
		e := h.pop()
		e.at += time.Duration(1024 + i%64)
		h.push(e)
	}
}

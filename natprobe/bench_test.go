package natprobe

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

type discardConn struct{}

func (discardConn) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, net.ErrClosed
}
func (discardConn) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) { return len(b), nil }

// benchPath is the reader path without sockets: the real registry, limiter,
// codec, slot bookkeeping and sealing; writes are discarded.
type benchPath struct {
	reg  *Registry
	rd   *reader
	n    int
	last *handle
}

func newBenchPath() *benchPath {
	reg := NewRegistry(RegistryConfig{ProbeBudgetPerRole: 65535, SessionRate: Rate{PerSec: 1e9, Burst: 1e9}, ExtraQuotaPerRole: 255})
	s := &Server{cfg: ServerConfig{Registry: reg}, reg: reg, src: newSourceLimiter(Rate{PerSec: 1e9, Burst: 1e9}, 4096)}
	p := &pool{conns: []packetConn{discardConn{}}, ports: []uint16{40999}}
	l := &listener{id: 0, fam: protocol.FamilyUDP4, conn: discardConn{}, pool: p, adv: netip.MustParseAddrPort("198.51.100.1:3478")}
	return &benchPath{reg: reg, rd: newReader(s, l, &readerStats{})}
}

// chunk registers a fresh session (one live session at a time) and seals n
// probes for it, as openers when wrap is set.
func (bp *benchPath) chunk(tb testing.TB, n int, extra, wrap bool) [][]byte {
	bp.n++
	token, route := protocol.NewToken(), protocol.NewRouteID()
	bp.last.Close()
	h, err := bp.reg.register(nat.Registration{SessionID: fmt.Sprint("b", bp.n), Route: route, Token: token, TTL: time.Hour})
	if err != nil {
		tb.Fatal(err)
	}
	bp.last = h
	c, err := udpwire.NewCodec(token, route, udpwire.RoleInitiator, udpwire.PadPolicy{Min: 64, Max: 128}, nil)
	if err != nil {
		tb.Fatal(err)
	}
	out := make([][]byte, n)
	for i := range out {
		h := udpwire.Header{Type: udpwire.TProbe, Role: udpwire.RoleInitiator, FA: extra, Cand: udpwire.NoCand, Seq: c.NextSeq(), TS: c.Now()}
		if out[i], err = c.Seal(nil, &h, nil, 0); err != nil {
			tb.Fatal(err)
		}
		if wrap {
			out[i] = c.Wrap(nil, out[i])
		}
	}
	return out
}

// handle is what the reader loop does per datagram.
func (bp *benchPath) handle(pkt []byte, src netip.AddrPort) {
	_ = life.Safe("natprobe/packet", func() { bp.rd.process(pkt, src) })
}

// BenchmarkHandleProbe: the per-packet cost without system calls, route
// unmasking included; 0 allocations.
func BenchmarkHandleProbe(b *testing.B) {
	for _, v := range []struct {
		name        string
		extra, wrap bool
		chunk       int
	}{{"ack", false, false, 60000}, {"ack+extra", true, false, 250}, {"opener/ack", false, true, 60000}, {"opener/ack+extra", true, true, 250}} {
		b.Run(v.name, func(b *testing.B) {
			bp := newBenchPath()
			src := netip.MustParseAddrPort("203.0.113.5:40000")
			var pkts [][]byte
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				if i%v.chunk == 0 {
					b.StopTimer()
					pkts = bp.chunk(b, v.chunk, v.extra, v.wrap)
					b.StartTimer()
				}
				bp.handle(pkts[i%v.chunk], src)
			}
			b.StopTimer()
			if st := bp.rd.st; st.acks.Load() != uint64(b.N) {
				b.Fatalf("acks %d of %d", st.acks.Load(), b.N)
			}
		})
	}
}

// The packet path does not allocate, for a session's first probe, its
// later probes, probes that come as openers and an unknown route
// alike.
func TestHandleProbeZeroAlloc(t *testing.T) {
	bp := newBenchPath()
	src := netip.MustParseAddrPort("203.0.113.5:40000")
	first := func() {
		pkts := bp.chunk(t, 1, false, false)
		if a := testing.AllocsPerRun(1, func() { bp.handle(pkts[0], src) }); a != 0 {
			t.Fatalf("%v allocations for a session's first probe", a)
		}
	}
	first()
	pkts := bp.chunk(t, 2000, false, false)
	i := 0
	if a := testing.AllocsPerRun(1000, func() { bp.handle(pkts[i], src); i++ }); a != 0 {
		t.Fatalf("%v allocations per probe", a)
	}
	pkts, i = bp.chunk(t, 2000, false, true), 0
	if a := testing.AllocsPerRun(1000, func() { bp.handle(pkts[i], src); i++ }); a != 0 {
		t.Fatalf("%v allocations per opener probe", a)
	}
	rnd := make([]byte, 160)
	_, _ = rand.Read(rnd)
	rnd[0] = 0x07
	if a := testing.AllocsPerRun(1000, func() { bp.handle(rnd, src) }); a != 0 {
		t.Fatalf("%v allocations per unknown-route packet", a)
	}
}

// The unknown-route drop rate (target: ≥ 1.5 M packets/s per core).
func BenchmarkUnknownRoute(b *testing.B) {
	bp := newBenchPath()
	ring := make([][]byte, 4096)
	for i := range ring {
		ring[i] = make([]byte, 141+i%120)
		_, _ = rand.Read(ring[i])
		ring[i][0] = byte(udpwire.B0Min + i%12)
	}
	src := netip.MustParseAddrPort("203.0.113.5:40000")
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		bp.handle(ring[i%len(ring)], src)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds()/1e6, "Mpkt/s")
}

// natprobe throughput on loopback with real sockets and replies: one
// listener with one reader (one server core) or the default two, fed by 4
// client goroutines that each keep a window of probes in flight on their own
// socket. BenchmarkLoopbackEcho is the platform's ceiling for the same
// traffic: a bare echo of the datagrams.
func BenchmarkProbeLoopback(b *testing.B) {
	for _, readers := range []int{1, 2} {
		b.Run(fmt.Sprintf("readers=%d", readers), func(b *testing.B) { benchLoopback(b, readers) })
	}
}

const loopbackClients = 4

func benchLoopback(b *testing.B, readers int) {
	reg := NewRegistry(RegistryConfig{ProbeBudgetPerRole: 65535, SessionRate: Rate{PerSec: 1e9, Burst: 1e9}})
	s, err := NewServer(ServerConfig{Registry: reg, Groups: loGroup(), ReadersPerListener: readers, SourceRate: Rate{PerSec: 1e9, Burst: 1e9}})
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Start(); err != nil {
		b.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	const perSession = 60000 // a session per 60000 probes: the lifetime budget
	per := b.N/loopbackClients + 1
	pkts := make([][][]byte, loopbackClients)
	for i := range pkts {
		for len(pkts[i]) < per {
			bp := &benchPath{reg: reg, n: i*1000 + len(pkts[i])/perSession}
			pkts[i] = append(pkts[i], bp.chunk(b, min(perSession, per-len(pkts[i])), false, false)...)
		}
	}
	driveLoopback(b, s.Observers(protocol.FamilyUDP4)[0].Addr, pkts)
}

func BenchmarkLoopbackEcho(b *testing.B) {
	srv, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo4, 0)))
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = srv.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	defer func() { _ = srv.Close(); <-done }()
	per := b.N/loopbackClients + 1
	pkt := make([]byte, 141)
	pkts := make([][][]byte, loopbackClients)
	for i := range pkts {
		for range per {
			pkts[i] = append(pkts[i], pkt)
		}
	}
	driveLoopback(b, srv.LocalAddr().(*net.UDPAddr).AddrPort(), pkts)
}

// driveLoopback sends pkts[i] from client i to to, keeping at most a window
// of 64 datagrams unanswered, and reports the answers per second.
func driveLoopback(b *testing.B, to netip.AddrPort, pkts [][][]byte) {
	const window = 64
	type cl struct {
		conn *net.UDPConn
		pkts [][]byte
		recv atomic.Int64
	}
	cs := make([]*cl, len(pkts))
	for i := range cs {
		conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo4, 0)))
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.SetReadBuffer(4 << 20)
		cs[i] = &cl{conn: conn, pkts: pkts[i]}
	}
	recvDone := make(chan struct{}, len(cs))
	for _, c := range cs {
		go func() {
			defer func() { recvDone <- struct{}{} }()
			buf := make([]byte, 2048)
			for {
				if _, _, err := c.conn.ReadFromUDPAddrPort(buf); err != nil {
					return
				}
				c.recv.Add(1)
			}
		}()
	}
	sendDone := make(chan struct{}, len(cs))
	b.ResetTimer()
	for _, c := range cs {
		go func() {
			defer func() { sendDone <- struct{}{} }()
			for sent := 0; sent < len(c.pkts); {
				n := min(window, len(c.pkts)-sent)
				for k := range n {
					_, _ = c.conn.WriteToUDPAddrPort(c.pkts[sent+k], to)
				}
				sent += n
				deadline := time.Now().Add(100 * time.Millisecond)
				for c.recv.Load() < int64(sent) && time.Now().Before(deadline) {
				}
			}
		}()
	}
	for range cs {
		<-sendDone
	}
	b.StopTimer()
	elapsed := b.Elapsed().Seconds()
	var got, total int64
	for _, c := range cs {
		got += c.recv.Load()
		total += int64(len(c.pkts))
		_ = c.conn.Close()
	}
	for range cs {
		<-recvDone
	}
	b.ReportMetric(float64(got)/elapsed, "replies/s")
	b.ReportMetric(100*float64(total-got)/float64(total), "lost%")
}

// The registry: lock-free concurrent lookups while sessions come and go.
func BenchmarkRegistryLookupParallel(b *testing.B) {
	reg := NewRegistry(RegistryConfig{})
	routes := make([]protocol.RouteID, 4096)
	for i := range routes {
		routes[i] = protocol.NewRouteID()
		if _, err := reg.register(nat.Registration{SessionID: fmt.Sprint("s", i), Route: routes[i], Token: tok(1), TTL: time.Hour}); err != nil {
			b.Fatal(err)
		}
	}
	var writes atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		r := protocol.NewRouteID()
		for pb.Next() {
			i++
			if i%1000 == 0 { // ≈ 0.1 % writes: register and close a session
				r[15]++
				id := writes.Add(1)
				if h, err := reg.register(nat.Registration{SessionID: fmt.Sprint("w", id), Route: r, Token: tok(2), TTL: time.Hour}); err == nil {
					h.Close()
				}
				continue
			}
			if e := reg.lookup(routes[i%len(routes)]); e == nil {
				b.Fatal("lookup failed")
			}
		}
	})
}

func BenchmarkRegisterClose(b *testing.B) {
	reg := NewRegistry(RegistryConfig{})
	for i := range 4096 { // a realistic table: the copy-on-write cost scales with the shard
		if _, err := reg.register(nat.Registration{SessionID: fmt.Sprint("s", i), Route: protocol.NewRouteID(), Token: tok(1), TTL: time.Hour}); err != nil {
			b.Fatal(err)
		}
	}
	routes := make([]protocol.RouteID, 1024)
	for i := range routes {
		routes[i] = protocol.NewRouteID()
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		h, err := reg.register(nat.Registration{SessionID: "x", Route: routes[i%len(routes)], Token: tok(3), TTL: time.Hour})
		if err != nil {
			b.Fatal(err)
		}
		h.Close()
	}
}

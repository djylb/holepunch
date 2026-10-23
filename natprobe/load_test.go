package natprobe

import (
	"bytes"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/probetest"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// Load at component level (no sockets, which only add the kernel's cost): 2000
// registered sessions whose two roles each send 7 probes per family to three
// observers, 56 k probes over 12 readers. Every probe is answered (extras
// within each role's quota), the p99 handling latency stays below 1 ms, no
// goroutine is started and a session costs at most 4 KiB.
func TestLoadManySessions(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	const sessions, perFamily = 2000, 7
	reg := NewRegistry(RegistryConfig{})
	s := &Server{cfg: ServerConfig{Registry: reg}, reg: reg, src: newSourceLimiter(Rate{PerSec: -1}, 4096)}
	pool4 := &pool{conns: []packetConn{discardConn{}}, ports: []uint16{40999}}
	pool6 := &pool{conns: []packetConn{discardConn{}}, ports: []uint16{40999}}
	var ls []*listener
	for i := range 3 {
		ls = append(ls, &listener{id: uint8(i), pi: uint8(i), slots: 1, fam: protocol.FamilyUDP4, conn: discardConn{}, pool: pool4})
		ls = append(ls, &listener{id: uint8(portsPerGroup + i), og: 1, pi: uint8(i), slots: 1, group: 1, fam: protocol.FamilyUDP6, conn: discardConn{}, pool: pool6})
	}
	type job struct {
		pkt []byte
		src netip.AddrPort
	}
	work := make([][]job, len(ls))
	tokens := make([]protocol.Token, sessions)
	routes := make([]protocol.RouteID, sessions)
	for n := range sessions {
		tokens[n], routes[n] = protocol.NewToken(), protocol.NewRouteID()
		for _, role := range []udpwire.Role{udpwire.RoleInitiator, udpwire.RoleResponder} {
			c := newClient(t, tokens[n], routes[n], role)
			for li, l := range ls {
				src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(n >> 8), byte(n)}), 40000+uint16(role))
				if l.fam == protocol.FamilyUDP6 {
					src = netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(n >> 8), 15: byte(n)}), 40000+uint16(role))
				}
				sock := nat.SocketID(l.fam, nat.IndexPrimary)
				// 7 probes per family: 3 observers, retransmissions and keepalives
				for range perFamily/3 + boolInt(li < 2*(perFamily%3)) {
					work[li] = append(work[li], job{pkt: c.probe(probetest.Probe{Sock: sock, Obs: l.id, Extra: true}), src: src})
				}
			}
		}
	}
	total := 0
	for _, w := range work {
		total += len(w)
	}
	// Goroutines are checked against those running now, not their number: one
	// of an earlier test that ends meanwhile would lower the count, and a
	// worker below is still exiting when Wait returns.
	base := goleak.IgnoreCurrent()
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for n := range sessions {
		if _, err := reg.register(nat.Registration{SessionID: fmt.Sprint("load-", n), Route: routes[n], Token: tokens[n], TTL: time.Minute}); err != nil {
			t.Fatal(err)
		}
	}

	stats := make([]readerStats, 12)
	lat := make([][]time.Duration, 12)
	var wg sync.WaitGroup
	start := time.Now()
	for r := range 12 {
		li := r % len(ls)
		rd := newReader(s, ls[li], &stats[r])
		mine := work[li][r/len(ls):]
		lat[r] = make([]time.Duration, 0, len(mine)/2+1)
		wg.Go(func() {
			for i := 0; i < len(mine); i += 2 { // two readers per listener share its packets
				t0 := time.Now()
				rd.process(mine[i].pkt, mine[i].src, netip.Addr{})
				lat[r] = append(lat[r], time.Since(t0))
			}
		})
	}
	wg.Wait()
	elapsed := time.Since(start)

	var after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&after)
	var st ServerStats
	var all []time.Duration
	for r := range stats {
		stats[r].addTo(&st)
		all = append(all, lat[r]...)
	}
	slices.Sort(all)
	p99 := all[len(all)*99/100]
	perSession := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / sessions
	t.Logf("%d probes in %v (%.0f k/s over 12 readers), p99 %v, %d B per session", total, elapsed, float64(total)/elapsed.Seconds()/1e3, p99, perSession)
	if st.Acks != uint64(total) || st.PacketsIn != uint64(total) || st.Extras != 2*sessions*defaultExtraQuota {
		t.Fatalf("stats %+v of %d", st, total)
	}
	switch limit := time.Millisecond; {
	case testkit.RaceEnabled: // the race detector slows every probe too much for a latency bound
	case p99 > limit:
		t.Fatalf("p99 %v > %v", p99, limit)
	}
	if perSession > 4<<10 {
		t.Fatalf("%d B per session > 4 KiB", perSession)
	}
	if err := goleak.Find(base); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(reg)
	runtime.KeepAlive(work)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Packet uniqueness of natprobe's replies: in 1000 acks of one session no byte
// position is constant, and the route never appears on the wire.
func TestRepliesHaveNoConstantByte(t *testing.T) {
	r := newRig(t, rigOpts{reg: RegistryConfig{ProbeBudgetPerRole: 2000, SessionRate: Rate{PerSec: 1e6, Burst: 1e6}}})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	route := rt(1)
	var acks [][]byte
	for range 1000 {
		out := r.deliver(0, c.probe(probetest.Probe{}), srcA)
		if len(out) != 1 {
			t.Fatalf("%d replies", len(out))
		}
		if bytes.Contains(out[0].b, route[:]) {
			t.Fatal("the route is on the wire")
		}
		acks = append(acks, out[0].b)
	}
	for i := range udpwire.MinPeerPacket + 30 { // every ack is at least 83 bytes
		constant := true
		for _, a := range acks[1:] {
			constant = constant && a[i] == acks[0][i]
		}
		if constant {
			t.Fatalf("byte %d is %#x in every ack", i, acks[0][i])
		}
	}
}

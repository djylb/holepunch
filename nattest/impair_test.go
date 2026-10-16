package nattest

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/clock"
)

// linkPair builds, on a fake clock, a host behind a NAT whose uplink
// carries cfg, and a public observer.
func linkPair(t *testing.T, cfg LinkConfig, opts ...Option) (*Network, *clock.Fake, *NAT, udp, udp) {
	t.Helper()
	n, clk := fakeNet(t, opts...)
	_, o := observer(t, n, 3478)
	nat := n.NAT(NATConfig{Uplink: cfg})
	c := listen(t, nat.Host(), 4000)
	return n, clk, nat, c, o
}

func TestLinkLoss(t *testing.T) {
	_, clk, nat, c, o := linkPair(t, LinkConfig{Loss: 0.3})
	got := 0
	for i := range 2000 {
		send(t, c, addrOf(o), "x")
		if i%500 == 0 {
			got += drain(o) // the receive queue holds 1024 packets
		}
	}
	clk.Advance(time.Second)
	got += drain(o)
	if got < 1250 || got > 1550 {
		t.Fatalf("delivered %d/2000 with 30%% loss", got)
	}
	if lost := nat.Stats().Dropped.Loss; int(lost)+got != 2000 {
		t.Fatalf("loss accounting %d + %d", lost, got)
	}
}

func TestLinkDelayAndJitter(t *testing.T) {
	_, clk, _, c, o := linkPair(t, LinkConfig{Delay: 20 * time.Millisecond, Jitter: 10 * time.Millisecond})
	for i := range 200 {
		_, _ = c.WriteToUDPAddrPort([]byte{byte(i)}, addrOf(o))
	}
	clk.Advance(9 * time.Millisecond)
	if queued(o) != 0 {
		t.Fatal("delivered before Delay-Jitter")
	}
	clk.Advance(21 * time.Millisecond) // 30 ms: everything (<= 20+10) has arrived
	if queued(o) != 200 {
		t.Fatalf("%d delivered by Delay+Jitter", queued(o))
	}
	inversions, prev := 0, -1
	b := make([]byte, 1)
	for queued(o) > 0 {
		_, _, _ = o.ReadFromUDPAddrPort(b)
		if int(b[0]) < prev {
			inversions++
		}
		prev = int(b[0])
	}
	if inversions == 0 {
		t.Fatal("jitter produced no reordering")
	}
}

func TestLinkReorderAndDuplicate(t *testing.T) {
	_, clk, _, c, o := linkPair(t, LinkConfig{Reorder: 0.2, Duplicate: 0.1})
	for i := range 500 {
		_, _ = c.WriteToUDPAddrPort([]byte{byte(i), byte(i >> 8)}, addrOf(o))
		clk.Advance(100 * time.Microsecond)
	}
	clk.Advance(time.Second)
	seen := map[int]int{}
	inversions, prev := 0, -1
	b := make([]byte, 2)
	for queued(o) > 0 {
		_, _, _ = o.ReadFromUDPAddrPort(b)
		v := int(b[0]) | int(b[1])<<8
		seen[v]++
		if v < prev {
			inversions++
		}
		prev = v
	}
	dups := 0
	for _, k := range seen {
		dups += k - 1
	}
	if len(seen) != 500 || dups < 25 || dups > 80 {
		t.Fatalf("%d distinct, %d duplicates", len(seen), dups)
	}
	if inversions < 50 {
		t.Fatalf("only %d inversions with 20%% reordering", inversions)
	}
}

// TestLinkDuplicateDelayed: a duplicate of a delayed packet travels on its
// own and passes the remaining hops too.
func TestLinkDuplicateDelayed(t *testing.T) {
	_, clk, _, c, o := linkPair(t, LinkConfig{Duplicate: 1, Delay: 5 * time.Millisecond})
	send(t, c, addrOf(o), "x")
	clk.Advance(5 * time.Millisecond)
	if got := drain(o); got != 2 {
		t.Fatalf("%d copies", got)
	}
}

func TestLinkRateLimit(t *testing.T) {
	_, clk, nat, c, o := linkPair(t, LinkConfig{RatePPS: 100}) // burst 10
	for range 50 {
		send(t, c, addrOf(o), "x")
	}
	if got := drain(o); got != 10 {
		t.Fatalf("burst %d, want 10", got)
	}
	for range 100 { // one packet per 10 ms
		clk.Advance(10 * time.Millisecond)
		send(t, c, addrOf(o), "x")
	}
	if got := drain(o); got != 100 {
		t.Fatalf("steady %d, want 100", got)
	}
	if d := nat.Stats().Dropped.Rate; d != 40 {
		t.Fatalf("rate drops %d", d)
	}
}

func TestLinkMTU(t *testing.T) {
	n, _, nat, c, o := linkPair(t, LinkConfig{MTU: 1280})
	send(t, c, addrOf(o), string(make([]byte, 1252))) // 1252 + 28 = 1280
	recvNow(t, o)
	send(t, c, addrOf(o), string(make([]byte, 1253)))
	expectNone(t, o)
	if nat.Stats().Dropped.MTU != 1 {
		t.Fatal("MTU drop not counted")
	}
	// The core has the default MTU of 1500.
	bc := listen(t, n.PublicHost(netip.IPv4Unspecified()), 1)
	send(t, bc, addrOf(o), string(make([]byte, 1473)))
	expectNone(t, o)
	if n.Stats().Dropped.MTU != 2 {
		t.Fatal("core MTU")
	}
	// IPv6 headers are 20 bytes longer.
	_, o6 := pub6(t, n, 1)
	c6 := listenOn(t, n.PublicHost(netip.IPv6Unspecified()), "udp6", netip.AddrPort{})
	send(t, c6, addrOf(o6), string(make([]byte, 1452)))
	recvNow(t, o6)
	send(t, c6, addrOf(o6), string(make([]byte, 1453)))
	expectNone(t, o6)
}

func TestCoreLinkAndSetLink(t *testing.T) {
	_, clk, nat, c, o := linkPair(t, LinkConfig{Loss: 1}, WithCoreLink(LinkConfig{Delay: 5 * time.Millisecond}))
	nat.SetLink(LinkConfig{Delay: 15 * time.Millisecond})
	send(t, c, addrOf(o), "x")
	clk.Advance(19 * time.Millisecond)
	expectNone(t, o)
	clk.Advance(time.Millisecond)
	recvNow(t, o)
}

func TestScanDefenseDistinctPorts(t *testing.T) {
	n, clk := fakeNet(t)
	peer := n.PublicHost(netip.IPv4Unspecified())
	_, o := observer(t, n, 3478)
	nat := n.NAT(NATConfig{MappingTimeout: NoTimeout, ScanDefense: &ScanDefense{DistinctDstPorts: 20, MaxConsecutiveRun: -1, BanFor: time.Minute}})
	h := nat.Host()
	c := listen(t, h, 4000)
	m := srcAt(t, c, o)
	for i := range 20 { // exactly at the threshold: fine
		send(t, c, netip.AddrPortFrom(peer.Addrs()[0], uint16(10000+i*7)), "s")
	}
	if nat.Stats().ScanBans != 0 {
		t.Fatal("banned at the threshold")
	}
	send(t, c, netip.AddrPortFrom(peer.Addrs()[0], 20000), "21st")
	if st := nat.Stats(); st.ScanBans != 1 || st.Dropped.Ban != 1 {
		t.Fatalf("%+v", st)
	}
	// The whole source IP is banned, in both directions, for BanFor.
	other := listen(t, h, 4001)
	send(t, other, addrOf(o), "other socket")
	send(t, o, m, "inbound")
	expectNone(t, o)
	expectNone(t, c)
	clk.Advance(time.Minute)
	send(t, o, m, "inbound")
	recvNow(t, c)
	if nat.Stats().ScanBans != 1 {
		t.Fatal("the ban was counted twice")
	}
}

func TestScanDefenseWindowSlides(t *testing.T) {
	n, clk := fakeNet(t)
	peer := n.PublicHost(netip.IPv4Unspecified())
	nat := n.NAT(NATConfig{ScanDefense: &ScanDefense{DistinctDstPorts: 10}})
	c := listen(t, nat.Host(), 4000)
	for i := range 40 { // bursts of 10 distinct ports, one window apart
		send(t, c, netip.AddrPortFrom(peer.Addrs()[0], uint16(10000+i*3)), "s")
		if i%10 == 9 {
			clk.Advance(11 * time.Second)
		}
	}
	if st := nat.Stats(); st.ScanBans != 0 {
		t.Fatalf("bursts separated by the window were banned: %+v", st)
	}
	// Idle trackers are forgotten once their window has passed.
	clk.Advance(11 * time.Second)
	other := n.PublicHost(netip.IPv4Unspecified())
	send(t, c, netip.AddrPortFrom(other.Addrs()[0], 1), "s")
	if len(nat.scan.out) != 1 {
		t.Fatalf("%d trackers kept after their window", len(nat.scan.out))
	}
}

func TestScanDefenseConsecutiveRun(t *testing.T) {
	n, _ := fakeNet(t)
	peer := n.PublicHost(netip.IPv4Unspecified())
	nat := n.NAT(NATConfig{ScanDefense: &ScanDefense{MaxConsecutiveRun: 8}})
	c := listen(t, nat.Host(), 4000)
	for i := range 8 { // descending runs count too
		send(t, c, netip.AddrPortFrom(peer.Addrs()[0], uint16(30008-i)), "down")
	}
	if nat.Stats().ScanBans != 0 {
		t.Fatal("a run of 8 was banned")
	}
	send(t, c, netip.AddrPortFrom(peer.Addrs()[0], 30000), "9th")
	if nat.Stats().ScanBans != 1 {
		t.Fatal("a run of 9 was not banned")
	}
}

func TestScanDefenseUnsolicitedInbound(t *testing.T) {
	n, clk := fakeNet(t)
	_, sc := observer(t, n, 1)
	_, friend := observer(t, n, 3478)
	nat := n.NAT(NATConfig{Filtering: APDF, ScanDefense: &ScanDefense{UnsolicitedInbound: 5, BanFor: 10 * time.Second}})
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, friend)
	srcAt(t, c, sc) // c talks to the scanner's port 1 ...
	for i := range 6 {
		send(t, sc, netip.AddrPortFrom(m.Addr(), uint16(20000+i)), "knock") // ... which knocks elsewhere
	}
	if st := nat.Stats(); st.ScanBans != 1 || st.FilteredInbound != 6 {
		t.Fatalf("%+v", st)
	}
	send(t, sc, m, "legitimate but banned")
	expectNone(t, c)
	send(t, c, addrOf(sc), "towards the banned IP")
	expectNone(t, sc)
	send(t, friend, m, "friend")
	recvNow(t, c)
	clk.Advance(10 * time.Second)
	send(t, sc, m, "after the ban")
	recvNow(t, c)
}

// TestScanDefenseDefaults: an empty ScanDefense uses the default
// thresholds, and 64 consecutive ports are fine while 65 are not.
func TestScanDefenseDefaults(t *testing.T) {
	n, _ := fakeNet(t)
	peer := n.PublicHost(netip.IPv4Unspecified())
	nat := n.NAT(NATConfig{ScanDefense: &ScanDefense{}})
	c := listen(t, nat.Host(), 4000)
	for i := range 64 {
		send(t, c, netip.AddrPortFrom(peer.Addrs()[0], uint16(40000+i)), "run")
	}
	if nat.Stats().ScanBans != 0 {
		t.Fatal("banned at the default run threshold")
	}
	send(t, c, netip.AddrPortFrom(peer.Addrs()[0], 40064), "65th")
	if nat.Stats().ScanBans != 1 {
		t.Fatal("not banned above the default run threshold")
	}
}

func TestRunState(t *testing.T) {
	var r runState
	best := 0
	for i, p := range []uint16{100, 99, 98, 98, 97, 50, 51, 52} {
		best = max(best, r.add(time.Duration(i), p, time.Second))
	}
	if best != 4 {
		t.Fatalf("run %d, want 4", best)
	}
	if r.add(10*time.Second, 53, time.Second) != 1 {
		t.Fatal("a pause must restart the run")
	}
	var w countWindow
	w.win = time.Second
	w.add(0)
	w.add(time.Second / 2)
	if w.count(time.Second) != 1 {
		t.Fatal("countWindow")
	}
	// A long run reuses the queue instead of growing it for ever.
	for i := range 10000 {
		w.add(time.Second + time.Duration(i)*time.Millisecond)
	}
	if got := w.count(11 * time.Second); got != 999 || len(w.q) > 4096 { // (10 s, 11 s)
		t.Fatalf("count %d, queue %d", got, len(w.q))
	}
}

func TestPortNoiseSequential(t *testing.T) {
	n, clk := fakeNet(t)
	cfg := SymmetricSeq(1)
	cfg.PortNoisePPS = 20
	nat := n.NAT(cfg)
	c := listen(t, nat.Host(), 4000)
	var gaps []int
	prev := -1
	for i := range 50 {
		_, o := observer(t, n, uint16(100+i))
		p := int(srcAt(t, c, o).Port())
		if prev >= 0 {
			gaps = append(gaps, p-prev-1) // ports other subscribers took in between
		}
		prev = p
		clk.Advance(500 * time.Millisecond)
	}
	sum := 0
	for _, g := range gaps {
		sum += g
	}
	if mean := float64(sum) / float64(len(gaps)); math.Abs(mean-10) > 3 { // λ·Δt = 20 × 0.5 s
		t.Fatalf("mean noise gap %.2f, want about 10 (gaps %v)", mean, gaps)
	}
	if st := nat.Stats(); st.NoiseAllocs < 400 || st.NoiseActive == 0 {
		t.Fatalf("%+v", st)
	}
	// Without noise the sequence is exact.
	quiet := listen(t, n.NAT(SymmetricSeq(1)).Host(), 4000)
	_, o1 := observer(t, n, 1)
	_, o2 := observer(t, n, 2)
	clk.Advance(time.Second)
	if d := int(srcAt(t, quiet, o2).Port()) - int(srcAt(t, quiet, o1).Port()); d != -1 {
		t.Fatalf("quiet NAT delta %d", d)
	}
}

func TestPortNoiseOccupiesAndExpires(t *testing.T) {
	n, clk := fakeNet(t)
	cfg := SymmetricRandom()
	cfg.PortRange = [2]uint16{5000, 5099}
	cfg.PortNoisePPS = 50
	cfg.MappingTimeout = 2 * time.Second
	nat := n.NAT(cfg)
	clk.Advance(time.Second)
	if a := nat.Stats().NoiseActive; a < 30 || a > 70 {
		t.Fatalf("active noise %d", a)
	}
	clk.Advance(10 * time.Second) // about λ·hold = 100 ports, capped by the range
	if st := nat.Stats(); st.NoiseActive > 100 {
		t.Fatalf("noise overflows the range: %+v", st)
	}
	nat.ExpireAll()
	if st := nat.Stats(); st.NoiseActive != 0 {
		t.Fatalf("ExpireAll kept the noise: %+v", st)
	}
}

// TestPortNoiseLongIdle: a fake clock advanced by hours realizes a bounded
// amount of noise instead of stalling.
func TestPortNoiseLongIdle(t *testing.T) {
	n, clk := fakeNet(t)
	cfg := SymmetricSeq(1)
	cfg.PortNoisePPS = 100
	cfg.MappingTimeout = NoTimeout
	nat := n.NAT(cfg)
	clk.Advance(24 * time.Hour)
	if st := nat.Stats(); st.NoiseAllocs > maxNoiseCatchUp {
		t.Fatalf("%d noise events in one catch-up", st.NoiseAllocs)
	}
}

// TestScanDefenseForgetsSilentScanners: the trackers of unsolicited sources
// are forgotten once their window has passed, even when the LAN sends
// nothing that would sweep them.
func TestScanDefenseForgetsSilentScanners(t *testing.T) {
	n, clk := fakeNet(t)
	nat := n.NAT(NATConfig{ScanDefense: &ScanDefense{UnsolicitedInbound: 2, Window: time.Second, BanFor: time.Second}})
	target := netip.AddrPortFrom(ext(t, nat), 4000)
	for range 20 {
		c := listen(t, n.PublicHost(netip.IPv4Unspecified()), 1)
		for range 3 { // the third knock bans the source
			send(t, c, target, "knock")
		}
	}
	if st := nat.Stats(); st.ScanBans != 20 || len(nat.scan.unsol) != 20 || len(nat.scan.banExt) != 20 {
		t.Fatalf("bans %d, trackers %d, banned %d", st.ScanBans, len(nat.scan.unsol), len(nat.scan.banExt))
	}
	clk.Advance(2 * time.Second)
	send(t, listen(t, n.PublicHost(netip.IPv4Unspecified()), 1), target, "knock")
	if len(nat.scan.unsol) != 1 || len(nat.scan.banExt) != 0 {
		t.Fatalf("%d trackers and %d bans kept after their window", len(nat.scan.unsol), len(nat.scan.banExt))
	}
}

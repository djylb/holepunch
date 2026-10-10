package nattest

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestHostStats(t *testing.T) {
	n, clk := fakeNet(t)
	ho, o := observer(t, n, 1000)
	h := n.NAT(PortRestricted()).Host()
	c := listen(t, h, 4000)
	// Five consecutive ports and three scattered ones, 3 bytes each.
	for i, p := range []uint16{2000, 2001, 2002, 2003, 2004, 9000, 7000, 8000} {
		if _, err := c.WriteToUDPAddrPort([]byte{byte(4 + i%2), 1, 2}, netip.AddrPortFrom(ho.Addrs()[0], p)); err != nil {
			t.Fatal(err)
		}
	}
	clk.Advance(2 * time.Second)
	send(t, c, addrOf(o), "hello")
	st := h.Stats()
	if st.PacketsSent != 9 || st.BytesSent != 8*3+5 {
		t.Fatalf("sent %d/%d", st.PacketsSent, st.BytesSent)
	}
	if st.PeakPPS100ms != 8 || st.PeakPPS1s != 8 {
		t.Fatalf("peaks %d %d", st.PeakPPS100ms, st.PeakPPS1s)
	}
	if st.DistinctDstPortsPerIP10s != 9 || st.MaxConsecutiveRun != 5 {
		t.Fatalf("distinct %d run %d", st.DistinctDstPortsPerIP10s, st.MaxConsecutiveRun)
	}
	if st.FirstByteHistogram[4] != 4 || st.FirstByteHistogram[5] != 4 || st.FirstByteHistogram['h'] != 1 {
		t.Fatal("first-byte histogram")
	}
	if st.LenHistogram[3] != 8 || st.LenHistogram[5] != 1 {
		t.Fatalf("length histogram %v", st.LenHistogram)
	}
	if !st.FirstSendTo[ho.Addrs()[0]].Equal(st.FirstSendAt) || st.SocketsOpened != 1 || st.SocketsByPurpose["test"] != 1 {
		t.Fatalf("stats %+v", st)
	}
	if os := ho.Stats(); os.DroppedNoSocket != 8 || os.PacketsRecv != 1 || os.BytesRecv != 5 {
		t.Fatalf("observer stats %+v", os)
	}
	if h.OpenSockets() != 1 {
		t.Fatal("open sockets")
	}
	_ = c.Close()
	if st := h.Stats(); h.OpenSockets() != 0 || st.SocketsClosed != 1 || !st.Sockets[0].Closed {
		t.Fatal("the socket is not accounted closed")
	}
}

func TestNetStats(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1000)
	nat := n.NAT(PortRestricted())
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, o)
	send(t, o, netip.AddrPortFrom(m.Addr(), m.Port()+1), "filtered")
	send(t, o, netip.MustParseAddrPort("203.0.113.250:1"), "nobody")
	st := n.Stats()
	if st.PacketsSent != 3 || st.PacketsDelivered != 1 || st.FilteredInbound != 1 || st.Dropped.NoRoute != 1 || st.Dropped.Total() != 1 {
		t.Fatalf("%+v", st)
	}
	if (DropStats{Loss: 1, TTL: 2, Closed: 3, PortExhausted: 4}).Total() != 10 {
		t.Fatal("Total")
	}
}

// sessionShape is how an e2e test reads the packet shape of one session from
// the sockets the session opened.
type sessionShape struct {
	packets        uint64
	firstBytes     map[byte]uint64
	minLen, maxLen int
	constOffsets   []int
}

func shapeOf(socks []SocketStats) sessionShape {
	s := sessionShape{firstBytes: map[byte]uint64{}, minLen: 1 << 30}
	for _, k := range socks {
		s.packets += k.PacketsSent
		for b, c := range k.FirstByteHistogram {
			if c > 0 {
				s.firstBytes[byte(b)] += c
			}
		}
		for l := range k.LenHistogram {
			s.minLen, s.maxLen = min(s.minLen, l), max(s.maxLen, l)
		}
		s.constOffsets = append(s.constOffsets, k.ConstantOffsets...)
	}
	return s
}

// TestPacketShapePerSession shows the packet uniqueness assertions on the
// per-socket statistics: every byte position varies within a session, the
// first byte stays in [0x04, 0x0F], and each session has its own length
// interval, even when the sessions run on the same host.
func TestPacketShapePerSession(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 3478)
	h := n.NAT(FullCone()).Host()
	rng := rand.New(rand.NewPCG(1, 2))
	// session sends 2×40 packets from two sockets, with lengths in [lo, hi];
	// a legacy layout repeats a 16-byte route after the first byte.
	session := func(lo, hi int, legacy bool) {
		var route [16]byte
		for i := range route {
			route[i] = byte(rng.Uint32())
		}
		for _, purpose := range []string{"probe", "sibling"} {
			pc, err := h.ListenPacket(context.Background(), "udp4", netip.AddrPort{}, purpose)
			if err != nil {
				t.Fatal(err)
			}
			for range 40 {
				p := make([]byte, lo+rng.IntN(hi-lo+1))
				for i := range p {
					p[i] = byte(rng.Uint32())
				}
				p[0] = byte(0x04 + rng.IntN(12))
				if legacy {
					copy(p[1:], route[:])
				}
				if _, err := pc.(udp).WriteToUDPAddrPort(p, addrOf(o)); err != nil {
					t.Fatal(err)
				}
				drain(o)
			}
			_ = pc.Close()
		}
	}
	session(48, 112, false)
	session(160, 416, false)
	session(60, 120, true)
	pmap, err := h.ListenPacket(context.Background(), "udp4", netip.AddrPort{}, "portmap")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pmap.Close() }()
	for range 3 { // a NAT-PMP request: constant bytes, excluded by purpose
		_, _ = pmap.(udp).WriteToUDPAddrPort([]byte{0, 1, 0, 0, 0x13, 0x88, 0, 0, 0, 0, 0x0e, 0x10}, addrOf(o))
	}

	st := h.Stats()
	var lib []SocketStats
	for _, s := range st.Sockets {
		if s.Purpose != "portmap" {
			lib = append(lib, s)
		}
	}
	if len(lib) != 6 || len(st.Sockets) != 7 {
		t.Fatalf("%d library sockets of %d", len(lib), len(st.Sockets))
	}
	s1, s2, legacy := shapeOf(lib[0:2]), shapeOf(lib[2:4]), shapeOf(lib[4:6])
	for i, s := range []sessionShape{s1, s2} {
		if s.packets != 80 || len(s.constOffsets) != 0 {
			t.Fatalf("session %d: %d packets, constant offsets %v", i+1, s.packets, s.constOffsets)
		}
		for b := range s.firstBytes {
			if b < 0x04 || b > 0x0f {
				t.Fatalf("session %d: first byte %#x outside [0x04, 0x0F]", i+1, b)
			}
		}
		if len(s.firstBytes) < 10 {
			t.Fatalf("session %d: only %d first-byte values", i+1, len(s.firstBytes))
		}
	}
	if s1.maxLen >= s2.minLen || s1.minLen < 48 || s2.maxLen > 416 {
		t.Fatalf("length intervals [%d,%d] and [%d,%d] do not tell the sessions apart", s1.minLen, s1.maxLen, s2.minLen, s2.maxLen)
	}
	want := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	for _, s := range lib[4:6] {
		if !slices.Equal(s.ConstantOffsets, want) {
			t.Fatalf("legacy layout: constant offsets %v, want the route bytes", s.ConstantOffsets)
		}
	}
	if len(legacy.constOffsets) == 0 {
		t.Fatal("the legacy layout went unnoticed")
	}
	if pm := st.Sockets[6]; len(pm.ConstantOffsets) != 12 || pm.FirstByteHistogram[0] != 3 {
		t.Fatalf("portmap socket %+v", pm)
	}
	var total uint64
	for _, k := range st.FirstByteHistogram {
		total += k
	}
	if total != st.PacketsSent || total != 243 {
		t.Fatalf("host histogram counts %d of %d packets", total, st.PacketsSent)
	}
}

func TestConstantOffsets(t *testing.T) {
	var s constScan
	if got := s.offsets(0); got != nil {
		t.Fatalf("no packet: %v", got)
	}
	s.add([]byte{1, 2, 3, 4})
	if got := s.offsets(1); got != nil {
		t.Fatalf("one packet: %v", got)
	}
	s.add([]byte{9, 2, 3, 4, 5})
	if got := s.offsets(2); !slices.Equal(got, []int{1, 2, 3}) {
		t.Fatalf("two packets: %v", got)
	}
	s.add([]byte{9, 2}) // a shorter packet drops the offsets beyond it
	if got := s.offsets(3); !slices.Equal(got, []int{1}) {
		t.Fatalf("short packet: %v", got)
	}
	s.add([]byte{9, 7, 3})
	if got := s.offsets(4); got != nil || s.ref != nil {
		t.Fatalf("all varying: %v", got)
	}
	s.add([]byte{1})
	if got := s.offsets(5); got != nil {
		t.Fatalf("after all varied: %v", got)
	}
	var e constScan
	e.add(nil)
	e.add([]byte{1})
	if got := e.offsets(2); got != nil {
		t.Fatalf("empty first packet: %v", got)
	}
	var big constScan
	big.add(make([]byte, shapeBytes+100))
	big.add(make([]byte, shapeBytes+100))
	if got := big.offsets(2); len(got) != shapeBytes {
		t.Fatalf("compared %d offsets, want %d", len(got), shapeBytes)
	}
}

// TestClosedSocketsKept: a long test does not accumulate the statistics of
// every socket it ever closed.
func TestClosedSocketsKept(t *testing.T) {
	n := newNet(t)
	h := n.PublicHost(netip.IPv4Unspecified())
	keep := listen(t, h, 1)
	for range closedSocketsKept + 10 {
		pc, err := h.Listen("udp4", netip.AddrPort{})
		if err != nil {
			t.Fatal(err)
		}
		_ = pc.Close()
	}
	st := h.Stats()
	if len(st.Sockets) != closedSocketsKept+1 || st.Sockets[0].Local != addrOf(keep) || st.Sockets[0].Closed {
		t.Fatalf("%d sockets kept, first %+v", len(st.Sockets), st.Sockets[0])
	}
	if st.SocketsOpened != closedSocketsKept+11 || st.SocketsClosed != closedSocketsKept+10 {
		t.Fatalf("opened %d closed %d", st.SocketsOpened, st.SocketsClosed)
	}
}

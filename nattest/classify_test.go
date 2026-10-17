package nattest

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/stun"
)

// stunMsg returns a STUN Binding Request of n attribute bytes (a multiple
// of four).
func stunMsg(n int) []byte {
	b := make([]byte, 20+n)
	binary.BigEndian.PutUint16(b, 0x0001)
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	binary.BigEndian.PutUint32(b[4:], stun.MagicCookie)
	return b
}

// TestClassifier checks the outbound protocol classifier: per flow,
// datagrams after the fifth are cut unless one of the first five was a
// STUN message; a flow it allowed passes for good; each destination is a
// flow of its own; the dropped datagrams still mapped, and are counted.
func TestClassifier(t *testing.T) {
	n := newNet(t)
	_, o1 := observer(t, n, 1)
	_, o2 := observer(t, n, 2)
	_, o3 := observer(t, n, 3)
	cfg := FullCone()
	cfg.Classifier = &Classifier{}
	nat := n.NAT(cfg)
	c := listen(t, nat.Host(), 4000)
	for i := range 5 {
		send(t, c, addrOf(o1), "plain")
		if msg, _ := recvNow(t, o1); msg != "plain" {
			t.Fatalf("datagram %d: %q", i+1, msg)
		}
	}
	send(t, c, addrOf(o1), "sixth")
	expectNone(t, o1)
	if _, err := c.WriteToUDPAddrPort(stunMsg(8), addrOf(o1)); err != nil {
		t.Fatal(err)
	}
	expectNone(t, o1) // too late: the flow is cut

	if _, err := c.WriteToUDPAddrPort(stunMsg(8), addrOf(o2)); err != nil {
		t.Fatal(err)
	}
	recvNow(t, o2)
	for range 20 {
		send(t, c, addrOf(o2), "after stun")
		recvNow(t, o2)
	}

	for range 4 {
		send(t, c, addrOf(o3), "plain")
		recvNow(t, o3)
	}
	if _, err := c.WriteToUDPAddrPort(stunMsg(4), addrOf(o3)); err != nil {
		t.Fatal(err)
	}
	recvNow(t, o3)
	for range 10 {
		send(t, c, addrOf(o3), "fifth was stun")
		recvNow(t, o3)
	}
	if d := nat.Stats().Dropped.Classified; d != 2 {
		t.Fatalf("classified drops %d, want 2", d)
	}
}

// TestClassifierWindowAndIdle checks a configured window and match, and
// that a flow idle for MappingTimeout is inspected anew.
func TestClassifierWindowAndIdle(t *testing.T) {
	n, clk := fakeNet(t)
	_, o := observer(t, n, 1)
	cfg := FullCone()
	cfg.MappingTimeout = 10 * time.Second
	cfg.Classifier = &Classifier{Window: 2, Allow: func(b []byte) bool { return string(b) == "hello" }}
	c := listen(t, n.NAT(cfg).Host(), 4000)
	send(t, c, addrOf(o), "x")
	send(t, c, addrOf(o), "hello")
	for range 5 {
		send(t, c, addrOf(o), "y")
	}
	if k := queued(o); k != 7 {
		t.Fatalf("%d delivered, want 7", k)
	}
	clk.Advance(11 * time.Second)
	for range 3 {
		send(t, c, addrOf(o), "z")
	}
	if k := queued(o); k != 9 {
		t.Fatalf("%d delivered after the idle time, want 9", k)
	}
}

// TestRoutes checks NATConfig.Routes. A route with the device's own rules
// is a path-dependent mapping: a socket's mapping toward the
// route's prefix differs from its mapping toward every other destination,
// each endpoint independent within its path, on the same external IP. A
// route of its own kind — a proxy that maps each destination apart at
// random and admits anyone, beside a port-restricted cone — keeps
// its rules: its mappings take inbound packets from any source, the
// device's own do not, and a reply leaves on the path of its destination
// through the mapping toward it, never through the proxy mapping that
// admitted the packet.
func TestRoutes(t *testing.T) {
	n := newNet(t)
	srv, o1 := observer(t, n, 1)
	_, o2 := observer(t, n, 2)
	_, o3 := observer(t, n, 3)
	cfg := FullCone()
	cfg.Routes = []Route{{Dst: []netip.Prefix{netip.PrefixFrom(srv.Addrs()[0], 32)}}}
	c := listen(t, n.NAT(cfg).Host(), 4000)
	toServer := srcAt(t, c, o1)
	toOthers := srcAt(t, c, o2)
	if toServer.Port() != 4000 {
		t.Fatalf("the first mapping %v did not keep the port", toServer)
	}
	if toOthers == toServer || toOthers.Addr() != toServer.Addr() {
		t.Fatalf("paths %v and %v: want one IP, two ports", toServer, toOthers)
	}
	if again := srcAt(t, c, o3); again != toOthers {
		t.Fatalf("other destinations map to %v and %v", toOthers, again)
	}

	// A port-restricted cone toward o1, a proxy toward everybody else.
	_, p2 := observer(t, n, 4)
	_, p3 := observer(t, n, 5)
	cfg = PortRestricted()
	cfg.Routes = []Route{
		{Dst: []netip.Prefix{netip.PrefixFrom(srv.Addrs()[0], 32)}, Mapping: EIM, Filtering: APDF, PortAlloc: Preserve},
		{Dst: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Mapping: APDM, Filtering: EIF, PortAlloc: Random, Proxy: true},
	}
	c = listen(t, n.NAT(cfg).Host(), 5000)
	cone := srcAt(t, c, o1)
	if cone.Port() != 5000 {
		t.Fatalf("the cone route did not keep the port: %v", cone)
	}
	a2, a3 := srcAt(t, c, p2), srcAt(t, c, p3)
	if a2 == a3 || a2 == cone {
		t.Fatalf("proxy mappings %v and %v beside %v: want one per destination", a2, a3, cone)
	}
	send(t, p3, a2, "to the proxy mapping toward p2") // anyone may use it
	if msg, _ := recvNow(t, c); msg != "to the proxy mapping toward p2" {
		t.Fatalf("got %q", msg)
	}
	send(t, p3, cone, "to the cone")
	expectNone(t, c)
	_, o9 := observer(t, n, 9)
	send(t, o9, a2, "from a stranger")
	_, from := recvNow(t, c)
	send(t, c, from, "reply")
	if _, src := recvNow(t, o9); src == a2 {
		t.Fatalf("the reply left through the proxy mapping %v that admitted the packet", a2)
	}
}

// TestSocketStatsSTUN checks how HostStats accounts STUN messages: apart
// from the packet shape (first bytes, constant offsets), with the flows they
// opened and those that a plain packet opened.
func TestSocketStatsSTUN(t *testing.T) {
	n := newNet(t)
	_, o1 := observer(t, n, 1)
	_, o2 := observer(t, n, 2)
	h := n.NAT(FullCone()).Host()
	c := listen(t, h, 4000)
	if _, err := c.WriteToUDPAddrPort(stunMsg(8), addrOf(o1)); err != nil {
		t.Fatal(err)
	}
	send(t, c, addrOf(o1), "abc")
	send(t, c, addrOf(o1), "xyz")
	send(t, c, addrOf(o2), "plain first")
	if _, err := c.WriteToUDPAddrPort(stunMsg(4), addrOf(o2)); err != nil {
		t.Fatal(err)
	}
	var s SocketStats
	for _, x := range h.Stats().Sockets {
		if x.Local.Port() == 4000 {
			s = x
		}
	}
	if s.PacketsSent != 5 || s.STUNPackets != 2 || s.Flows != 2 || s.PlainFirst != 1 || s.STUNAfterPlain != 1 {
		t.Fatalf("stats %+v", s)
	}
	if s.FirstByteHistogram[0] != 0 || s.FirstByteHistogram['a'] != 1 {
		t.Fatalf("STUN first bytes counted: %v", s.FirstByteHistogram['a'])
	}
}

// TestClassifierAllowRunsUnlocked: Allow is the caller's code and runs
// without the device's lock, so it may call back into the device.
func TestClassifierAllowRunsUnlocked(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1)
	cfg := FullCone()
	var nat *NAT
	seen := 0
	cfg.Classifier = &Classifier{Allow: func([]byte) bool {
		seen += len(nat.Mappings()) // deadlocks if called under the lock
		return true
	}}
	nat = n.NAT(cfg)
	c := listen(t, nat.Host(), 4000)
	for range 3 {
		send(t, c, addrOf(o), "x")
		recvNow(t, o)
	}
	if seen != 1 {
		t.Fatalf("Allow ran %d times, want once: the first datagram allows the flow", seen)
	}
}

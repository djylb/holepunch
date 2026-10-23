package nattest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/leak"
	"github.com/djylb/holepunch/natprobe"
)

// *Host has the method set of holepunch.Network, which internal/leak repeats
// with std types; Listen fits natprobe.ServerConfig.Listen; the sockets
// are HopLimiters; pipes are net.Conns.
var (
	_ leak.Network    = (*Host)(nil)
	_                 = natprobe.ServerConfig{Listen: (*Host)(nil).Listen}
	_ leak.HopLimiter = (*conn)(nil)
	_ leak.HopLimiter = callerConn{}
	_ Conn            = (*conn)(nil)
	_ Conn            = callerConn{}
	_ net.Conn        = (*PipeConn)(nil)
)

// TestTrackingNetwork runs a host through internal/leak's TrackingNetwork,
// as the library's socket-leak assertions do: the tracked sockets keep the
// HopLimiter capability.
func TestTrackingNetwork(t *testing.T) {
	n := newNet(t)
	tn := leak.NewTrackingNetwork(n.PublicHost())
	pc, err := tn.ListenPacket(context.Background(), "udp4", netip.AddrPort{}, "probe")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pc.(leak.HopLimiter); !ok {
		t.Fatal("the tracked socket lost SetHopLimit")
	}
	if err := tn.CheckOpen(1); err != nil {
		t.Fatal(err)
	}
	_ = pc.Close()
	if err := tn.CheckClosed(); err != nil {
		t.Fatal(err)
	}
}

func TestHostNetworkMethods(t *testing.T) {
	n := newNet(t)
	srv := n.PublicHost()
	n.SetDNS("stun.example.", srv.Addrs()...)
	nat := n.NAT(NATConfig{IPv6: &IPv6Config{Mode: NoNAT, Firewall: APDF}})
	var nw leak.Network = nat.Host()
	ctx := context.Background()

	ifaces, addrs, err := nw.InterfaceAddrs()
	if err != nil || len(ifaces) != 1 || ifaces[0].Name != "eth0" || ifaces[0].Flags&net.FlagUp == 0 || len(addrs) != 1 {
		t.Fatalf("InterfaceAddrs %v %v %v", ifaces, addrs, err)
	}
	pfx := addrs[0]
	if len(pfx) != 2 || !pfx[0].Addr().Is4() || pfx[0].Bits() != 16 || pfx[1].Bits() != 64 {
		t.Fatalf("InterfaceAddrs %v", pfx)
	}
	a4, err := nw.OutboundAddr(ctx, "udp4")
	if err != nil || a4 != pfx[0].Addr() {
		t.Fatalf("OutboundAddr udp4 %v %v", a4, err)
	}
	a6, err := nw.OutboundAddr(ctx, "udp6")
	if err != nil || a6 != pfx[1].Addr() || !a6.IsGlobalUnicast() || a6.IsPrivate() {
		t.Fatalf("OutboundAddr udp6 %v %v", a6, err)
	}
	if a, _ := nw.OutboundAddr(ctx, "udp"); a != a4 {
		t.Fatalf("OutboundAddr Conn %v", a)
	}
	got, err := nw.LookupNetIP(ctx, "ip4", "STUN.example")
	if err != nil || len(got) != 1 || got[0] != srv.Addrs()[0] {
		t.Fatalf("lookup ip4 %v %v", got, err)
	}
	if got, _ := nw.LookupNetIP(ctx, "ip", "stun.example"); len(got) != 2 {
		t.Fatalf("lookup ip %v", got)
	}
	if got, _ := nw.LookupNetIP(ctx, "ip6", "[2001:db8::1]"); len(got) != 1 {
		t.Fatalf("literal %v", got)
	}
	if got, _ := nw.LookupNetIP(ctx, "ip4", "localhost"); len(got) != 1 || !got[0].IsLoopback() {
		t.Fatalf("localhost %v", got)
	}
	var dnsErr *net.DNSError
	if _, err := nw.LookupNetIP(ctx, "ip", "nope.example"); !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("missing name: %v", err)
	}
	if _, err := nw.LookupNetIP(ctx, "ip6", "192.0.2.1"); !errors.As(err, &dnsErr) {
		t.Fatalf("family filter: %v", err)
	}
	n.SetDNS("stun.example")
	if _, err := nw.LookupNetIP(ctx, "ip", "stun.example"); err == nil {
		t.Fatal("a removed name still resolves")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := nw.ListenPacket(cctx, "udp", netip.AddrPort{}, "probe"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ListenPacket: %v", err)
	}
	if _, err := nw.OutboundAddr(cctx, "udp"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled OutboundAddr: %v", err)
	}
	if _, err := nw.LookupNetIP(cctx, "ip", "localhost"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled LookupNetIP: %v", err)
	}
	v4only := n.NAT(FullCone()).Host()
	if _, err := v4only.OutboundAddr(ctx, "udp6"); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("v6 on a v4-only host: %v", err)
	}
}

func TestListenSemantics(t *testing.T) {
	n := newNet(t)
	h := n.PublicHost()
	v4, v6 := h.Addrs()[0], h.Addrs()[1]
	ctx := context.Background()
	c, err := h.ListenUDP(ctx, "udp", netip.AddrPort{}, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	port := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	if port < ephemeralLo || port > ephemeralHi {
		t.Fatalf("ephemeral port %d", port)
	}
	// A dual-stack wildcard holds the port in both families.
	for _, nw := range []string{"udp4", "udp6"} {
		if _, err := h.ListenPacket(ctx, nw, netip.AddrPortFrom(netip.Addr{}, port), "x"); !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("%s reuse: %v", nw, err)
		}
	}
	// A specific address and a wildcard conflict; two specific addresses do not.
	c4 := listenOn(t, h, "udp4", netip.AddrPortFrom(v4, 7000))
	if _, err := h.Listen("udp4", netip.AddrPortFrom(netip.Addr{}, 7000)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("wildcard over specific: %v", err)
	}
	listenOn(t, h, "udp6", netip.AddrPortFrom(v6, 7000))
	if _, err := h.Listen("udp4", netip.AddrPortFrom(v4, 7000)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("specific twice: %v", err)
	}
	if _, err := h.Listen("udp4", netip.MustParseAddrPort("198.51.100.200:1")); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("foreign address: %v", err)
	}
	if _, err := h.Listen("udp4", netip.AddrPortFrom(v6, 1)); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("family mismatch: %v", err)
	}
	if _, err := h.Listen("udp6", netip.AddrPortFrom(v4, 1)); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("family mismatch: %v", err)
	}
	var unknown net.UnknownNetworkError
	if _, err := h.Listen("tcp", netip.AddrPort{}); !errors.As(err, &unknown) {
		t.Fatalf("tcp: %v", err)
	}
	lo := listenOn(t, h, "udp4", netip.MustParseAddrPort("127.0.0.1:9"))
	if addrOf(lo).Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatal("loopback bind")
	}
	// The dual-stack socket receives both families, IPv4 sources unmapped.
	other := n.PublicHost()
	o4 := listenOn(t, other, "udp4", netip.AddrPortFrom(other.Addrs()[0], 1))
	o6 := listenOn(t, other, "udp6", netip.AddrPortFrom(other.Addrs()[1], 1))
	send(t, o4, netip.AddrPortFrom(v4, port), "four")
	send(t, o6, netip.AddrPortFrom(v6, port), "six")
	uc := c
	if s, src := recvNow(t, uc); s != "four" || !src.Addr().Is4() {
		t.Fatalf("%q %v", s, src)
	}
	if s, src := recvNow(t, uc); s != "six" || !src.Addr().Is6() {
		t.Fatalf("%q %v", s, src)
	}
	if _, err := c4.WriteToUDPAddrPort([]byte("x"), addrOf(o6)); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("v4 socket to v6: %v", err)
	}
	if _, err := c4.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("224.0.0.1:5")); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("multicast: %v", err)
	}
	if _, err := c4.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("0.0.0.0:5")); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("unspecified: %v", err)
	}
	if _, err := c4.WriteToUDPAddrPort(make([]byte, 70000), addrOf(o4)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversize: %v", err)
	}
	if _, err := c4.WriteTo([]byte("x"), &net.TCPAddr{}); err == nil {
		t.Fatal("a bad address was accepted")
	}
	if _, err := c4.WriteTo([]byte("x"), nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil address: %v", err)
	}
	if _, err := c4.WriteTo([]byte("x"), (*net.UDPAddr)(nil)); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("typed nil address: %v", err)
	}
	if _, err := c4.WriteTo([]byte("tcp addr string"), net.TCPAddrFromAddrPort(addrOf(o4))); err != nil {
		t.Fatalf("an address parsed from its string: %v", err)
	}
	recvNow(t, o4)
	v4only := n.PublicHost(netip.IPv4Unspecified())
	if _, err := v4only.Listen("udp6", netip.AddrPort{}); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("udp6 on a v4-only host: %v", err)
	}
	if _, err := v4only.Listen("udp", netip.AddrPortFrom(netip.IPv6Unspecified(), 0)); err != nil {
		t.Fatalf("dual-stack wildcard on a v4-only host: %v", err)
	}
}

func TestEphemeralPortsUnique(t *testing.T) {
	n := newNet(t)
	h := n.PublicHost(netip.IPv4Unspecified())
	seen := map[uint16]bool{}
	for range 300 {
		p := addrOf(listen(t, h, 0)).Port()
		if seen[p] {
			t.Fatalf("ephemeral port %d reused while open", p)
		}
		seen[p] = true
	}
	if h.OpenSockets() != 300 {
		t.Fatal(h.OpenSockets())
	}
}

func TestLoopbackAndSelfDelivery(t *testing.T) {
	n := newNet(t)
	nat := n.NAT(PortRestricted())
	h := nat.Host()
	a := listen(t, h, 1000)
	b := listen(t, h, 2000)
	send(t, a, netip.MustParseAddrPort("127.0.0.1:2000"), "lo")
	send(t, a, netip.AddrPortFrom(h.Addrs()[0], 2000), "self")
	if s, src := recvNow(t, b); s != "lo" || !src.Addr().IsLoopback() {
		t.Fatalf("%q %v", s, src)
	}
	if s, _ := recvNow(t, b); s != "self" {
		t.Fatal(s)
	}
	if st := nat.Stats(); st.MappingsCreated != 0 {
		t.Fatal("local traffic must not create mappings")
	}
}

// TestLANTraffic: hosts of one LAN reach each other directly, without NAT
// state or TTL loss.
func TestLANTraffic(t *testing.T) {
	n := newNet(t)
	nat := n.NAT(SymmetricRandom())
	a, b := nat.Host(), nat.Host()
	ca, cb := listen(t, a, 1000), listen(t, b, 1000)
	_ = ca.SetHopLimit(1)
	send(t, ca, netip.AddrPortFrom(b.Addrs()[0], 1000), "x")
	if _, src := recvNow(t, cb); src != netip.AddrPortFrom(a.Addrs()[0], 1000) {
		t.Fatalf("source %v", src)
	}
	if st := nat.Stats(); st.MappingsCreated != 0 || st.Dropped.TTL != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestReadFromAndDeadlines(t *testing.T) {
	n := newNet(t)
	h := n.PublicHost()
	c := listen(t, h, 1000)
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	_, _, err := c.ReadFrom(make([]byte, 10))
	if !isTimeout(err) || time.Since(start) < 25*time.Millisecond {
		t.Fatalf("read deadline: %v after %v", err, time.Since(start))
	}
	// An expired deadline wins over queued data, as on an OS socket.
	send(t, c, netip.AddrPortFrom(h.Addrs()[0], 1000), "queued")
	_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := c.ReadFrom(make([]byte, 10)); !isTimeout(err) {
		t.Fatalf("past deadline: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	b := make([]byte, 3) // truncated, as on Linux
	nr, addr, err := c.ReadFrom(b)
	if err != nil || nr != 3 || string(b) != "que" || addr.(*net.UDPAddr).Port != 1000 {
		t.Fatalf("%d %v %v %q", nr, addr, err, b)
	}
	_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := c.WriteTo([]byte("x"), addr); !isTimeout(err) {
		t.Fatalf("write deadline: %v", err)
	}
	_ = c.SetDeadline(time.Time{})
	if _, err := c.WriteTo([]byte("x"), addr); err != nil {
		t.Fatal(err)
	}
	drain(c)
	// Moving the deadline into the past interrupts a blocked read.
	done := make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(make([]byte, 10)); done <- err }()
	time.Sleep(10 * time.Millisecond)
	_ = c.SetReadDeadline(time.Now())
	if err := <-done; !isTimeout(err) {
		t.Fatalf("interrupt: %v", err)
	}
	// Close interrupts a blocked read too.
	_ = c.SetReadDeadline(time.Time{})
	go func() { _, _, err := c.ReadFrom(make([]byte, 10)); done <- err }()
	time.Sleep(10 * time.Millisecond)
	_ = c.Close()
	if err := <-done; !isClosedErr(err) {
		t.Fatalf("close: %v", err)
	}
	for name, err := range map[string]error{
		"Close":            c.Close(),
		"SetReadDeadline":  c.SetReadDeadline(time.Now()),
		"SetHopLimit":      c.SetHopLimit(5),
		"SetReadBuffer":    c.(interface{ SetReadBuffer(int) error }).SetReadBuffer(1),
		"SetWriteBuffer":   c.(interface{ SetWriteBuffer(int) error }).SetWriteBuffer(1),
		"ReadFrom":         func() error { _, _, err := c.ReadFrom(b); return err }(),
		"WriteToAddrPort":  func() error { _, err := c.WriteToUDPAddrPort(b, addrOf(c)); return err }(),
		"ReadFromAddrPort": func() error { _, _, err := c.ReadFromUDPAddrPort(b); return err }(),
	} {
		if !isClosedErr(err) {
			t.Errorf("%s after Close: %v", name, err)
		}
	}
}

// TestExtendedDeadlineKeepsBlockedRead: moving the deadline of a blocked
// read later lets it wait past the old deadline for data. The fake clock
// passes the old deadline only after the extension, whatever the load.
func TestExtendedDeadlineKeepsBlockedRead(t *testing.T) {
	n, clk := fakeNet(t)
	h := n.PublicHost(netip.IPv4Unspecified())
	c := listen(t, h, 1000)
	_ = c.SetReadDeadline(clk.Now().Add(20 * time.Millisecond))
	done := make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(make([]byte, 10)); done <- err }()
	_ = c.SetReadDeadline(clk.Now().Add(time.Hour))
	clk.Advance(30 * time.Millisecond)
	send(t, c, netip.AddrPortFrom(h.Addrs()[0], 1000), "late")
	if err := <-done; err != nil {
		t.Fatalf("extended deadline: %v", err)
	}
}

func TestHopLimitValidation(t *testing.T) {
	n := newNet(t)
	c := listen(t, n.PublicHost(), 1)
	if c.SetHopLimit(256) == nil || c.SetHopLimit(-1) == nil {
		t.Fatal("invalid hop limits accepted")
	}
	if err := c.SetHopLimit(255); err != nil {
		t.Fatal(err)
	}
}

package nattest

import (
	"context"
	"net/netip"
	"testing"
)

func pub6(t *testing.T, n *Network, port uint16) (*Host, udp) {
	t.Helper()
	h := n.PublicHost(netip.IPv6Unspecified())
	return h, listenOn(t, h, "udp6", netip.AddrPortFrom(h.Addrs()[0], port))
}

func TestIPv6PublicDirect(t *testing.T) {
	n := newNet(t)
	ha, a := pub6(t, n, 1000)
	hb, b := pub6(t, n, 2000)
	if !netip.MustParsePrefix("2001:db8::/32").Contains(ha.Addrs()[0]) {
		t.Fatalf("public v6 %v", ha.Addrs())
	}
	if netip.PrefixFrom(ha.Addrs()[0], 64).Masked() == netip.PrefixFrom(hb.Addrs()[0], 64).Masked() {
		t.Fatal("public hosts share a /64")
	}
	send(t, a, addrOf(b), "hi")
	if _, src := recvNow(t, b); src != addrOf(a) {
		t.Fatalf("src %v", src)
	}
}

func TestIPv6NoNATFirewall(t *testing.T) {
	n := newNet(t)
	_, o := pub6(t, n, 1000)
	_, stranger := pub6(t, n, 1000)
	fw := PublicFW()
	fw.IPv6 = &IPv6Config{Mode: NoNAT, Firewall: APDF}
	nat := n.NAT(fw)
	h := nat.Host(netip.IPv6Unspecified())
	if len(h.Addrs()) != 1 || !h.Addrs()[0].Is6() || h.Addrs()[0].IsPrivate() {
		t.Fatalf("addrs %v", h.Addrs())
	}
	c := listenOn(t, h, "udp6", netip.AddrPort{})
	self := netip.AddrPortFrom(h.Addrs()[0], addrOf(c).Port())
	if m := srcAt(t, c, o); m != self { // no translation
		t.Fatalf("mapping %v, want %v", m, self)
	}
	send(t, o, self, "reply")
	recvNow(t, c)
	send(t, stranger, self, "unsolicited")
	expectNone(t, c)
	if st := nat.Stats(); st.FilteredInbound != 1 || len(nat.ExternalIPs()) != 0 {
		t.Fatalf("%+v", st)
	}
	if _, pfx, _ := h.InterfaceAddrs(); pfx[0][0].Bits() != 64 {
		t.Fatalf("prefix %v", pfx)
	}
}

// TestIPv6NoNATBehindNAT: a NoNAT device below another one shares the
// address space of the realm above.
func TestIPv6NoNATBehindNAT(t *testing.T) {
	n := newNet(t)
	_, o := pub6(t, n, 1000)
	outer := n.NAT(NATConfig{IPv6: &IPv6Config{Mode: NoNAT, Firewall: EIF}})
	inner := outer.NAT(NATConfig{IPv6: &IPv6Config{Mode: NoNAT, Firewall: EIF}})
	h := inner.Host(netip.IPv6Unspecified())
	c := listenOn(t, h, "udp6", netip.AddrPort{})
	if m := srcAt(t, c, o); m.Addr() != h.Addrs()[0] {
		t.Fatalf("mapping %v", m)
	}
	_, pfx, _ := h.InterfaceAddrs()
	if !pfx[0][0].Contains(outer.f6.site.Addr()) {
		t.Fatalf("inner prefix %v outside the outer site %v", pfx[0][0], outer.f6.site)
	}
	send(t, o, netip.AddrPortFrom(h.Addrs()[0], addrOf(c).Port()), "back")
	recvNow(t, c)
}

func TestIPv6OpenFirewallAndPublicOpenV4(t *testing.T) {
	n := newNet(t)
	_, o6 := pub6(t, n, 1000)
	_, o4 := observer(t, n, 1000)
	cfg := PublicOpen()
	cfg.IPv6 = &IPv6Config{Mode: NoNAT, Firewall: Open}
	h := n.NAT(cfg).Host()
	if len(h.Addrs()) != 2 {
		t.Fatalf("dual stack %v", h.Addrs())
	}
	c := listenOn(t, h, "udp", netip.AddrPort{})
	port := addrOf(c).Port()
	send(t, o6, netip.AddrPortFrom(h.Addrs()[1], port), "v6 unsolicited")
	send(t, o4, netip.AddrPortFrom(h.Addrs()[0], port), "v4 unsolicited")
	if drain(c) != 2 {
		t.Fatal("an open host is not reachable")
	}
}

func TestPublicFWv4(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1000)
	_, stranger := observer(t, n, 1000)
	h := n.NAT(PublicFW()).Host()
	if h.Addrs()[0].IsPrivate() {
		t.Fatalf("a PUBFW host has a private address %v", h.Addrs())
	}
	c := listen(t, h, 4000)
	self := netip.AddrPortFrom(h.Addrs()[0], 4000)
	if m := srcAt(t, c, o); m != self {
		t.Fatalf("identity mapping %v", m)
	}
	send(t, stranger, self, "x")
	expectNone(t, c)
	send(t, o, self, "y")
	recvNow(t, c)
	if a, _ := h.OutboundAddr(context.Background(), "udp4"); a != h.Addrs()[0] {
		t.Fatal("OutboundAddr")
	}
}

func TestNPTv6(t *testing.T) {
	n := newNet(t)
	_, o := pub6(t, n, 1000)
	nat := n.NAT(NATConfig{IPv6: &IPv6Config{Mode: NPTv6, Firewall: EIF}})
	h := nat.Host(netip.IPv6Unspecified())
	in := h.Addrs()[0]
	if !in.IsPrivate() {
		t.Fatalf("an NPTv6 host should have a ULA, got %v", in)
	}
	c := listenOn(t, h, "udp6", netip.AddrPortFrom(netip.Addr{}, 5555))
	m := srcAt(t, c, o)
	if m.Port() != 5555 || m.Addr().IsPrivate() {
		t.Fatalf("mapping %v", m)
	}
	ib, mb := in.As16(), m.Addr().As16()
	if [8]byte(ib[8:]) != [8]byte(mb[8:]) {
		t.Fatalf("the interface identifier changed: %v -> %v", in, m.Addr())
	}
	_, other := pub6(t, n, 2000)
	send(t, other, m, "eif")
	if s, _ := recvNow(t, c); s != "eif" {
		t.Fatal(s)
	}
	if h.publicAddr() != m.Addr() {
		t.Fatal("publicAddr through NPTv6")
	}
}

func TestNPTv6OpenFirewall(t *testing.T) {
	n := newNet(t)
	_, o := pub6(t, n, 1000)
	nat := n.NAT(NATConfig{IPv6: &IPv6Config{Mode: NPTv6, Firewall: Open}})
	h := nat.Host(netip.IPv6Unspecified())
	c := listenOn(t, h, "udp6", netip.AddrPortFrom(netip.Addr{}, 5000))
	send(t, o, netip.AddrPortFrom(h.publicAddr(), 5000), "unsolicited")
	if s, _ := recvNow(t, c); s != "unsolicited" {
		t.Fatal(s)
	}
}

func TestNAT66(t *testing.T) {
	n := newNet(t)
	_, o := pub6(t, n, 1000)
	_, o2 := pub6(t, n, 1000)
	cfg := SymmetricSeq(1)
	cfg.IPv6 = &IPv6Config{Mode: NAT66}
	nat := n.NAT(cfg)
	h := nat.Host()
	if len(h.Addrs()) != 2 || !h.Addrs()[1].IsPrivate() {
		t.Fatalf("addrs %v", h.Addrs())
	}
	c := listenOn(t, h, "udp6", netip.AddrPort{})
	m1, m2 := srcAt(t, c, o), srcAt(t, c, o2)
	if m1.Addr() != m2.Addr() || m1.Port()+1 != m2.Port() || !m1.Addr().Is6() {
		t.Fatalf("NAT66 APDM sequential: %v %v", m1, m2)
	}
	if ips := nat.ExternalIPs(); len(ips) != 2 || !ips[1].Is6() {
		t.Fatalf("external %v", ips)
	}
	// The IPv4 and IPv6 tables are independent.
	_, o4 := observer(t, n, 1000)
	if m4 := srcAt(t, listen(t, h, 7000), o4); !m4.Addr().Is4() {
		t.Fatal(m4)
	}
	if st := nat.Stats(); st.MappingsActive != 3 {
		t.Fatalf("%+v", st)
	}
	// Rebind with an IPv6 address only touches the IPv6 family.
	v4 := ext(t, nat)
	nat.Rebind([]netip.Addr{netip.MustParseAddr("2001:db8:aaaa::1")})
	if ips := nat.ExternalIPs(); len(ips) != 2 || ips[0] != v4 || ips[1] != netip.MustParseAddr("2001:db8:aaaa::1") {
		t.Fatalf("after Rebind %v", ips)
	}
	if st := nat.Stats(); st.MappingsActive != 1 {
		t.Fatalf("the IPv4 mapping should survive: %+v", st)
	}
}

func TestFamilyIsolation(t *testing.T) {
	n := newNet(t)
	h6 := n.NAT(NATConfig{IPv6: &IPv6Config{Mode: NoNAT, Firewall: APDF}}).Host(netip.IPv6Unspecified())
	h4 := n.NAT(FullCone()).Host()
	c6 := listenOn(t, h6, "udp", netip.AddrPort{})
	c4 := listen(t, h4, 1)
	if _, err := c6.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("203.0.113.9:1")); err == nil {
		t.Fatal("a v6-only host sent IPv4")
	}
	if _, err := c4.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("[2001:db8::1]:1")); err == nil {
		t.Fatal("a udp4 socket sent IPv6")
	}
	if _, err := h4.ListenPacket(context.Background(), "udp6", netip.AddrPort{}, "x"); err == nil {
		t.Fatal("udp6 on a v4-only host")
	}
	// A dual-stack socket sends either family from the matching address.
	_, o6 := pub6(t, n, 1)
	ds := listenOn(t, n.PublicHost(), "udp", netip.AddrPort{})
	send(t, ds, addrOf(o6), "v6 from dual stack")
	recvNow(t, o6)
}

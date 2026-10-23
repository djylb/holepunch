package netaddr

import (
	"net"
	"net/netip"
	"slices"
	"testing"
)

type strAddr string

func (s strAddr) Network() string { return "udp" }
func (s strAddr) String() string  { return string(s) }

func TestCanon(t *testing.T) {
	in := netip.MustParseAddrPort("[::ffff:192.0.2.1]:7")
	if got := Canon(in); got != netip.MustParseAddrPort("192.0.2.1:7") {
		t.Fatalf("Canon(%v) = %v", in, got)
	}
	z := netip.AddrPortFrom(netip.MustParseAddr("fe80::1%en0"), 9)
	if got := Canon(z); got.Addr().Zone() != "" {
		t.Fatalf("zone kept: %v", got)
	}
}

func TestFromNetAddr(t *testing.T) {
	cases := []struct {
		in   net.Addr
		want string
		ok   bool
	}{
		{nil, "", false},
		{(*net.UDPAddr)(nil), "", false},
		{&net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 5}, "192.0.2.9:5", true},
		{strAddr("[2001:db8::1]:44"), "[2001:db8::1]:44", true},
		{strAddr("not-an-address"), "", false},
	}
	for _, c := range cases {
		got, ok := FromNetAddr(c.in)
		if ok != c.ok || (ok && got.String() != c.want) {
			t.Errorf("FromNetAddr(%v) = %v %v, want %v %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// classCorpus pins every address class for one corpus: IPv4 and IPv6
// private, shared (CGN), link-local with and without a zone, loopback,
// IPv4-mapped, multicast, unspecified, broadcast, global and ULA. Columns:
// Unusable, UsableTarget (port 40000), Private, Public, IsCGN, ScopeOf.
var classCorpus = []struct {
	addr                                     string
	unusable, target, private, public, isCGN bool
	scope                                    Scope
}{
	{"0.0.0.0", true, false, false, false, false, ScopeNone},
	{"255.255.255.255", true, false, false, false, false, ScopeNone},
	{"127.0.0.1", true, false, false, false, false, ScopePrivate},
	{"10.1.2.3", false, true, true, false, false, ScopePrivate},
	{"172.16.0.1", false, true, true, false, false, ScopePrivate},
	{"192.168.1.1", false, true, true, false, false, ScopePrivate},
	{"100.64.0.1", false, true, true, false, true, ScopePrivate},
	{"100.127.255.254", false, true, true, false, true, ScopePrivate},
	{"100.128.0.1", false, true, false, true, false, ScopeGlobal},
	{"169.254.1.1", false, true, true, false, false, ScopePrivate},
	{"224.0.0.1", true, false, false, false, false, ScopeNone},
	{"203.0.113.5", false, true, false, true, false, ScopeGlobal},
	{"8.8.8.8", false, true, false, true, false, ScopeGlobal},
	{"::", true, false, false, false, false, ScopeNone},
	{"::1", true, false, false, false, false, ScopePrivate},
	{"fe80::1", true, false, true, false, false, ScopePrivate},
	{"fe80::1%eth0", true, false, true, false, false, ScopePrivate},
	{"fd00::1", false, true, true, false, false, ScopePrivate},
	{"fc00::1", false, true, true, false, false, ScopePrivate},
	{"ff02::1", true, false, false, false, false, ScopeNone},
	{"2001:db8::1", false, true, false, true, false, ScopeGlobal},
	{"2606:4700::1", false, true, false, true, false, ScopeGlobal},
	{"64:ff9b::808:808", false, true, false, true, false, ScopeGlobal},
	// IPv4-mapped addresses are classified as the IPv4 address they map.
	{"::ffff:10.0.0.1", false, true, true, false, false, ScopePrivate},
	{"::ffff:8.8.8.8", false, true, false, true, false, ScopeGlobal},
	{"::ffff:100.64.0.1", false, true, true, false, true, ScopePrivate},
	{"::ffff:169.254.1.1", false, true, true, false, false, ScopePrivate},
	{"::ffff:127.0.0.1", true, false, false, false, false, ScopePrivate},
	{"::ffff:0.0.0.0", true, false, false, false, false, ScopeNone},
	{"::ffff:255.255.255.255", true, false, false, false, false, ScopeNone},
}

func TestAddressClasses(t *testing.T) {
	for _, c := range classCorpus {
		a := netip.MustParseAddr(c.addr)
		got := []bool{Unusable(a), UsableTarget(netip.AddrPortFrom(a, 40000)), Private(a), Public(a), IsCGN(a)}
		want := []bool{c.unusable, c.target, c.private, c.public, c.isCGN}
		if !slices.Equal(got, want) || ScopeOf(a) != c.scope {
			t.Errorf("%s: %v scope %d, want %v scope %d", c.addr, got, ScopeOf(a), want, c.scope)
		}
		if UsableTarget(netip.AddrPortFrom(a, 0)) {
			t.Errorf("%s: a target without a port", c.addr)
		}
	}
	if !Unusable(netip.Addr{}) || UsableTarget(netip.AddrPort{}) || Private(netip.Addr{}) || Public(netip.Addr{}) ||
		IsCGN(netip.Addr{}) || ScopeOf(netip.Addr{}) != ScopeNone {
		t.Error("the zero address")
	}
}

func TestUDPAddr(t *testing.T) {
	ap := netip.MustParseAddrPort("198.51.100.2:9000")
	if got := UDPAddr(ap); got.String() != "198.51.100.2:9000" {
		t.Fatalf("UDPAddr = %v", got)
	}
}

// apAddr is a net.Addr with an AddrPort method, as some conns return.
type apAddr netip.AddrPort

func (a apAddr) Network() string          { return "udp" }
func (a apAddr) String() string           { return netip.AddrPort(a).String() }
func (a apAddr) AddrPort() netip.AddrPort { return netip.AddrPort(a) }

func TestAddrPortOf(t *testing.T) {
	mapped := netip.MustParseAddrPort("[::ffff:192.0.2.1]:5351")
	zoned := netip.MustParseAddrPort("[fe80::1%en0]:7")
	cases := []struct {
		in   net.Addr
		want netip.AddrPort
	}{
		{nil, netip.AddrPort{}},
		{(*net.UDPAddr)(nil), netip.AddrPort{}},
		{&net.IPAddr{IP: net.IPv4(1, 2, 3, 4)}, netip.AddrPort{}},
		{strAddr("1.2.3.4:5"), netip.MustParseAddrPort("1.2.3.4:5")},
		{net.UDPAddrFromAddrPort(mapped), mapped}, // kept as it is
		{apAddr(zoned), zoned},
	}
	for _, c := range cases {
		if got := AddrPortOf(c.in); got != c.want {
			t.Errorf("AddrPortOf(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	if got := Unmap(zoned); got != zoned {
		t.Errorf("Unmap(%v) = %v", zoned, got)
	}
	if got := Unmap(mapped); got != netip.MustParseAddrPort("192.0.2.1:5351") {
		t.Errorf("Unmap(%v) = %v", mapped, got)
	}
	if got, ok := FromNetAddr(apAddr(zoned)); !ok || got.Addr().Zone() != "" {
		t.Errorf("FromNetAddr(%v) = %v %v", zoned, got, ok)
	}
}

// TestPortDelta: the short way round the range.
func TestPortDelta(t *testing.T) {
	for _, c := range []struct {
		a, b uint16
		d    int
	}{{1000, 1001, 1}, {65535, 1024, 1}, {1024, 65535, -1}, {40000, 30000, -10000}, {2000, 60000, 58000 - PortRange}} {
		if d := PortDelta(c.a, c.b); d != c.d {
			t.Errorf("PortDelta(%d, %d) = %d, want %d", c.a, c.b, d, c.d)
		}
	}
}

package netaddr

import (
	"net"
	"net/netip"
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

func TestUnusable(t *testing.T) {
	bad := []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255", "127.0.0.1", "::1", "fe80::1"}
	for _, s := range bad {
		if !Unusable(netip.MustParseAddr(s)) {
			t.Errorf("%s should be unusable", s)
		}
	}
	if !Unusable(netip.Addr{}) {
		t.Error("invalid address should be unusable")
	}
	good := []string{"203.0.113.5", "10.1.0.2", "100.64.1.1", "2001:db8::5", "fe80::1%en0", "::ffff:198.51.100.1"}
	for _, s := range good {
		if Unusable(netip.MustParseAddr(s)) {
			t.Errorf("%s should be usable", s)
		}
	}
}

func TestPrivate(t *testing.T) {
	priv := []string{"10.0.0.1", "172.16.3.4", "192.168.1.1", "169.254.0.1", "100.64.0.1", "100.127.255.254", "fd00::1", "fe80::1", "::ffff:10.0.0.1"}
	for _, s := range priv {
		if !Private(netip.MustParseAddr(s)) {
			t.Errorf("%s should be private", s)
		}
	}
	pub := []string{"203.0.113.1", "100.128.0.1", "2001:db8::1", "8.8.8.8"}
	for _, s := range pub {
		if Private(netip.MustParseAddr(s)) {
			t.Errorf("%s should not be private", s)
		}
	}
}

func TestUDPAddr(t *testing.T) {
	ap := netip.MustParseAddrPort("198.51.100.2:9000")
	if got := UDPAddr(ap); got.String() != "198.51.100.2:9000" {
		t.Fatalf("UDPAddr = %v", got)
	}
}

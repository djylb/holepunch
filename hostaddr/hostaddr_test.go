package hostaddr

import (
	"net"
	"net/netip"
	"testing"
)

// Overlay interfaces are recognised by name, point-to-point links and the
// 100.64/10 space; Docker and VM bridges are LANs; a point-to-point uplink
// that carries the host's public address is public; loopback and down
// interfaces are not usable.
func TestClassify(t *testing.T) {
	up := net.FlagUp | net.FlagRunning
	ifaces := []net.Interface{
		{Name: "eth0", Flags: up | net.FlagBroadcast},
		{Name: "tailscale0", Flags: up | net.FlagPointToPoint},
		{Name: "utun4", Flags: up | net.FlagPointToPoint},
		{Name: "wg0", Flags: up | net.FlagPointToPoint},
		{Name: "ztks54inm2", Flags: up | net.FlagBroadcast},
		{Name: "ZeroTier One [8056c2e21c000001]", Flags: up},
		{Name: "tun0", Flags: up | net.FlagPointToPoint},
		{Name: "docker0", Flags: up | net.FlagBroadcast},
		{Name: "br-5f0e1c2d3b4a", Flags: up | net.FlagBroadcast},
		{Name: "virbr0", Flags: up | net.FlagBroadcast},
		{Name: "vmnet8", Flags: up | net.FlagBroadcast},
		{Name: "ppp0", Flags: up | net.FlagPointToPoint},
		{Name: "gif0", Flags: up | net.FlagPointToPoint},
		{Name: "lo", Flags: up | net.FlagLoopback},
		{Name: "eth1", Flags: net.FlagBroadcast},
	}
	pfx := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, p := range s {
			out = append(out, netip.MustParsePrefix(p))
		}
		return out
	}
	addrs := [][]netip.Prefix{
		pfx("192.168.1.10/24", "100.72.1.2/24"),
		pfx("100.101.102.103/32", "fd7a:115c:a1e0::1/128"),
		pfx("10.6.0.2/32"),
		pfx("10.7.0.2/24"),
		pfx("10.147.17.4/24"),
		pfx("172.25.1.1/16"),
		pfx("10.8.0.6/24"),
		pfx("172.17.0.1/16"),
		pfx("172.18.0.1/16"),
		pfx("192.168.122.1/24"),
		pfx("192.168.200.1/24"),
		pfx("198.51.100.20/32"),
		pfx("10.99.0.1/32"),
		pfx("127.0.0.1/8"),
		pfx("192.168.2.10/24"),
	}
	want := map[string]struct {
		usable bool
		kind   Kind
	}{
		"192.168.1.10":      {true, LAN},
		"100.72.1.2":        {true, Overlay}, // 100.64/10 on an Ethernet link: carrier or Tailscale space
		"100.101.102.103":   {true, Overlay},
		"fd7a:115c:a1e0::1": {true, Overlay},
		"10.6.0.2":          {true, Overlay},
		"10.7.0.2":          {true, Overlay},
		"10.147.17.4":       {true, Overlay},
		"172.25.1.1":        {true, Overlay},
		"10.8.0.6":          {true, Overlay},
		"172.17.0.1":        {true, LAN},
		"172.18.0.1":        {true, LAN},
		"192.168.122.1":     {true, LAN},
		"192.168.200.1":     {true, LAN},
		"198.51.100.20":     {true, Public},  // a PPPoE uplink's public address
		"10.99.0.1":         {true, Overlay}, // another point-to-point link, private
		"127.0.0.1":         {false, Loopback},
		"192.168.2.10":      {false, LAN},
	}
	got := Classify(ifaces, addrs)
	if len(got) != len(want) {
		t.Fatalf("%d addresses, want %d", len(got), len(want))
	}
	for _, a := range got {
		w, ok := want[a.Addr().String()]
		if !ok || a.Usable() != w.usable || a.Kind != w.kind {
			t.Errorf("%s on %s: usable %v kind %v, want %+v", a.Addr(), a.Interface, a.Usable(), a.Kind, w)
		}
	}
}

// List reads the host's interfaces; every address has a kind.
func TestList(t *testing.T) {
	list, err := List()
	if err != nil {
		t.Skip("no interface list:", err)
	}
	for _, a := range list {
		if a.Kind < Loopback || a.Kind > Overlay || !a.Addr().IsValid() || a.Kind.String() == "unknown" {
			t.Errorf("%+v", a)
		}
	}
}

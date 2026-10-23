package nat

import (
	"net/netip"
	"testing"
)

// TestEndpointPolicies pins the endpoint rules built on the netaddr
// classes for one corpus: the LAN rule of a local socket address (no
// shared space, no verified IP here), the overlay rule and the
// self-reported port-mapping rule without a verified IP.
func TestEndpointPolicies(t *testing.T) {
	for _, c := range []struct {
		addr                  string
		lan, overlay, portmap bool
	}{
		{"0.0.0.0", false, false, false},
		{"255.255.255.255", false, false, false},
		{"127.0.0.1", false, false, false},
		{"10.1.2.3", true, true, true},
		{"192.168.1.1", true, true, true},
		{"100.64.0.1", false, true, true}, // shared space: an overlay or CGNAT address, never LAN
		{"100.128.0.1", false, true, false},
		{"169.254.1.1", true, true, true},
		{"224.0.0.1", false, false, false},
		{"203.0.113.5", false, true, false},
		{"::1", false, false, false},
		{"fe80::1", false, false, false},
		{"fe80::1%eth0", false, false, false},
		{"fd00::1", true, true, true},
		{"2001:db8::1", false, true, false},
		{"::ffff:10.0.0.1", true, true, true},
		{"::ffff:100.64.0.1", false, true, true},
		{"::ffff:169.254.1.1", true, true, true},
		{"::ffff:0.0.0.0", false, false, false},
	} {
		a := netip.MustParseAddr(c.addr)
		ap := netip.AddrPortFrom(a, 40000)
		if got := lanCandidate(ap, nil); got != c.lan {
			t.Errorf("lanCandidate(%s) = %v", c.addr, got)
		}
		if got := overlayCandidate(a.Unmap()); got != c.overlay {
			t.Errorf("overlayCandidate(%s) = %v", c.addr, got)
		}
		if got := AdmitSelfReported(SourcePortMap, ap, nil); got != c.portmap {
			t.Errorf("AdmitSelfReported(portmap, %s) = %v", c.addr, got)
		}
	}
	pub := netip.MustParseAddrPort("203.0.113.5:40000")
	if !lanCandidate(pub, []netip.Addr{pub.Addr()}) || !AdmitSelfReported(SourceSTUN, pub, []netip.Addr{pub.Addr()}) ||
		AdmitSelfReported(SourceSTUN, pub, nil) {
		t.Error("verified public address")
	}
}

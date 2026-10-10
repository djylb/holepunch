package portmapper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"
)

// procRouteHex renders an address the way /proc/net/route prints it on this
// host: the network-order word as a native integer.
func procRouteHex(a string) string {
	ip := netip.MustParseAddr(a).As4()
	return fmt.Sprintf("%08X", binary.NativeEndian.Uint32(ip[:]))
}

func TestParseProcNetRoute(t *testing.T) {
	row := func(iface, dst, gw string, flags, metric int, mask string) string {
		return fmt.Sprintf("%s\t%s\t%s\t%04X\t0\t0\t%d\t%s\t0\t0\t0\n", iface, procRouteHex(dst), procRouteHex(gw), flags, metric, procRouteHex(mask))
	}
	header := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	table := header +
		row("eth0", "192.168.1.0", "0.0.0.0", 0x1, 100, "255.255.255.0") + // on-link, no gateway
		row("wg0", "0.0.0.0", "10.0.0.1", 0x3, 600, "0.0.0.0") + // default, worse metric
		row("eth0", "0.0.0.0", "192.168.1.1", 0x3, 100, "0.0.0.0") + // the default route
		row("eth1", "0.0.0.0", "172.16.0.1", 0x2, 10, "0.0.0.0") + // not up
		row("eth0", "10.1.0.0", "192.168.1.254", 0x3, 0, "255.255.0.0") + // via a gateway, not default
		"eth2\tzz\t0101A8C0\t0003\t0\t0\t1\t00000000\n" + // unparsable destination
		"garbage line\n"
	got, err := parseProcNetRoute([]byte(table))
	if err != nil || got != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("parseProcNetRoute() = %s, %v; want 192.168.1.1", got, err)
	}
	for name, in := range map[string]string{
		"empty":       "",
		"header only": header,
		"no default":  header + row("eth0", "192.168.1.0", "0.0.0.0", 0x1, 100, "255.255.255.0"),
	} {
		if _, err := parseProcNetRoute([]byte(in)); !errors.Is(err, errNoDefaultRoute) {
			t.Errorf("%s: err = %v, want errNoDefaultRoute", name, err)
		}
	}
}

type ipForwardRow struct {
	dst, mask, next string
	metric          uint32
}

// ipForwardTable builds a MIB_IPFORWARDTABLE that declares count rows.
func ipForwardTable(count int, rows ...ipForwardRow) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(count))
	for _, r := range rows {
		e := make([]byte, ipForwardRowLen)
		d, m, n := netip.MustParseAddr(r.dst).As4(), netip.MustParseAddr(r.mask).As4(), netip.MustParseAddr(r.next).As4()
		copy(e[ipForwardDestOff:], d[:])
		copy(e[ipForwardMaskOff:], m[:])
		copy(e[ipForwardNextOff:], n[:])
		binary.LittleEndian.PutUint32(e[ipForwardMetricOff:], r.metric)
		b = append(b, e...)
	}
	return b
}

func TestParseIPForwardTable(t *testing.T) {
	rows := []ipForwardRow{
		{"10.0.0.0", "255.0.0.0", "10.1.1.1", 1},
		{"0.0.0.0", "0.0.0.0", "192.168.0.1", 25},
		{"0.0.0.0", "0.0.0.0", "192.168.50.1", 35},
		{"0.0.0.0", "0.0.0.0", "0.0.0.0", 1}, // on-link default, no next hop
	}
	got, err := parseIPForwardTable(ipForwardTable(len(rows), rows...))
	if err != nil || got != netip.MustParseAddr("192.168.0.1") {
		t.Fatalf("parseIPForwardTable() = %s, %v; want 192.168.0.1", got, err)
	}
	// A count larger than the buffer is clamped to the rows present.
	if got, err := parseIPForwardTable(ipForwardTable(1000, rows[1])); err != nil || got != netip.MustParseAddr("192.168.0.1") {
		t.Fatalf("overstated count: %s, %v", got, err)
	}
	for name, b := range map[string][]byte{
		"empty":      nil,
		"no rows":    ipForwardTable(0),
		"no default": ipForwardTable(1, rows[0]),
		"truncated":  ipForwardTable(2, rows[1])[:30],
	} {
		if _, err := parseIPForwardTable(b); !errors.Is(err, errNoDefaultRoute) {
			t.Errorf("%s: err = %v, want errNoDefaultRoute", name, err)
		}
	}
}

// TestSystemGateway runs this platform's real lookup. On a host with an IPv4
// default route it must return a usable address that agrees with an
// independent source: rtnetlink on Linux, route(8) on darwin.
func TestSystemGateway(t *testing.T) {
	got, err := systemGateway()
	if errors.Is(err, errNoDefaultRoute) {
		t.Skipf("no IPv4 default route here: %v", err)
	}
	if err != nil {
		t.Fatalf("systemGateway() = %v", err)
	}
	if !got.Is4() || got.IsUnspecified() {
		t.Fatalf("systemGateway() = %s, want a usable IPv4 address", got)
	}
	t.Logf("default gateway %s", got)
	want, source, ok := referenceGateway(t)
	if !ok {
		return
	}
	if want != got {
		t.Fatalf("systemGateway() = %s, %s says %s", got, source, want)
	}
}

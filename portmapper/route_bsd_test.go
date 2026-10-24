//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package portmapper

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
	"testing"
)

func v4(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestDefaultRouteGateway(t *testing.T) {
	const upGW = syscall.RTF_UP | syscall.RTF_GATEWAY
	any4 := netip.IPv4Unspecified()
	scopedDefault := bsdRoute{flags: upGW | darwinIfScope, dst: any4, gw: v4("10.0.0.1"), hasMask: true}
	routes := []bsdRoute{
		{},
		{flags: syscall.RTF_UP, dst: any4, hasMask: true},                                                   // on-link
		{flags: upGW, dst: v4("10.1.0.0"), gw: v4("192.168.1.254"), mask: [4]byte{255, 255}, hasMask: true}, // not default
		{flags: upGW, gw: v4("192.168.1.2")},                                                                // an IPv6 destination
		{flags: upGW, dst: any4, gw: any4, hasMask: true},                                                   // no gateway address
		{flags: upGW, dst: any4, mask: [4]byte{255}, gw: v4("10.9.9.9"), hasMask: true},                     // 0.0.0.0/8
		scopedDefault,
		{flags: upGW, dst: any4, gw: v4("192.168.1.1")},                // the default route, mask omitted
		{flags: upGW, dst: any4, gw: v4("192.168.9.9"), hasMask: true}, // a later unscoped default
	}
	got, err := defaultRouteGateway(routes, true)
	if err != nil || got != v4("192.168.1.1") {
		t.Fatalf("darwin: defaultRouteGateway() = %s, %v; want the first unscoped default 192.168.1.1", got, err)
	}
	got, err = defaultRouteGateway(routes, false)
	if err != nil || got != v4("10.0.0.1") {
		t.Fatalf("other BSD: defaultRouteGateway() = %s, %v; want the first default 10.0.0.1", got, err)
	}
	// Scoped routes still count when there is nothing else.
	if got, err := defaultRouteGateway([]bsdRoute{scopedDefault}, true); err != nil || got != v4("10.0.0.1") {
		t.Fatalf("only scoped: %s, %v", got, err)
	}
	if _, err := defaultRouteGateway(routes[:6], true); !errors.Is(err, errNoDefaultRoute) {
		t.Fatalf("no default route: err = %v, want errNoDefaultRoute", err)
	}
}

// sockaddr4 is an AF_INET sockaddr of the routing table; n < 16 cuts it to
// the kernel's short form (a netmask), and family 0 leaves it unset.
func sockaddr4(a netip.Addr, n int, family byte) []byte {
	b := make([]byte, 16)
	b[0], b[1] = byte(n), family
	ip := a.As4()
	copy(b[4:], ip[:])
	return b[:n]
}

// ribMsg builds one route message: the header, then each sockaddr padded to
// the kernel's alignment, in RTAX order.
func ribMsg(typ byte, flags int, sas map[int][]byte) []byte {
	msg := make([]byte, syscall.SizeofRtMsghdr)
	var addrs uint32
	for i := range syscall.RTAX_MAX {
		sa, ok := sas[i]
		if !ok {
			continue
		}
		addrs |= 1 << i
		step := saAlign
		if len(sa) > 0 {
			step = (len(sa) + saAlign - 1) &^ (saAlign - 1)
		}
		pad := make([]byte, step)
		copy(pad, sa)
		msg = append(msg, pad...)
	}
	binary.NativeEndian.PutUint16(msg, uint16(len(msg)))
	msg[2], msg[3] = syscall.RTM_VERSION, typ
	binary.NativeEndian.PutUint32(msg[rtmFlagsOff:], uint32(flags))
	binary.NativeEndian.PutUint32(msg[rtmAddrsOff:], addrs)
	setHeaderLen(msg)
	return msg
}

// TestParseRIB: the destination, gateway and short-form netmask of route
// messages; other message types and versions are skipped, a truncated table
// ends the parse.
func TestParseRIB(t *testing.T) {
	const upGW = syscall.RTF_UP | syscall.RTF_GATEWAY
	any4 := netip.IPv4Unspecified()
	def := ribMsg(syscall.RTM_GET, upGW, map[int][]byte{
		syscall.RTAX_DST:     sockaddr4(any4, 16, syscall.AF_INET),
		syscall.RTAX_GATEWAY: sockaddr4(v4("192.168.1.1"), 16, syscall.AF_INET),
		syscall.RTAX_NETMASK: {}, // an empty mask: sa_len 0
	})
	subnet := ribMsg(syscall.RTM_GET, upGW, map[int][]byte{
		syscall.RTAX_DST:     sockaddr4(v4("10.1.0.0"), 16, syscall.AF_INET),
		syscall.RTAX_GATEWAY: sockaddr4(v4("192.168.1.254"), 16, syscall.AF_INET),
		syscall.RTAX_NETMASK: sockaddr4(v4("255.255.0.0"), 6, 0),
	})
	other := ribMsg(syscall.RTM_ADD, upGW, nil)
	old := ribMsg(syscall.RTM_GET, upGW, nil)
	old[2] = syscall.RTM_VERSION + 1
	rib := append(append(append(append([]byte{}, other...), old...), subnet...), def...)
	routes := parseRIB(append(rib, 0xff, 0xff, 0, 0)) // a length past the end
	if len(routes) != 2 {
		t.Fatalf("routes %+v", routes)
	}
	if r := routes[0]; r.dst != v4("10.1.0.0") || r.gw != v4("192.168.1.254") || !r.hasMask || r.mask != [4]byte{255, 255} {
		t.Fatalf("subnet %+v", r)
	}
	if r := routes[1]; r.flags != upGW || r.dst != any4 || r.gw != v4("192.168.1.1") || !r.hasMask || r.mask != [4]byte{} {
		t.Fatalf("default %+v", r)
	}
	if got, err := defaultRouteGateway(routes, false); err != nil || got != v4("192.168.1.1") {
		t.Fatalf("defaultRouteGateway = %s, %v", got, err)
	}
}

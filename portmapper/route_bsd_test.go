//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package portmapper

import (
	"errors"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/net/route"
)

// routeMsg builds a routing message the way route.ParseRIB returns one.
func routeMsg(flags int, dst, gw, mask route.Addr) *route.RouteMessage {
	addrs := make([]route.Addr, syscall.RTAX_MAX)
	addrs[syscall.RTAX_DST], addrs[syscall.RTAX_GATEWAY], addrs[syscall.RTAX_NETMASK] = dst, gw, mask
	return &route.RouteMessage{Flags: flags, Addrs: addrs}
}

func inet4(s string) *route.Inet4Addr { return &route.Inet4Addr{IP: netip.MustParseAddr(s).As4()} }

func TestDefaultRouteGateway(t *testing.T) {
	const upGW = syscall.RTF_UP | syscall.RTF_GATEWAY
	any4 := inet4("0.0.0.0")
	scopedDefault := routeMsg(upGW|darwinIfScope, any4, inet4("10.0.0.1"), any4)
	msgs := []route.Message{
		&route.InterfaceMessage{},
		routeMsg(syscall.RTF_UP, any4, &route.LinkAddr{Index: 1}, any4),                 // on-link
		routeMsg(upGW, inet4("10.1.0.0"), inet4("192.168.1.254"), inet4("255.255.0.0")), // not default
		routeMsg(upGW, &route.Inet6Addr{}, &route.Inet6Addr{IP: [16]byte{0xfe, 0x80, 15: 1}}, nil),
		routeMsg(upGW, any4, any4, any4), // no gateway address
		&route.RouteMessage{Flags: upGW}, // too few addresses
		scopedDefault,
		routeMsg(upGW, any4, inet4("192.168.1.1"), nil),  // the default route, mask omitted
		routeMsg(upGW, any4, inet4("192.168.9.9"), any4), // a later unscoped default
	}
	got, err := defaultRouteGateway(msgs, true)
	if err != nil || got != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("darwin: defaultRouteGateway() = %s, %v; want the first unscoped default 192.168.1.1", got, err)
	}
	got, err = defaultRouteGateway(msgs, false)
	if err != nil || got != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("other BSD: defaultRouteGateway() = %s, %v; want the first default 10.0.0.1", got, err)
	}
	// Scoped routes still count when there is nothing else.
	if got, err := defaultRouteGateway([]route.Message{scopedDefault}, true); err != nil || got != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("only scoped: %s, %v", got, err)
	}
	if _, err := defaultRouteGateway(msgs[:6], true); !errors.Is(err, errNoDefaultRoute) {
		t.Fatalf("no default route: err = %v, want errNoDefaultRoute", err)
	}
}

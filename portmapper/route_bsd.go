//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package portmapper

import (
	"net/netip"
	"runtime"
	"syscall"

	"golang.org/x/net/route"
)

// darwinIfScope is darwin's RTF_IFSCOPE. Besides the system default route,
// darwin keeps a default route scoped to each interface; on the other BSDs
// the bit means something else.
const darwinIfScope = 0x1000000

// systemGateway reads the IPv4 default route from the kernel routing table
// (sysctl NET_RT_DUMP).
func systemGateway() (netip.Addr, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return netip.Addr{}, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return netip.Addr{}, err
	}
	return defaultRouteGateway(msgs, runtime.GOOS == "darwin" || runtime.GOOS == "ios")
}

// defaultRouteGateway returns the gateway of the IPv4 default route — an up
// route through a gateway to 0.0.0.0/0 — in msgs. With darwin set, a route
// that is not scoped to one interface wins over scoped ones.
func defaultRouteGateway(msgs []route.Message, darwin bool) (netip.Addr, error) {
	var best netip.Addr
	bestScoped := true
	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok || rm.Flags&(syscall.RTF_UP|syscall.RTF_GATEWAY) != syscall.RTF_UP|syscall.RTF_GATEWAY || len(rm.Addrs) <= syscall.RTAX_NETMASK {
			continue
		}
		if dst, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr); !ok || dst.IP != [4]byte{} {
			continue
		}
		if mask, ok := rm.Addrs[syscall.RTAX_NETMASK].(*route.Inet4Addr); ok && mask.IP != [4]byte{} {
			continue
		}
		gw, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr)
		if !ok || gw.IP == [4]byte{} {
			continue
		}
		scoped := darwin && rm.Flags&darwinIfScope != 0
		if !best.IsValid() || bestScoped && !scoped {
			best, bestScoped = netip.AddrFrom4(gw.IP), scoped
		}
	}
	if !best.IsValid() {
		return netip.Addr{}, errNoDefaultRoute
	}
	return best, nil
}

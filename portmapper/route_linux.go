//go:build linux

package portmapper

import (
	"net/netip"
	"os"
)

// systemGateway reads the IPv4 default route from /proc/net/route.
func systemGateway() (netip.Addr, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	return parseProcNetRoute(b)
}

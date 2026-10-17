//go:build !linux

package hostaddr

import (
	"net"
	"net/netip"
)

// interfacesFallback has nothing to fall back to outside Linux.
func interfacesFallback() ([]net.Interface, [][]netip.Prefix, error) {
	return nil, nil, errNoFallback
}

//go:build !linux

package hostaddr

import (
	"errors"
	"net"
	"net/netip"
)

var errNoFallback = errors.New("hostaddr: no fallback interface list")

// interfacesFallback has nothing to fall back to outside Linux.
func interfacesFallback() ([]net.Interface, [][]netip.Prefix, error) {
	return nil, nil, errNoFallback
}

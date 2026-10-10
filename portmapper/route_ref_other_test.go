//go:build !(linux || darwin)

package portmapper

import (
	"net/netip"
	"testing"
)

// referenceGateway has no independent source on this platform.
func referenceGateway(*testing.T) (netip.Addr, string, bool) { return netip.Addr{}, "", false }

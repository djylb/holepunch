//go:build darwin

package portmapper

import (
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

// referenceGateway asks route(8) for the default gateway.
func referenceGateway(t *testing.T) (netip.Addr, string, bool) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		t.Logf("route(8) unavailable, comparison skipped: %v", err)
		return netip.Addr{}, "", false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "gateway:"); ok {
			if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				return a, "route(8)", true
			}
		}
	}
	t.Logf("route(8) printed no IPv4 gateway, comparison skipped:\n%s", out)
	return netip.Addr{}, "", false
}

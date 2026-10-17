//go:build !wasip1

package udpsock

import (
	"syscall"
	"testing"
)

// EHOSTDOWN (BSD, macOS: an on-link host that never answered ARP) is a
// report and means no route; on Windows package syscall invents the value.
func TestClassifyHostDown(t *testing.T) {
	err := wrapped(syscall.EHOSTDOWN)
	if !IsICMPReport(err) || !IsNoRoute(err) {
		t.Errorf("IsICMPReport(%v) = %v, IsNoRoute = %v; want true, true", err, IsICMPReport(err), IsNoRoute(err))
	}
}

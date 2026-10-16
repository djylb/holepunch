//go:build !wasip1

package udpicmp

import (
	"syscall"
	"testing"
)

// EHOSTDOWN (BSD, macOS: an on-link host that never answered ARP) is a
// report and means no route; on Windows package syscall invents the value.
func TestClassifyHostDown(t *testing.T) {
	err := wrapped(syscall.EHOSTDOWN)
	if !IsReport(err) || !IsNoRoute(err) {
		t.Errorf("IsReport(%v) = %v, IsNoRoute = %v; want true, true", err, IsReport(err), IsNoRoute(err))
	}
}

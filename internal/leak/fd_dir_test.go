//go:build darwin || linux

package leak

import (
	"net"
	"syscall"
	"testing"
)

// TestOpenFDsIsExact compares OpenFDs with probing every descriptor number:
// the descriptors used to read the listing must not be counted.
func TestOpenFDsIsExact(t *testing.T) {
	pc, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	got, err := OpenFDs()
	if err != nil {
		t.Fatal(err)
	}
	// Descriptors are allocated lowest first, so a test process stays far
	// below the probed range.
	want := 0
	var st syscall.Stat_t
	for fd := range 1 << 12 {
		if syscall.Fstat(fd, &st) == nil {
			want++
		}
	}
	if got != want {
		t.Fatalf("OpenFDs = %d, %d descriptors are open", got, want)
	}
}

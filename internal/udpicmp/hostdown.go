//go:build !windows && !wasip1

package udpicmp

import (
	"errors"
	"syscall"
)

// hostDown reports EHOSTDOWN: an on-link host that never answered ARP or
// neighbor discovery (BSD, macOS).
func hostDown(e syscall.Errno) bool { return errors.Is(e, syscall.EHOSTDOWN) }

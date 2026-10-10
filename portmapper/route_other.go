//go:build !(linux || darwin || dragonfly || freebsd || netbsd || openbsd || windows)

package portmapper

import (
	"errors"
	"net/netip"
)

// systemGateway has no implementation on this platform; Config.Gateway can
// supply the gateway instead.
func systemGateway() (netip.Addr, error) {
	return netip.Addr{}, errors.New("default gateway lookup is not supported on this platform")
}

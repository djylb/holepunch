//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package udpsock

import (
	"net/netip"
	"syscall"
)

func setIntOption(syscall.RawConn, int, int, int) error { return nil }

func dstOption(bool) (level, opt int, ok bool) { return 0, 0, false }

func parseDst([]byte) (netip.Addr, bool) { return netip.Addr{}, false }

func appendSrc(oob []byte, _ netip.Addr) []byte { return oob }

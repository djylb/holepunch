//go:build !windows

package udpicmp

import (
	"errors"
	"net"
	"syscall"
)

// DisableReports does nothing: outside Windows an unconnected UDP socket
// gets no ICMP reports.
func DisableReports(_ net.PacketConn) error { return nil }

func reportErrno(e syscall.Errno) bool {
	return errors.Is(e, syscall.ECONNREFUSED) || errors.Is(e, syscall.ECONNRESET)
}

func noRouteErrno(e syscall.Errno) bool {
	return errors.Is(e, syscall.EHOSTUNREACH) || errors.Is(e, syscall.ENETUNREACH) || hostDown(e)
}

//go:build !windows

package udpsock

import (
	"errors"
	"net"
	"syscall"
)

// DisableICMPReports does nothing: outside Windows an unconnected UDP socket
// gets no ICMP reports.
func DisableICMPReports(_ net.PacketConn) error { return nil }

// EnableICMPReports does nothing: outside Windows an unconnected UDP socket
// gets no ICMP reports to switch on.
func EnableICMPReports(_ net.PacketConn) error { return nil }

func reportErrno(e syscall.Errno) bool {
	return errors.Is(e, syscall.ECONNREFUSED) || errors.Is(e, syscall.ECONNRESET)
}

func noRouteErrno(e syscall.Errno) bool {
	return errors.Is(e, syscall.EHOSTUNREACH) || errors.Is(e, syscall.ENETUNREACH) || hostDown(e)
}

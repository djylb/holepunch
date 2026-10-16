package udpicmp

import (
	"errors"
	"syscall"
)

// IsReport reports whether err, returned by a read or a write of a UDP
// socket, is an ICMP error report: port or host unreachable, or (Windows) a
// TTL that expired. It names the fate of an earlier datagram, so the socket
// is fine and the caller keeps reading.
func IsReport(err error) bool {
	var e syscall.Errno
	return errors.As(err, &e) && (reportErrno(e) || noRouteErrno(e))
}

// IsNoRoute reports whether err says the destination cannot be reached: no
// route to it, or (EHOSTDOWN, the BSDs' and macOS's answer for an on-link
// host that does not answer ARP or neighbour discovery) no host behind it.
// The write itself failed for that destination, and only for it.
func IsNoRoute(err error) bool {
	var e syscall.Errno
	return errors.As(err, &e) && noRouteErrno(e)
}

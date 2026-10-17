package udpsock

import (
	"errors"
	"syscall"
)

// getsockoptInt and setsockoptInt take the descriptor that RawConn.Control
// hands out: a socket handle on Windows, which sets the unicast TTL through
// the same IP_TTL and IPV6_UNICAST_HOPS options as Unix.
func getsockoptInt(fd uintptr, level, opt int) (int, error) {
	return syscall.GetsockoptInt(syscall.Handle(fd), level, opt)
}

func setsockoptInt(fd uintptr, level, opt, v int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), level, opt, v)
}

// wsaEMSGSIZE is WSAEMSGSIZE (winerror.h), which package syscall does not
// name.
const wsaEMSGSIZE syscall.Errno = 10040

// IsTruncated reports whether a read failed on a datagram larger than the
// buffer: Windows fills the buffer and fails the read with WSAEMSGSIZE. The
// socket is fine; the next read gets the next datagram.
func IsTruncated(err error) bool { return errors.Is(err, wsaEMSGSIZE) }

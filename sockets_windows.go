package holepunch

import (
	"errors"
	"syscall"
)

// getsockoptInt and setsockoptInt take the descriptor that RawConn.Control
// hands out: a socket handle on Windows. Windows sets the unicast TTL through
// the same IP_TTL and IPV6_UNICAST_HOPS options as Unix, so low TTL works
// on its sockets too.
func getsockoptInt(fd uintptr, level, opt int) (int, error) {
	return syscall.GetsockoptInt(syscall.Handle(fd), level, opt)
}

func setsockoptInt(fd uintptr, level, opt, v int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), level, opt, v)
}

// wsaEMSGSIZE is WSAEMSGSIZE (winerror.h), which package syscall does not
// name.
const wsaEMSGSIZE syscall.Errno = 10040

// oversized reports whether a read failed on a datagram larger than the
// buffer: Windows fills the buffer and fails the read with WSAEMSGSIZE.
func oversized(err error) bool { return errors.Is(err, wsaEMSGSIZE) }

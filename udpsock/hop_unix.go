//go:build unix

package udpsock

import "syscall"

// getsockoptInt and setsockoptInt take the descriptor that RawConn.Control
// hands out: a file descriptor on Unix.
func getsockoptInt(fd uintptr, level, opt int) (int, error) {
	return syscall.GetsockoptInt(int(fd), level, opt)
}

func setsockoptInt(fd uintptr, level, opt, v int) error {
	return syscall.SetsockoptInt(int(fd), level, opt, v)
}

// IsTruncated reports whether a read failed on a datagram larger than the
// buffer: never on Unix, which truncates the datagram silently.
func IsTruncated(_ error) bool { return false }

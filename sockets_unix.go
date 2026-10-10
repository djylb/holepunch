//go:build unix

package holepunch

import "syscall"

// getsockoptInt and setsockoptInt take the descriptor that RawConn.Control
// hands out: a file descriptor on Unix.
func getsockoptInt(fd uintptr, level, opt int) (int, error) {
	return syscall.GetsockoptInt(int(fd), level, opt)
}

func setsockoptInt(fd uintptr, level, opt, v int) error {
	return syscall.SetsockoptInt(int(fd), level, opt, v)
}

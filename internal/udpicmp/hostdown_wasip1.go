package udpicmp

import "syscall"

// hostDown is always false: WASI has no host-down errno.
func hostDown(syscall.Errno) bool { return false }

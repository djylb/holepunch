//go:build !windows

package udpsock

import (
	"errors"
	"syscall"
)

func portUnavailableErrno(e syscall.Errno) bool {
	return errors.Is(e, syscall.EADDRINUSE) || errors.Is(e, syscall.EACCES)
}

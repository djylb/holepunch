package udpsock

import (
	"errors"
	"syscall"
)

// Winsock bind errors (winerror.h).
const (
	errWSAEACCES     syscall.Errno = 10013
	errWSAEADDRINUSE syscall.Errno = 10048
)

func portUnavailableErrno(e syscall.Errno) bool {
	return e == errWSAEADDRINUSE || e == errWSAEACCES || errors.Is(e, syscall.EADDRINUSE) || errors.Is(e, syscall.EACCES)
}

package udpsock

import (
	"errors"
	"syscall"
)

// IsPortUnavailable reports whether err, returned by a bind, says that the
// port cannot be had: another socket holds it (EADDRINUSE), or the system
// refuses it to this process (EACCES: a privileged port, or on Windows a
// port another socket holds exclusively or that the system reserves). A
// caller that pinned the port falls back to another one.
func IsPortUnavailable(err error) bool {
	var e syscall.Errno
	return errors.As(err, &e) && portUnavailableErrno(e)
}

//go:build !unix && !windows

package udpsock

import (
	"errors"
	"syscall"
)

func getHopLimit(syscall.RawConn, bool) (int, error) { return 0, errors.ErrUnsupported }

func setHopLimit(syscall.RawConn, bool, int) error { return errors.ErrUnsupported }

// IsTruncated reports whether a read failed on a datagram larger than the
// buffer: never here, where datagrams are truncated silently.
func IsTruncated(_ error) bool { return false }

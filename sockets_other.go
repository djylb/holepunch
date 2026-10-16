//go:build !unix && !windows

package holepunch

import (
	"errors"
	"syscall"
)

// errNoRawHopLimit: this platform (js, wasip1) has no setsockopt path for
// the unicast TTL; low TTL needs a conn that implements HopLimiter.
var errNoRawHopLimit = errors.New("holepunch: hop limit not settable on this platform")

func rawHopLimit(syscall.RawConn, bool) (int, error) { return 0, errNoRawHopLimit }

func setRawHopLimit(syscall.RawConn, bool, int) error { return errNoRawHopLimit }

// oversized reports whether a read failed on a datagram larger than the
// buffer: never here, where datagrams are truncated.
func oversized(_ error) bool { return false }

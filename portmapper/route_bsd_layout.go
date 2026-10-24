//go:build darwin || netbsd

package portmapper

import (
	"runtime"
	"syscall"
)

// saAlign is the alignment of the sockaddrs after the header: darwin's
// kernel aligns them to 4 bytes, NetBSD's (6 and later) to 8 on every
// architecture.
var saAlign = func() int {
	if runtime.GOOS == "netbsd" {
		return 8
	}
	return 4
}()

// rtmHeaderLen is the length of msg's header, fixed; 0 when msg is shorter.
func rtmHeaderLen(msg []byte) int {
	if len(msg) < syscall.SizeofRtMsghdr {
		return 0
	}
	return syscall.SizeofRtMsghdr
}

// rtmVersionOK reports a route message version this parser reads.
func rtmVersionOK(v byte) bool { return v == syscall.RTM_VERSION }

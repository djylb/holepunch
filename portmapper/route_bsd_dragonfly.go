package portmapper

import (
	"syscall"
	"unsafe"
)

// saAlign is the alignment of the sockaddrs after the header: a pointer's
// size.
var saAlign = int(unsafe.Sizeof(uintptr(0)))

// rtmHeaderLen is the length of msg's header, fixed; 0 when msg is shorter.
func rtmHeaderLen(msg []byte) int {
	if len(msg) < syscall.SizeofRtMsghdr {
		return 0
	}
	return syscall.SizeofRtMsghdr
}

// rtmVersionOK reports a route message version this parser reads: DragonFly
// 5.8 and later send version 7 (syscall knows 6) with the same header.
func rtmVersionOK(v byte) bool { return v == syscall.RTM_VERSION || v == 7 }

package portmapper

import (
	"syscall"
	"unsafe"
)

// saAlign is the alignment of the sockaddrs after the header: a pointer's
// size.
var saAlign = int(unsafe.Sizeof(uintptr(0)))

// rtmHeaderLen is the length of a route message's header.
func rtmHeaderLen([]byte) int { return syscall.SizeofRtMsghdr }

// rtmVersionOK reports a route message version this parser reads: DragonFly
// 5.8 and later send version 7 (syscall knows 6) with the same header.
func rtmVersionOK(v byte) bool { return v == syscall.RTM_VERSION || v == 7 }

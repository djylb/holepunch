package portmapper

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// saAlign is the alignment of the sockaddrs after the header: a pointer's
// size.
var saAlign = int(unsafe.Sizeof(uintptr(0)))

// rtmVersionOK reports a route message version this parser reads.
func rtmVersionOK(v byte) bool { return v == syscall.RTM_VERSION }

// rtmHeaderLen is the length of a route message's header, which OpenBSD
// writes in the header itself (rtm_hdrlen).
func rtmHeaderLen(msg []byte) int {
	off := int(unsafe.Offsetof(syscall.RtMsghdr{}.Hdrlen))
	if len(msg) < off+2 {
		return 0
	}
	return int(binary.NativeEndian.Uint16(msg[off:]))
}

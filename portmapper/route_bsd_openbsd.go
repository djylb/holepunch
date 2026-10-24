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

// rtmHdrlenOff is the offset of rtm_hdrlen: OpenBSD writes the header's
// length in the header itself.
var rtmHdrlenOff = int(unsafe.Offsetof(syscall.RtMsghdr{}.Hdrlen))

// rtmHeaderLen is the length msg's header gives; 0 when msg is too short
// to give it.
func rtmHeaderLen(msg []byte) int {
	if len(msg) < rtmHdrlenOff+2 {
		return 0
	}
	return int(binary.NativeEndian.Uint16(msg[rtmHdrlenOff:]))
}

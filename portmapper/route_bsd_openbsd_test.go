package portmapper

import (
	"encoding/binary"
	"syscall"
)

// setHeaderLen records a test message's header length in rtm_hdrlen.
func setHeaderLen(msg []byte) {
	binary.NativeEndian.PutUint16(msg[rtmHdrlenOff:], syscall.SizeofRtMsghdr)
}

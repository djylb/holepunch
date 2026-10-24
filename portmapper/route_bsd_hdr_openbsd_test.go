package portmapper

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// setHeaderLen records a test message's header length in rtm_hdrlen.
func setHeaderLen(msg []byte) {
	binary.NativeEndian.PutUint16(msg[unsafe.Offsetof(syscall.RtMsghdr{}.Hdrlen):], syscall.SizeofRtMsghdr)
}

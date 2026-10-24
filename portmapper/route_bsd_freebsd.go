package portmapper

import (
	"strings"
	"syscall"
	"unsafe"
)

// freebsdHeader64 is rt_msghdr's length on a 64-bit kernel (amd64, arm64).
const freebsdHeader64 = 0x98

// freebsdCompat32 reports a 32-bit program on a 64-bit kernel, whose routing
// messages have the kernel's layout: a longer header and sockaddrs aligned
// to 8 bytes.
var freebsdCompat32 = func() bool {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return false
	}
	archs, err := syscall.Sysctl("kern.supported_archs")
	return err == nil && (strings.Contains(archs, "amd64") || strings.Contains(archs, "aarch64") || strings.Contains(archs, "arm64"))
}()

// saAlign is the alignment of the sockaddrs after the header: the
// kernel's pointer size.
var saAlign = func() int {
	if freebsdCompat32 {
		return 8
	}
	return int(unsafe.Sizeof(uintptr(0)))
}()

// rtmHeaderLen is the length of msg's header, the kernel's; 0 when msg is
// shorter.
func rtmHeaderLen(msg []byte) int {
	n := syscall.SizeofRtMsghdr
	if freebsdCompat32 {
		n = freebsdHeader64
	}
	if len(msg) < n {
		return 0
	}
	return n
}

// rtmVersionOK reports a route message version this parser reads.
func rtmVersionOK(v byte) bool { return v == syscall.RTM_VERSION }

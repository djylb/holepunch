//go:build darwin || dragonfly || freebsd || netbsd

package portmapper

// setHeaderLen records a test message's header length where the kernel
// does: nowhere but in SizeofRtMsghdr.
func setHeaderLen([]byte) {}

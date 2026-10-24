//go:build darwin || dragonfly || freebsd || netbsd

package portmapper

import "syscall"

// setHeaderLen checks that a test message holds the fixed header, which
// records its length nowhere.
func setHeaderLen(msg []byte) {
	if len(msg) < syscall.SizeofRtMsghdr {
		panic("route message shorter than its header")
	}
}

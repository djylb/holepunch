//go:build unix || windows

package udpsock

import "syscall"

// hopOption is the socket option holding the unicast TTL of the family. The
// names are the same on Unix and Windows (where both values are 4).
func hopOption(v6 bool) (level, opt int) {
	if v6 {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

func getHopLimit(rc syscall.RawConn, v6 bool) (int, error) {
	level, opt := hopOption(v6)
	var v int
	var serr error
	if err := rc.Control(func(fd uintptr) { v, serr = getsockoptInt(fd, level, opt) }); err != nil {
		return 0, err
	}
	return v, serr
}

func setHopLimit(rc syscall.RawConn, v6 bool, hops int) error {
	level, opt := hopOption(v6)
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = setsockoptInt(fd, level, opt, hops) }); err != nil {
		return err
	}
	return serr
}

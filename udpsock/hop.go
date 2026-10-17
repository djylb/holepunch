package udpsock

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// HopLimit returns the unicast TTL of c's socket when it is bound to an IPv4
// address, else its IPv6 unicast hop limit; 0 means the system default,
// which some systems (macOS for IPv6) report for a socket nobody set. c must
// implement syscall.Conn, as *net.UDPConn does; otherwise, and on platforms
// without socket options (js, wasip1), the error is errors.ErrUnsupported.
// The family is that of c's local address: on a dual-stack socket bound to
// [::] it is the IPv6 hop limit, which some systems (Linux) do not apply to
// IPv4 traffic.
func HopLimit(c net.PacketConn) (int, error) {
	rc, v6, err := rawConn(c)
	if err != nil {
		return 0, err
	}
	v, err := getHopLimit(rc, v6)
	if v < 0 {
		v = 0
	}
	return v, err
}

// SetHopLimit sets the unicast TTL of c's socket when it is bound to an
// IPv4 address, else its IPv6 unicast hop limit, to hops in [1, 255]; 0
// restores the system default (not every system takes that for IPv4). What
// HopLimit returned SetHopLimit takes back, so a caller restores a socket's
// value by reading it first. The requirements on c are HopLimit's.
func SetHopLimit(c net.PacketConn, hops int) error {
	if hops < 0 || hops > 255 {
		return fmt.Errorf("udpsock: hop limit %d not in [0, 255]", hops)
	}
	rc, v6, err := rawConn(c)
	if err != nil {
		return err
	}
	if hops == 0 {
		hops = -1 // RFC 3493: the system default
	}
	return setHopLimit(rc, v6, hops)
}

// rawConn returns c's raw socket and whether its local address is IPv6.
func rawConn(c net.PacketConn) (syscall.RawConn, bool, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil, false, fmt.Errorf("udpsock: %T has no socket: %w", c, errors.ErrUnsupported)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, false, err
	}
	v6 := false
	switch a := c.LocalAddr().(type) {
	case *net.UDPAddr:
		v6 = a != nil && !a.AddrPort().Addr().Unmap().Is4()
	case nil:
	default:
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			v6 = !ap.Addr().Unmap().Is4()
		}
	}
	return rc, v6, nil
}

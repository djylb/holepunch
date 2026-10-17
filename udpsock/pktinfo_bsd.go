//go:build freebsd || openbsd

package udpsock

import (
	"net/netip"
	"syscall"
)

// FreeBSD and OpenBSD: IP_RECVDSTADDR reports the destination as a bare
// in_addr, and IP_SENDSRCADDR (the same number) names the source as one.
const (
	ipv6RecvPktinfo = syscall.IPV6_RECVPKTINFO
	ipv6Pktinfo     = syscall.IPV6_PKTINFO
)

func ipDstOption() (opt int, ok bool) { return syscall.IP_RECVDSTADDR, true }

func ipDst(typ int, data []byte) (netip.Addr, bool) {
	if typ != syscall.IP_RECVDSTADDR || len(data) < 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(data[:4])), true
}

func ipSrcMessage() (typ, size, srcOff int, ok bool) {
	return syscall.IP_RECVDSTADDR /* IP_SENDSRCADDR */, 4, 0, true
}

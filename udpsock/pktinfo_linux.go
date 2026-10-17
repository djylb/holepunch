package udpsock

import (
	"net/netip"
	"syscall"
)

// Linux: IP_PKTINFO both ways; struct in_pktinfo is ifindex, spec_dst,
// addr. The header destination is addr; a send names its source in
// spec_dst.
const (
	ipv6RecvPktinfo = syscall.IPV6_RECVPKTINFO
	ipv6Pktinfo     = syscall.IPV6_PKTINFO
)

func ipDstOption() (opt int, ok bool) { return syscall.IP_PKTINFO, true }

func ipDst(typ int, data []byte) (netip.Addr, bool) {
	if typ != syscall.IP_PKTINFO || len(data) < 12 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(data[8:12])), true
}

func ipSrcMessage() (typ, size, srcOff int, ok bool) { return syscall.IP_PKTINFO, 12, 4, true }

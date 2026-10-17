package udpsock

import (
	"net/netip"
	"syscall"
)

// macOS: IP_RECVPKTINFO to receive and IP_PKTINFO to send, with Linux's
// struct in_pktinfo; IPv6 per RFC 3542, whose numbers package syscall does
// not name here.
const (
	ipv6RecvPktinfo = 61
	ipv6Pktinfo     = 46
)

func ipDstOption() (opt int, ok bool) { return syscall.IP_RECVPKTINFO, true }

func ipDst(typ int, data []byte) (netip.Addr, bool) {
	if typ != syscall.IP_PKTINFO || len(data) < 12 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(data[8:12])), true
}

func ipSrcMessage() (typ, size, srcOff int, ok bool) { return syscall.IP_PKTINFO, 12, 4, true }

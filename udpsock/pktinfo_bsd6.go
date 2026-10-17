//go:build netbsd || dragonfly

package udpsock

import (
	"net/netip"
	"syscall"
)

// NetBSD and DragonFly: IPv6 only; an IPv4 socket keeps the system's source.
const (
	ipv6RecvPktinfo = syscall.IPV6_RECVPKTINFO
	ipv6Pktinfo     = syscall.IPV6_PKTINFO
)

func ipDstOption() (opt int, ok bool) { return 0, false }

func ipDst(int, []byte) (netip.Addr, bool) { return netip.Addr{}, false }

func ipSrcMessage() (typ, size, srcOff int, ok bool) { return 0, 0, 0, false }

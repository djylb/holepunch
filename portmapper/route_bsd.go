//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package portmapper

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"
)

// darwinIfScope is darwin's RTF_IFSCOPE. Besides the system default route,
// darwin keeps a default route scoped to each interface; on the other BSDs
// the bit means something else.
const darwinIfScope = 0x1000000

// Offsets of the routing message header (syscall.RtMsghdr, the kernel's
// rt_msghdr): the fields are read from the bytes, never through a pointer
// conversion of them, which need not be aligned. The header's length
// (rtmHeaderLen), the message version and the alignment of the sockaddrs
// after the header (saAlign) are each system's (route_bsd_*.go).
var (
	rtmFlagsOff = int(unsafe.Offsetof(syscall.RtMsghdr{}.Flags))
	rtmAddrsOff = int(unsafe.Offsetof(syscall.RtMsghdr{}.Addrs))
)

// bsdRoute is one route of the kernel table: its flags, its destination
// and gateway when they are IPv4 addresses (else invalid), and its netmask's
// IPv4 bytes, zero when the mask is absent or empty.
type bsdRoute struct {
	flags   int
	dst, gw netip.Addr
	mask    [4]byte
	hasMask bool
}

// systemGateway reads the IPv4 default route from the kernel routing table
// (sysctl NET_RT_DUMP).
func systemGateway() (netip.Addr, error) {
	// RouteRIB is deprecated in favour of golang.org/x/net/route, which the
	// module does not depend on; it is frozen, and the standard library's
	// only sysctl by MIB.
	//goland:noinspection GoDeprecation
	rib, err := syscall.RouteRIB(syscall.NET_RT_DUMP, syscall.AF_INET)
	if err != nil {
		return netip.Addr{}, err
	}
	return defaultRouteGateway(parseRIB(rib), runtime.GOOS == "darwin" || runtime.GOOS == "ios")
}

// parseRIB parses the route messages of a NET_RT_DUMP table; a message of
// another version or too short for its header is skipped, and the table
// ends at the first message whose length does not fit.
func parseRIB(b []byte) []bsdRoute {
	var out []bsdRoute
	for len(b) >= 4 {
		n := int(binary.NativeEndian.Uint16(b))
		if n < 4 || n > len(b) {
			break
		}
		msg := b[:n]
		b = b[n:]
		hdr := rtmHeaderLen(msg)
		if !rtmVersionOK(msg[2]) || msg[3] != syscall.RTM_GET || hdr < rtmAddrsOff+4 || hdr > len(msg) {
			continue
		}
		rt := bsdRoute{flags: int(int32(binary.NativeEndian.Uint32(msg[rtmFlagsOff:])))}
		addrs := binary.NativeEndian.Uint32(msg[rtmAddrsOff:])
		sas := msg[hdr:]
		for i := 0; i < syscall.RTAX_MAX && len(sas) > 0; i++ {
			if addrs&(1<<i) == 0 {
				continue
			}
			l := int(sas[0])
			sa := sas[:min(max(l, 1), len(sas))]
			switch i {
			case syscall.RTAX_DST:
				rt.dst = inet4Of(sa)
			case syscall.RTAX_GATEWAY:
				rt.gw = inet4Of(sa)
			case syscall.RTAX_NETMASK:
				// A mask is in the kernel's short form: its length may
				// stop before the address ends, and its family is unset.
				rt.hasMask = true
				if len(sa) > 4 {
					copy(rt.mask[:], sa[4:])
				}
			}
			step := saAlign
			if l > 0 {
				step = (l + saAlign - 1) &^ (saAlign - 1)
			}
			if step > len(sas) {
				break
			}
			sas = sas[step:]
		}
		out = append(out, rt)
	}
	return out
}

// inet4Of returns the address of an AF_INET sockaddr (length, family, port,
// address); invalid for any other.
func inet4Of(sa []byte) netip.Addr {
	if len(sa) < 8 || sa[1] != syscall.AF_INET {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(sa[4:8]))
}

// defaultRouteGateway returns the gateway of the IPv4 default route — an up
// route through a gateway to 0.0.0.0/0 — in routes. With darwin set, a route
// that is not scoped to one interface wins over scoped ones.
func defaultRouteGateway(routes []bsdRoute, darwin bool) (netip.Addr, error) {
	var best netip.Addr
	bestScoped := true
	for _, rt := range routes {
		if rt.flags&(syscall.RTF_UP|syscall.RTF_GATEWAY) != syscall.RTF_UP|syscall.RTF_GATEWAY ||
			rt.dst != netip.IPv4Unspecified() || rt.hasMask && rt.mask != [4]byte{} || !rt.gw.IsValid() || rt.gw.IsUnspecified() {
			continue
		}
		scoped := darwin && rt.flags&darwinIfScope != 0
		if !best.IsValid() || bestScoped && !scoped {
			best, bestScoped = rt.gw, scoped
		}
	}
	if !best.IsValid() {
		return netip.Addr{}, errNoDefaultRoute
	}
	return best, nil
}

package udpsock

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"syscall"
	"unsafe"
)

// Windows: IP_PKTINFO and IPV6_PKTINFO (both 19) switch the reports on and
// name the control messages, whose header is WSACMSGHDR — a SIZE_T length,
// then level and type — with data aligned to SIZE_T. IN_PKTINFO is the
// address then the interface index; IN6_PKTINFO likewise.
const (
	wsaIPPktinfo   = 19
	wsaIPv6Pktinfo = 19
	ipprotoIP      = 0
	ipprotoIPv6    = 41
	wsaAlign       = int(unsafe.Sizeof(uintptr(0)))
	wsaHeader      = (int(unsafe.Sizeof(uintptr(0))) + 8 + wsaAlign - 1) &^ (wsaAlign - 1)
)

func wsaSpace(n int) int { return wsaHeader + (n+wsaAlign-1)&^(wsaAlign-1) }

func setIntOption(rc syscall.RawConn, level, opt, v int) error {
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(syscall.Handle(fd), level, opt, v) }); err != nil {
		return err
	}
	return serr
}

func dstOption(v6 bool) (level, opt int, ok bool) {
	if v6 {
		return ipprotoIPv6, wsaIPv6Pktinfo, true
	}
	return ipprotoIP, wsaIPPktinfo, true
}

// cmsgLen reads a WSACMSGHDR's SIZE_T length.
func cmsgLen(b []byte) int {
	if wsaAlign == 8 {
		return int(binary.LittleEndian.Uint64(b))
	}
	return int(binary.LittleEndian.Uint32(b))
}

func parseDst(oob []byte) (netip.Addr, bool) {
	for len(oob) >= wsaHeader {
		l := cmsgLen(oob)
		if l < wsaHeader || l > len(oob) {
			return netip.Addr{}, false
		}
		level := int32(binary.LittleEndian.Uint32(oob[wsaAlign:]))
		typ := int32(binary.LittleEndian.Uint32(oob[wsaAlign+4:]))
		data := oob[wsaHeader:l]
		switch {
		case level == ipprotoIP && typ == wsaIPPktinfo && len(data) >= 4:
			return netip.AddrFrom4([4]byte(data[:4])), true
		case level == ipprotoIPv6 && typ == wsaIPv6Pktinfo && len(data) >= 16:
			return netip.AddrFrom16([16]byte(data[:16])).Unmap(), true
		}
		next := wsaSpace(l - wsaHeader)
		if next > len(oob) {
			break
		}
		oob = oob[next:]
	}
	return netip.Addr{}, false
}

func appendSrc(oob []byte, src netip.Addr) []byte {
	level, typ, n := ipprotoIP, wsaIPPktinfo, 8 // IN_PKTINFO
	if src.Is6() {
		level, typ, n = ipprotoIPv6, wsaIPv6Pktinfo, 20 // IN6_PKTINFO
	}
	off := len(oob)
	space := wsaSpace(n)
	oob = slices.Grow(oob, space)[:off+space] // no allocation with room in oob
	clear(oob[off:])
	m := oob[off:]
	if wsaAlign == 8 {
		binary.LittleEndian.PutUint64(m, uint64(wsaHeader+n))
	} else {
		binary.LittleEndian.PutUint32(m, uint32(wsaHeader+n))
	}
	binary.LittleEndian.PutUint32(m[wsaAlign:], uint32(level))
	binary.LittleEndian.PutUint32(m[wsaAlign+4:], uint32(typ))
	if src.Is6() {
		a := src.As16()
		copy(m[wsaHeader:], a[:])
	} else {
		a := src.As4()
		copy(m[wsaHeader:], a[:])
	}
	return oob
}

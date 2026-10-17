//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package udpsock

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"syscall"
)

func setIntOption(rc syscall.RawConn, level, opt, v int) error {
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), level, opt, v) }); err != nil {
		return err
	}
	return serr
}

func dstOption(v6 bool) (level, opt int, ok bool) {
	if v6 {
		return syscall.IPPROTO_IPV6, ipv6RecvPktinfo, true
	}
	opt, ok = ipDstOption()
	return syscall.IPPROTO_IP, opt, ok
}

// The header of a control message, read and written at byte offsets so
// that oob needs no alignment: Len is as wide as a pointer on Linux and
// 32 bits on the BSDs, then Level and Type.
const (
	cmsgLenSize = syscall.SizeofCmsghdr - 8
	cmsgLevel   = cmsgLenSize
	cmsgType    = cmsgLenSize + 4
)

// cmsgLen and putCmsgLen read and write Len, as wide as the platform's.
var cmsgLen, putCmsgLen = cmsgLenFuncs(cmsgLenSize)

func cmsgLenFuncs(size int) (func([]byte) int, func([]byte, int)) {
	if size == 8 {
		return func(b []byte) int { return int(binary.NativeEndian.Uint64(b)) },
			func(b []byte, n int) { binary.NativeEndian.PutUint64(b, uint64(n)) }
	}
	return func(b []byte) int { return int(binary.NativeEndian.Uint32(b)) },
		func(b []byte, n int) { binary.NativeEndian.PutUint32(b, uint32(n)) }
}

func putCmsgHeader(b []byte, length, level, typ int) {
	putCmsgLen(b, length)
	binary.NativeEndian.PutUint32(b[cmsgLevel:], uint32(level))
	binary.NativeEndian.PutUint32(b[cmsgType:], uint32(typ))
}

// parseDst walks the control messages of oob without allocating.
func parseDst(oob []byte) (netip.Addr, bool) {
	hdr := syscall.CmsgLen(0)
	for len(oob) >= hdr {
		l := cmsgLen(oob)
		if l < hdr || l > len(oob) {
			return netip.Addr{}, false
		}
		level := int32(binary.NativeEndian.Uint32(oob[cmsgLevel:]))
		typ := int(int32(binary.NativeEndian.Uint32(oob[cmsgType:])))
		data := oob[hdr:l]
		switch {
		case level == syscall.IPPROTO_IPV6 && typ == ipv6Pktinfo && len(data) >= 16:
			return netip.AddrFrom16([16]byte(data[:16])).Unmap(), true
		case level == syscall.IPPROTO_IP:
			if a, ok := ipDst(typ, data); ok {
				return a, true
			}
		}
		next := syscall.CmsgSpace(l - hdr)
		if next > len(oob) {
			break
		}
		oob = oob[next:]
	}
	return netip.Addr{}, false
}

// appendSrc appends one control message naming src.
func appendSrc(oob []byte, src netip.Addr) []byte {
	level, typ, n, srcOff := syscall.IPPROTO_IPV6, ipv6Pktinfo, 20, 0 // struct in6_pktinfo
	if src.Is4() {
		var ok bool
		if typ, n, srcOff, ok = ipSrcMessage(); !ok {
			return oob
		}
		level = syscall.IPPROTO_IP
	}
	off := len(oob)
	space := syscall.CmsgSpace(n)
	oob = slices.Grow(oob, space)[:off+space] // no allocation with room in oob
	clear(oob[off:])
	putCmsgHeader(oob[off:], syscall.CmsgLen(n), level, typ)
	data := oob[off+syscall.CmsgLen(0) : off+syscall.CmsgLen(n)]
	if src.Is6() {
		a := src.As16()
		copy(data, a[:])
	} else {
		a := src.As4()
		copy(data[srcOff:], a[:])
	}
	return oob
}

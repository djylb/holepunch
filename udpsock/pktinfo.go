package udpsock

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// ControlSize is a control buffer large enough for DstAddr and for the
// control message AppendSrcAddr appends, on every platform.
const ControlSize = 64

// A socket bound to the wildcard address receives datagrams sent to any of
// the host's addresses, but the system sends its replies from the address it
// routes by, which may not be the one the client sent to — and a NAT or
// firewall that only lets in the probed address's replies drops them. The
// packet-information options fix that: the destination of every datagram
// read is reported, and a datagram written can name its source.
//
//	_ = udpsock.EnableDstAddr(conn)
//	oob := make([]byte, udpsock.ControlSize)
//	n, oobn, _, from, err := conn.ReadMsgUDPAddrPort(buf, oob)
//	dst, _ := udpsock.DstAddr(oob[:oobn])
//	_, _, err = conn.WriteMsgUDPAddrPort(reply, udpsock.AppendSrcAddr(nil, dst), from)
//
// Linux, macOS, FreeBSD, OpenBSD and Windows support both families; NetBSD
// and DragonFly only IPv6. A socket serves one family: "udp4", or "udp6",
// which package net makes IPv6-only. On a dual-stack socket ("udp" on the
// wildcard address) IPv4 datagrams are reported and sourced only on some
// systems.

// EnableDstAddr makes c report the destination address of every datagram it
// reads, in the control data of ReadMsgUDPAddrPort (DstAddr), for the family
// of c's local address. c must implement syscall.Conn, as *net.UDPConn
// does; otherwise, and where the platform has no such option, the error is
// errors.ErrUnsupported.
func EnableDstAddr(c net.PacketConn) error {
	rc, v6, err := rawConn(c)
	if err != nil {
		return err
	}
	level, opt, ok := dstOption(v6)
	if !ok {
		return fmt.Errorf("udpsock: destination address: %w", errors.ErrUnsupported)
	}
	return setIntOption(rc, level, opt, 1)
}

// DstAddr returns the destination address reported in oob, the control data
// of a datagram read from a socket with EnableDstAddr; ok is false when oob
// carries none.
func DstAddr(oob []byte) (dst netip.Addr, ok bool) { return parseDst(oob) }

// AppendSrcAddr appends to oob the control message that makes
// WriteMsgUDPAddrPort send from src, an address of this host of the
// socket's family, and returns the extended slice. Where the platform has
// no such message it returns oob unchanged, and the system picks the source.
func AppendSrcAddr(oob []byte, src netip.Addr) []byte {
	if !src.IsValid() {
		return oob
	}
	return appendSrc(oob, src.Unmap())
}

package stun

import (
	"errors"
	"net"
	"net/netip"
)

// Serve answers the Binding Requests that arrive on conn, each with the
// address and port it came from, until conn is closed, and returns the read
// error then: net.ErrClosed. Other datagrams are ignored, and so are write
// errors and the read errors a socket recovers from — ICMP reports of
// earlier replies (Windows), a deadline the caller set — unless they repeat
// many times in a row. It is a complete STUN server for NAT discovery,
// without authentication or the RFC 5780 behaviour-discovery attributes.
func Serve(conn net.PacketConn) error {
	buf := make([]byte, maxMessage)
	var out []byte
	soft := 0
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || soft >= maxSoftErrors {
				return err
			}
			soft++
			continue
		}
		soft = 0
		id, ok := ParseBindingRequest(buf[:n])
		if !ok {
			continue
		}
		src, ok := addrPort(from)
		if !ok {
			continue
		}
		out = AppendBindingResponse(out[:0], id, src)
		_, _ = conn.WriteTo(out, from)
	}
}

// addrPort converts a datagram's source address.
func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch a := a.(type) {
	case *net.UDPAddr:
		if a == nil {
			return netip.AddrPort{}, false
		}
		ap := a.AddrPort()
		return netip.AddrPortFrom(ap.Addr().WithZone(""), ap.Port()), ap.IsValid()
	case nil:
		return netip.AddrPort{}, false
	default:
		ap, err := netip.ParseAddrPort(a.String())
		return ap, err == nil
	}
}

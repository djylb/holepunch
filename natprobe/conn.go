package natprobe

import (
	"net"
	"net/netip"
)

// packetConn is the allocation-free datagram interface of *net.UDPConn.
// Injected conns without it are adapted, at one allocation per packet.
type packetConn interface {
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
}

func adaptConn(pc net.PacketConn) packetConn {
	if c, ok := pc.(packetConn); ok {
		return c
	}
	return genericConn{pc}
}

// genericConn adapts a net.PacketConn to packetConn.
type genericConn struct{ net.PacketConn }

// ReadFromUDPAddrPort reads through ReadFrom, allocating the net.Addr.
func (c genericConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, a, err := c.ReadFrom(b)
	return n, addrPortOf(a), err
}

// WriteToUDPAddrPort writes through WriteTo, allocating the net.Addr.
func (c genericConn) WriteToUDPAddrPort(b []byte, to netip.AddrPort) (int, error) {
	return c.WriteTo(b, net.UDPAddrFromAddrPort(to))
}

// addrPortOf converts a net.Addr to an AddrPort, zero when it is not an
// ip:port.
func addrPortOf(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case nil:
		return netip.AddrPort{}
	case *net.UDPAddr:
		if v == nil {
			return netip.AddrPort{}
		}
		return v.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

// localAddrPort returns pc's local address, unmapped (zero when unknown).
func localAddrPort(pc net.PacketConn) netip.AddrPort {
	a := addrPortOf(pc.LocalAddr())
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

package natprobe

import (
	"net"
	"net/netip"

	"github.com/djylb/holepunch/internal/netaddr"
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
	return n, netaddr.AddrPortOf(a), err
}

// WriteToUDPAddrPort writes through WriteTo, allocating the net.Addr.
func (c genericConn) WriteToUDPAddrPort(b []byte, to netip.AddrPort) (int, error) {
	return c.WriteTo(b, net.UDPAddrFromAddrPort(to))
}

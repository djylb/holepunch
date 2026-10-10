package netaddr

import (
	"net"
	"net/netip"
)

// Canon returns ap in the form the runtime compares addresses in: an
// IPv4-mapped IPv6 address becomes plain IPv4 and the zone is dropped, so that
// the same peer seen through a dual-stack read and a v4 read is one key.
func Canon(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

// FromNetAddr converts the source address returned by ReadFrom into its
// canonical netip form. It handles *net.UDPAddr without allocating and falls
// back to parsing String for other implementations of net.Addr. ok is false
// when a has no usable address.
func FromNetAddr(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case nil:
		return netip.AddrPort{}, false
	case *net.UDPAddr:
		if v == nil {
			return netip.AddrPort{}, false
		}
		ap := v.AddrPort()
		return Canon(ap), ap.IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return Canon(ap), ap.IsValid()
}

// Unusable reports whether a can never be a destination of an initiated
// packet: invalid, unspecified, multicast, the IPv4 limited broadcast,
// loopback, or IPv6 link-local without a zone. Local
// addresses of this host are checked separately, against InterfaceAddrs.
func Unusable(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	zoneless := a.Is6() && !a.Is4In6() && a.Zone() == ""
	a = a.Unmap()
	switch {
	case a.IsUnspecified(), a.IsMulticast(), a.IsLoopback():
		return true
	case a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return true
	case a.Is6() && a.IsLinkLocalUnicast() && zoneless:
		return true
	}
	return false
}

// Private reports whether a is a LAN-scope address: RFC 1918, IPv4 link-local,
// IPv6 ULA and link-local, or the RFC 6598 shared space that carrier-grade
// NATs use inside. Such an address is a target only of a peer on the same
// LAN (pair.same_lan), as an upstream-LAN port mapping of a peer behind the
// same public IP, or when a verified observation itself is private.
func Private(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLinkLocalUnicast() || cgn.Contains(a)
}

// cgn is RFC 6598's shared address space; a constant, never written.
var cgn = netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10)

// UDPAddr returns ap as the *net.UDPAddr WriteTo takes on connections that do
// not offer WriteToUDPAddrPort.
func UDPAddr(ap netip.AddrPort) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(ap)
}

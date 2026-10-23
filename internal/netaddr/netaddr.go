package netaddr

import (
	"net"
	"net/netip"
)

// Unmap returns ap with an IPv4-mapped address unmapped and the zone kept:
// the form in which observation tables store and compare addresses.
func Unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// Canon returns ap in the form the runtime compares addresses in: an
// IPv4-mapped IPv6 address becomes plain IPv4 and the zone is dropped, so that
// the same peer seen through a dual-stack read and a v4 read is one key.
func Canon(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

// AddrPortOf converts a net.Addr to a netip.AddrPort as it is, mapped
// address and zone included; the zero value when a has no address with a
// port. It reads *net.UDPAddr and every implementation with an AddrPort
// method without allocating and falls back to parsing String for the
// others.
func AddrPortOf(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case nil:
		return netip.AddrPort{}
	case *net.UDPAddr:
		return v.AddrPort() // the zero value for a nil *net.UDPAddr
	case interface{ AddrPort() netip.AddrPort }:
		return v.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

// FromNetAddr converts a source address returned by ReadFrom, or any other
// net.Addr, into its canonical netip form: Canon of AddrPortOf. ok is false
// when a has no usable address.
func FromNetAddr(a net.Addr) (netip.AddrPort, bool) {
	ap := AddrPortOf(a)
	return Canon(ap), ap.IsValid()
}

// UDPAddr returns ap as the *net.UDPAddr WriteTo takes on connections that do
// not offer WriteToUDPAddrPort.
func UDPAddr(ap netip.AddrPort) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(ap)
}

// ---- address classes ----
//
// Every predicate below unmaps an IPv4-mapped address first, so that the
// same address is classified alike however it was read. Wire fields never
// carry a mapped address (protocol.Family.Matches refuses it).

// Unusable reports whether a can never be the destination of a packet the
// library initiates: invalid, unspecified, multicast, the IPv4 limited
// broadcast, loopback, or IPv6 link-local. A link-local IPv6 address is
// refused with or without a zone: the runtime compares and sends to
// addresses in the Canon form, which drops the zone, and a zone of the peer
// would mean nothing on this host anyway. Local addresses of this host are
// checked separately, against its interface addresses.
func Unusable(a netip.Addr) bool {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsMulticast(), a.IsLoopback():
		return true
	case a == broadcast4:
		return true
	case a.Is6() && a.IsLinkLocalUnicast():
		return true
	}
	return false
}

// UsableTarget reports whether ap can be the destination of an initiated
// packet at all: a port and an address that is not Unusable. Which targets
// a side may actually aim at is admission's call.
func UsableTarget(ap netip.AddrPort) bool {
	return ap.Port() != 0 && !Unusable(ap.Addr())
}

// Private reports whether a is a LAN-scope address: RFC 1918, IPv4 and IPv6
// link-local, IPv6 ULA, or the RFC 6598 shared space that carrier-grade
// NATs use inside (IsCGN). Such an address is a target only of a peer on the
// same LAN (pair.same_lan), as an upstream-LAN port mapping of a peer behind
// the same public IP, or when a verified observation itself is private.
// Loopback is not Private: it is ScopePrivate, but never a target.
func Private(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLinkLocalUnicast() || IsCGN(a)
}

// Public reports whether a is a global unicast address outside every LAN
// scope: ScopeOf(a) == ScopeGlobal. Only such an address of a peer is aimed
// at without a server's verification, in a family the server could not
// verify.
func Public(a netip.Addr) bool { return ScopeOf(a) == ScopeGlobal }

// IsCGN reports whether a is in the RFC 6598 shared address space
// 100.64.0.0/10 that carrier-grade NATs, and overlays such as Tailscale,
// number their hosts in.
func IsCGN(a netip.Addr) bool {
	return cgn.Contains(a.Unmap())
}

// Constants of the address classes, never written.
var (
	cgn        = netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10)
	broadcast4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

// Scope is the reachability scope of an address. Cross-address comparisons
// (mapping, MultiExit) only use observations of one scope: an observer on a
// private address, such as a bridge-local IP, only proves LAN reachability.
type Scope uint8

// Scopes.
const (
	// ScopeNone is the scope of an invalid, unspecified or multicast
	// address, and of the IPv4 limited broadcast.
	ScopeNone Scope = iota
	// ScopeGlobal is a global unicast address that is not Private.
	ScopeGlobal
	// ScopePrivate covers the Private addresses and loopback.
	ScopePrivate
)

// ScopeOf returns the scope of a.
func ScopeOf(a netip.Addr) Scope {
	a = a.Unmap()
	switch {
	case !a.IsValid() || a.IsUnspecified() || a.IsMulticast():
		return ScopeNone
	case a.IsLoopback() || Private(a):
		return ScopePrivate
	case a.IsGlobalUnicast():
		return ScopeGlobal
	}
	return ScopeNone
}

// ---- ports ----

// Ports a sequential allocator hands out: it wraps around in
// [MinUserPort, 65535], PortRange ports wide.
const (
	MinUserPort = 1024
	PortRange   = 65536 - MinUserPort
)

// PortDelta is b − a the short way round the allocator's wrapping range: a
// downward allocator that wrapped from 1024 to 65535 moved one step, not
// 64511.
func PortDelta(a, b uint16) int {
	d := int(b) - int(a)
	switch {
	case d > PortRange/2:
		d -= PortRange
	case d < -PortRange/2:
		d += PortRange
	}
	return d
}

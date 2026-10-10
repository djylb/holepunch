package nat

import (
	"net/netip"

	"github.com/djylb/holepunch/protocol"
)

// Scope is the reachability scope of an address.
// Cross-address comparisons (mapping, MultiExit) only use observations of
// one scope: an observer on a private address, such as a bridge-local IP,
// only proves LAN reachability.
type Scope uint8

// Scopes.
const (
	// ScopeNone is the scope of an invalid, unspecified or multicast address.
	ScopeNone Scope = iota
	// ScopeGlobal is a global unicast address that is not private.
	ScopeGlobal
	// ScopePrivate covers RFC 1918, 100.64.0.0/10 (shared CGN space), ULA,
	// link-local and loopback addresses.
	ScopePrivate
)

// ScopeOf returns the scope of a; an IPv4-mapped address is unmapped first.
func ScopeOf(a netip.Addr) Scope {
	a = a.Unmap()
	switch {
	case !a.IsValid() || a.IsUnspecified() || a.IsMulticast():
		return ScopeNone
	case a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsPrivate() || IsCGN(a):
		return ScopePrivate
	case a.IsGlobalUnicast():
		return ScopeGlobal
	}
	return ScopeNone
}

// IsCGN reports whether a is in the RFC 6598 shared address space
// 100.64.0.0/10 that carrier-grade NATs use inside.
func IsCGN(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() {
		return false
	}
	b := a.As4()
	return b[0] == 100 && b[1]&0xC0 == 64
}

// unmap returns a with an IPv4-mapped address unmapped, the form in which the
// table stores and compares addresses.
func unmap(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

// usableIn reports whether a can be an observed value of family f: a unicast
// address of the family with a port. Anything else would make the report
// fail protocol validation, so tables never hold it.
func usableIn(f protocol.Family, a netip.AddrPort) bool {
	ip := a.Addr()
	return a.Port() != 0 && f.Matches(ip) && !ip.IsUnspecified() && !ip.IsMulticast()
}

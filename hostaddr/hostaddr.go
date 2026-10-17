// Package hostaddr lists the addresses of this host's network interfaces
// and tells what kind of network each one is on: loopback, a LAN, the public
// Internet, or an overlay — a tunnel or mesh VPN such as Tailscale,
// WireGuard or ZeroTier.
//
// The kind matters to a peer-to-peer program: a LAN address reaches peers on
// the same network directly, a public one is the host itself on the
// Internet, and an overlay address reaches peers only through the overlay,
// which may relay. Overlays are recognised by interface name, by
// point-to-point links that carry a private address, and by the shared
// address space 100.64.0.0/10 that Tailscale and carrier-grade NATs number
// from. Docker and virtual-machine bridges are LANs: traffic over them is
// direct, between a host and its containers or machines.
//
// The package depends on the standard library only, starts no goroutine and
// keeps no state.
package hostaddr

import (
	"errors"
	"net"
	"net/netip"
	"strings"
)

// Kind is the kind of network an address is on.
type Kind uint8

// Kinds.
const (
	Loopback Kind = iota + 1 // on a loopback interface, or a loopback address
	LAN                      // a private or link-local address (RFC 1918, ULA, link-local) on a local network
	Public                   // a global address on a local network: the host is on the Internet without NAT
	Overlay                  // on a tunnel or overlay interface, or in 100.64.0.0/10
)

// String returns the kind's name: loopback, lan, public or overlay.
func (k Kind) String() string {
	switch k {
	case Loopback:
		return "loopback"
	case LAN:
		return "lan"
	case Public:
		return "public"
	case Overlay:
		return "overlay"
	}
	return "unknown"
}

// Addr is one address of an interface.
type Addr struct {
	Prefix    netip.Prefix // the address with its prefix length; IPv4-mapped addresses unmapped, no zone
	Interface string       // the interface's name, which is the zone of a link-local IPv6 address
	Up        bool         // the interface is up
	Kind      Kind
}

// Addr returns the address.
func (a Addr) Addr() netip.Addr { return a.Prefix.Addr() }

// Usable reports whether a is a live address of a real network: on an
// interface that is up, and not loopback.
func (a Addr) Usable() bool { return a.Up && a.Kind != Loopback }

// List returns the addresses of the host's interfaces, classified.
func List() ([]Addr, error) {
	ifaces, addrs, err := Interfaces()
	if err != nil {
		return nil, err
	}
	return Classify(ifaces, addrs), nil
}

// Interfaces returns the host's network interfaces and, at the same index,
// each one's addresses with their prefixes, IPv4-mapped addresses unmapped.
// An interface whose addresses cannot be read is listed without any.
//
// Where the system refuses package net's interface list — Android 11 and
// later to ordinary apps, some sandboxes — Linux reads the addresses from a
// netlink address dump instead, which those systems allow: every interface
// with an address is then reported up, with the loopback and
// point-to-point flags its addresses show and the name of its IPv4 label
// (an IPv6-only interface has none).
//
//holepunch:netimpl
func Interfaces() ([]net.Interface, [][]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		if fi, fa, ferr := interfacesFallback(); ferr == nil {
			return fi, fa, nil
		}
		return nil, nil, err
	}
	addrs := make([][]netip.Prefix, len(ifaces))
	for i := range ifaces {
		list, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range list {
			if p, ok := prefixOf(a); ok {
				addrs[i] = append(addrs[i], p)
			}
		}
	}
	return ifaces, addrs, nil
}

// Classify classifies interface addresses given in the form Interfaces
// returns them. Addresses without an interface at their index belong to an
// unnamed interface that is up.
func Classify(ifaces []net.Interface, addrs [][]netip.Prefix) []Addr {
	var out []Addr
	for i, list := range addrs {
		ifc := net.Interface{Flags: net.FlagUp}
		if i < len(ifaces) {
			ifc = ifaces[i]
		}
		for _, p := range list {
			a := p.Addr().Unmap().WithZone("")
			if !a.IsValid() {
				continue
			}
			bits := p.Bits()
			if p.Addr().Is4In6() && bits >= 96 {
				bits -= 96
			}
			out = append(out, Addr{
				Prefix:    netip.PrefixFrom(a, min(bits, a.BitLen())),
				Interface: ifc.Name,
				Up:        ifc.Flags&net.FlagUp != 0,
				Kind:      KindOf(ifc, a),
			})
		}
	}
	return out
}

// KindOf classifies a, an address of interface ifc.
func KindOf(ifc net.Interface, a netip.Addr) Kind {
	a = a.Unmap()
	switch {
	case ifc.Flags&net.FlagLoopback != 0 || a.IsLoopback():
		return Loopback
	case IsOverlay(ifc, a):
		return Overlay
	case a.IsGlobalUnicast() && !a.IsPrivate():
		return Public
	}
	return LAN
}

// IsOverlay reports whether a, an address of interface ifc, is an overlay
// address: on an interface whose name marks a tunnel or overlay (see
// OverlayName), on a point-to-point interface unless a is a public address
// — the link of a PPPoE or cellular uplink carries the host's own public
// address — or in the shared space 100.64.0.0/10, where Tailscale and
// carriers number their overlays and subscribers.
func IsOverlay(ifc net.Interface, a netip.Addr) bool {
	a = a.Unmap()
	return inCGN(a) || OverlayName(ifc.Name) ||
		ifc.Flags&net.FlagPointToPoint != 0 && (!a.IsGlobalUnicast() || a.IsPrivate() || a.IsLinkLocalUnicast())
}

// OverlayName reports whether an interface name marks a tunnel or overlay
// interface, by its prefix, compared case-insensitively: Tailscale
// (tailscale0 on Linux, "Tailscale" on Windows), utun on Apple systems
// (Tailscale, WireGuard and other VPNs), WireGuard (wg0), ZeroTier (zt… on
// Unix, "ZeroTier One" on Windows) and tun devices.
func OverlayName(name string) bool {
	name = strings.ToLower(name)
	for _, p := range [...]string{"tailscale", "utun", "wg", "zt", "zerotier", "tun"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

var errNoFallback = errors.New("hostaddr: no fallback interface list")

// inCGN reports whether a is in the RFC 6598 shared address space
// 100.64.0.0/10.
func inCGN(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	return b[0] == 100 && b[1]&0xC0 == 64
}

// prefixOf converts an interface address of package net, unmapping an
// IPv4-mapped one.
func prefixOf(a net.Addr) (netip.Prefix, bool) {
	n, ok := a.(*net.IPNet)
	if !ok {
		return netip.Prefix{}, false
	}
	ip, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	if ip.Is4In6() {
		ip = ip.Unmap()
		if ones >= 96 {
			ones -= 96
		}
	}
	return netip.PrefixFrom(ip, ones), true
}

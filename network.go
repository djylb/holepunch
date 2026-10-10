package holepunch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/djylb/holepunch/internal/udpicmp"
)

// Network abstracts every operating-system network access of a session:
// sockets, interface addresses, the outbound source address and name
// resolution. Its methods use standard-library types only, so a simulator
// such as nattest.Host implements it without importing this package.
// The library calls these methods outside its locks and inside a recover
// boundary; a panic is treated as an error of that call.
type Network interface {
	// ListenPacket opens a UDP socket on laddr ("udp4" or "udp6"; a zero
	// laddr address means every address of the family, port 0 means any).
	// The library binds each family on its own socket and never asks for a
	// dual-stack one. purpose is one of the Purpose constants, for
	// simulators and diagnostics. The returned conn may implement
	// HopLimiter. Reads and writes failing with an ICMP report (port or host
	// unreachable, TTL expired) are soft signals, so a conn that keeps the
	// Windows reports on still works.
	ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) //holepunch:callback
	// InterfaceAddrs returns the host's network interfaces and, at the same
	// index, each one's addresses with their prefixes. Of an interface the
	// library reads the name and the flags net.FlagUp, net.FlagLoopback and
	// net.FlagPointToPoint: addresses on tunnel and overlay interfaces
	// (Tailscale, WireGuard, ZeroTier, tun, utun, point-to-point links) and
	// in 100.64/10 are overlay candidates, kept apart from the LAN ones
	// (Options.ExcludeOverlay), and
	// Options.LocalInterface is looked up by name. On failure — Android 11
	// and later refuse the netlink request to ordinary apps — the session
	// runs without LAN and overlay addresses and Diagnostics.Warn carries
	// interface_list_unavailable; a host app that knows its interfaces can
	// inject a Network that returns them.
	InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error) //holepunch:callback
	// OutboundAddr returns the source address the host uses towards the
	// Internet for network ("udp4", "udp6"); no packet is sent.
	OutboundAddr(ctx context.Context, network string) (netip.Addr, error) //holepunch:callback
	// LookupNetIP resolves host for network ("ip", "ip4", "ip6").
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) //holepunch:callback
}

// Socket purposes passed to Network.ListenPacket. Package portmapper opens
// its request sockets with purpose "portmap".
const (
	PurposeProbe    = "probe"    // primary, second and sandwich-helper sockets
	PurposeSibling  = "sibling"  // sockets bound on other local addresses during probing
	PurposeWarmup   = "warmup"   // extra round sockets that pre-open mappings with a low TTL
	PurposeBirthday = "birthday" // extra round sockets of multi-socket (birthday) rounds
	PurposeFresh    = "fresh"    // fresh sockets bound at drawn ports for one round
)

// HopLimiter is the optional TTL / hop-limit capability of a conn returned by
// Network.ListenPacket. SetHopLimit(0) restores the system default.
//
// The library prefers this interface; otherwise it sets the option through
// syscall.Conn. The decision is made by interface, never by the concrete
// *net.UDPConn type, so wrapping conns keep their
// behaviour. A conn with neither capability, or one whose setting fails,
// makes the session send without low TTL: probe_report announces
// low_ttl=false and Diagnostics.Warn carries low_ttl_unsupported. The value
// found when the socket was created is restored before the winning socket is
// handed over.
type HopLimiter interface {
	SetHopLimit(hops int) error //holepunch:callback
}

// SystemNetwork returns the Network of the operating system: package net
// sockets, interfaces and resolver. ListenPacket switches the Windows ICMP
// reports off on every socket it opens. OutboundAddr learns the source
// address by connecting a UDP socket to a public address, which sends
// nothing.
func SystemNetwork() Network { return systemNetwork{} }

type systemNetwork struct{}

// outboundProbe are the addresses OutboundAddr connects to (no packet leaves
// the host); they only select the route.
const (
	outboundProbe4 = "8.8.8.8:53"
	outboundProbe6 = "[2400:3200::1]:53"
)

// ListenPacket opens an OS UDP socket.
//
//holepunch:netimpl
func (systemNetwork) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, _ string) (net.PacketConn, error) {
	var lc net.ListenConfig
	c, err := lc.ListenPacket(ctx, network, listenAddr(laddr))
	if err != nil {
		return nil, err
	}
	// Best effort: when the switch fails, the read loop still takes the
	// reports for the soft signals they are.
	_ = udpicmp.DisableReports(c)
	return c, nil
}

// InterfaceAddrs lists the OS interfaces with their addresses. An
// interface whose addresses cannot be read is listed without any.
//
//holepunch:netimpl
func (systemNetwork) InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
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

// OutboundAddr learns the route's source address from a connected UDP socket.
//
//holepunch:netimpl
func (systemNetwork) OutboundAddr(ctx context.Context, network string) (netip.Addr, error) {
	target, nw := outboundProbe4, "udp4"
	if strings.HasSuffix(network, "6") {
		target, nw = outboundProbe6, "udp6"
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, nw, target)
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = c.Close() }()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("holepunch: outbound address unavailable")
	}
	ap := ua.AddrPort()
	return ap.Addr().Unmap().WithZone(""), nil
}

// LookupNetIP resolves through the default resolver.
//
//holepunch:netimpl
func (systemNetwork) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// listenAddr renders laddr for package net; a zero address binds every
// address of the family.
func listenAddr(laddr netip.AddrPort) string {
	if !laddr.Addr().IsValid() {
		return ":" + strconv.Itoa(int(laddr.Port()))
	}
	return laddr.String()
}

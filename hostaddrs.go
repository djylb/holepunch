package holepunch

import (
	"net"
	"net/netip"
	"strings"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/protocol"
)

// hostAddr is one address of this host, as Network.InterfaceAddrs listed
// it, with what a session may use it for.
type hostAddr struct {
	addr  netip.Addr // unmapped, without zone
	iface string
	// live: on an interface that is up and not loopback; only such an
	// address can be a candidate or carry a sibling socket.
	live bool
	// overlay: on a tunnel or overlay interface, or in 100.64/10. Such an
	// address is never a LAN candidate; it is an overlay candidate unless
	// Options.ExcludeOverlay.
	overlay bool
}

// overlayName reports whether an interface name marks a tunnel or overlay
// interface, by its prefix, compared case-insensitively: Tailscale
// (tailscale0 on Linux, "Tailscale" on Windows), utun on Apple systems
// (Tailscale, WireGuard and other VPNs), WireGuard (wg0), ZeroTier (zt… on
// Unix, "ZeroTier One" on Windows) and tun devices. Docker and
// virtual-machine bridges (docker0, br-…, virbr…, vmnet…) are ordinary LANs:
// traffic over them is direct, between a host and its containers or
// machines.
func overlayName(name string) bool {
	name = strings.ToLower(name)
	for _, p := range [...]string{"tailscale", "utun", "wg", "zt", "zerotier", "tun"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// overlayAddr reports whether a, an address of interface ifc, is an overlay
// address: on an interface whose name marks a tunnel or overlay, on
// a point-to-point interface unless a is a public address — the link of a
// PPPoE or cellular uplink carries the host's own public address — or in
// the shared space 100.64/10, where Tailscale and carriers number their
// overlays and subscribers.
func overlayAddr(ifc net.Interface, a netip.Addr) bool {
	return nat.IsCGN(a) || overlayName(ifc.Name) ||
		ifc.Flags&net.FlagPointToPoint != 0 && (!a.IsGlobalUnicast() || netaddr.Private(a))
}

// hostAddrsOf classifies what Network.InterfaceAddrs returned. Addresses
// without an interface at their index belong to an unnamed, live
// interface.
func hostAddrsOf(ifaces []net.Interface, addrs [][]netip.Prefix) []hostAddr {
	var out []hostAddr
	for i, list := range addrs {
		ifc := net.Interface{Flags: net.FlagUp}
		if i < len(ifaces) {
			ifc = ifaces[i]
		}
		live := ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagLoopback == 0
		for _, p := range list {
			a := p.Addr().Unmap().WithZone("")
			if !a.IsValid() {
				continue
			}
			out = append(out, hostAddr{addr: a, iface: ifc.Name, live: live && !a.IsLoopback(), overlay: overlayAddr(ifc, a)})
		}
	}
	return out
}

// interfaceAddrs asks the Network for the host's interfaces once, at
// punch_start. Without them the session runs with no LAN and no overlay
// addresses and says so in Diagnostics.Warn: Android 11 and later refuse
// the list to ordinary apps, and a host app that knows its interfaces
// can then inject a Network that returns them.
func (rt *runtime) interfaceAddrs() []hostAddr {
	var ifaces []net.Interface
	var addrs [][]netip.Prefix
	var err error
	pe := life.Safe("network.interfaceaddrs", func() { ifaces, addrs, err = rt.netw.InterfaceAddrs() })
	if pe != nil {
		rt.cnt.callbackPanics.Add(1)
	}
	if pe != nil || err != nil {
		rt.addWarn(protocol.WarnInterfaceListUnavailable)
		return nil
	}
	return hostAddrsOf(ifaces, addrs)
}

// readHosts reads the host's interfaces once, at punch_start: every address
// is one of this host's (admission refuses them as targets), and
// Options.LocalInterface picks the primary sockets' addresses by name.
// Android refuses the interface table, and a missing interface looks the
// same: either way the session runs without the preference and says so,
// once.
func (rt *runtime) readHosts() {
	rt.hosts = rt.interfaceAddrs()
	for _, h := range rt.hosts {
		rt.localIPs[h.addr] = struct{}{}
	}
	if name := rt.opts.LocalInterface; name != "" {
		if rt.ifacePrefer = ifaceAddrs(rt.hosts, name); len(rt.ifacePrefer) == 0 && rt.hosts != nil {
			rt.addWarn(protocol.WarnInterfaceListUnavailable)
		}
	}
}

// lanAddr reports whether h may stand for this host on a LAN: a live
// address that is no overlay one.
func (h hostAddr) lanAddr() bool { return h.live && !h.overlay }

// localAddrs lists the host's LAN addresses of a family for probe_report:
// overlay addresses are reported apart (overlayAddrs).
func localAddrs(f protocol.Family, hosts []hostAddr) []netip.Addr {
	var out []netip.Addr
	for _, h := range hosts {
		if len(out) == maxLocalAddrs {
			break
		}
		if a := h.addr; h.lanAddr() && f.Matches(a) && !netaddr.Unusable(a) && !(a.Is6() && a.IsLinkLocalUnicast()) {
			out = append(out, a)
		}
	}
	return out
}

// overlayAddrs lists the overlay addresses of a family for probe_report
// (FamilyReport.Overlay): none when the caller excludes them or when the
// family's primary socket is bound to one address and so does not listen
// on them.
func (rt *runtime) overlayAddrs(fs *famState) []netip.Addr {
	if rt.opts.ExcludeOverlay || rt.preferredAddr(fs.fam).IsValid() {
		return nil
	}
	var out []netip.Addr
	for _, h := range rt.hosts {
		if a := h.addr; len(out) < maxOverlayAddrs && h.live && h.overlay && fs.fam.Matches(a) && !netaddr.Unusable(a) &&
			!(a.Is6() && a.IsLinkLocalUnicast()) {
			out = append(out, a)
		}
	}
	return out
}

// globalAddr is the host's first global unicast LAN address of family f,
// the one an unobserved family binds to (bindUnobserved).
func globalAddr(f protocol.Family, hosts []hostAddr) netip.Addr {
	for _, h := range hosts {
		if a := h.addr; h.lanAddr() && f.Matches(a) && a.IsGlobalUnicast() && !netaddr.Private(a) {
			return a
		}
	}
	return netip.Addr{}
}

// ifaceAddrs returns the addresses of the interface named name.
func ifaceAddrs(hosts []hostAddr, name string) []netip.Addr {
	var out []netip.Addr
	for _, h := range hosts {
		if h.iface == name {
			out = append(out, h.addr)
		}
	}
	return out
}

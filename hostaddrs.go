package holepunch

import (
	"net"
	"net/netip"

	"github.com/djylb/holepunch/hostaddr"
	"github.com/djylb/holepunch/internal/life"
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

// hostAddrsOf classifies what Network.InterfaceAddrs returned (hostaddr).
func hostAddrsOf(ifaces []net.Interface, addrs [][]netip.Prefix) []hostAddr {
	list := hostaddr.Classify(ifaces, addrs)
	out := make([]hostAddr, 0, len(list))
	for _, a := range list {
		out = append(out, hostAddr{addr: a.Addr(), iface: a.Interface, live: a.Usable(), overlay: a.Kind == hostaddr.Overlay})
	}
	return out
}

// interfaceAddrs asks the Network for the host's interfaces once, at
// punch_start. Without them the session runs with no LAN and no overlay
// addresses and says so in Diagnostics.Warn; a host app that knows its
// interfaces can inject a Network that returns them.
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
// A refused interface table and a missing interface look the same: either
// way the session runs without the preference and says so, once.
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
		if len(out) == protocol.MaxLocalAddrs {
			break
		}
		if a := h.addr; h.lanAddr() && f.Matches(a) && !netaddr.Unusable(a) {
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
		if a := h.addr; len(out) < protocol.MaxOverlayAddrs && h.live && h.overlay && fs.fam.Matches(a) && !netaddr.Unusable(a) {
			out = append(out, a)
		}
	}
	return out
}

// globalAddr is the host's first global unicast LAN address of family f,
// the one an unobserved family binds to (bindUnobserved).
func globalAddr(f protocol.Family, hosts []hostAddr) netip.Addr {
	for _, h := range hosts {
		if a := h.addr; h.lanAddr() && f.Matches(a) && netaddr.Public(a) {
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

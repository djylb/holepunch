package nat

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/djylb/holepunch/protocol"
)

// Endpoint bounds (FamilyView.endpoints; LAN addresses).
const (
	maxEndpoints        = 12
	maxLANEndpoints     = 4
	maxOverlayEndpoints = 2
)

// VerifiedIPs returns the IPs of the verified server rows in the
// classification scope: rows natprobe recorded whose cookie the client
// echoed. They are the only IPs the peer may be told to send to and
// the reference set for self-reported endpoints.
func (t *ObsTable) VerifiedIPs() []netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.verifiedIPsLocked(t.classScopeLocked())
}

func (t *ObsTable) verifiedIPsLocked(scope Scope) []netip.Addr {
	var out []netip.Addr
	for _, r := range t.rows {
		if t.verifiedServerRowLocked(r, scope) && !slices.Contains(out, r.Observed.Addr()) {
			out = append(out, r.Observed.Addr())
		}
	}
	return out
}

// verifiedServerRowLocked: a verified natprobe row whose observer and value
// are both in the scope. A private observer's verified row would pass the
// peer's admission anywhere, so it never becomes a server endpoint.
func (t *ObsTable) verifiedServerRowLocked(r Row, scope Scope) bool {
	if !r.Verified || !r.Observed.IsValid() || ScopeOf(r.Observed.Addr()) != scope {
		return false
	}
	if r.Key.Source != SourceServer && r.Key.Source != SourceServerAlt {
		return false
	}
	o := t.observerLocked(r.Key.Observer)
	return o != nil && o.Scope == scope
}

// AdmitSelfReported reports whether a self-reported address of source src may
// enter a server-side table (anti-reflection): a STUN address only
// when its IP is verified; a port-mapping external address when its IP is
// verified, or private or shared space (a LAN or CGNAT candidate). Other
// sources are never self-reported.
func AdmitSelfReported(src Source, a netip.AddrPort, verified []netip.Addr) bool {
	ip := a.Addr().Unmap()
	if !ip.IsValid() || a.Port() == 0 {
		return false
	}
	switch src {
	case SourceSTUN:
		return slices.Contains(verified, ip)
	case SourcePortMap:
		return slices.Contains(verified, ip) || ip.IsPrivate() || IsCGN(ip)
	case SourceServer, SourceServerAlt, SourcePeer:
		// Observed by a server or the peer, never self-reported.
	}
	return false
}

// SetReportedFallback sets whether a LAN-observed table (Traits.LANObserved)
// admits the global addresses its client reported — STUN answers and a
// port mapping's external address — although no server observation verifies
// their IP: the server saw the client only at private addresses, so it
// verifies no public IP the client could be reached at. They stay
// unverified endpoints, which the coordinator and the peer aim Direct stages
// at only (the unverified mode). It changes nothing for a table that is not
// LAN-observed.
func (t *ObsTable) SetReportedFallback(on bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reportedFallback = on
}

// AdmitReported reports whether a self-reported address of source src may
// enter the table: AdmitSelfReported, or, with the reported fallback on a
// LAN-observed table, a global unicast STUN or port-mapping address.
func (t *ObsTable) AdmitReported(src Source, a netip.AddrPort) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.admitReportedLocked(src, a, t.verifiedIPsLocked(t.classScopeLocked()))
}

func (t *ObsTable) admitReportedLocked(src Source, a netip.AddrPort, verified []netip.Addr) bool {
	if AdmitSelfReported(src, a, verified) {
		return true
	}
	ip := a.Addr().Unmap()
	return t.reportedFallback && (src == SourceSTUN || src == SourcePortMap) && a.Port() != 0 &&
		ScopeOf(ip) == ScopeGlobal && t.family.Matches(ip) && t.lanObservedLocked()
}

// NoteOverlay records the host's overlay addresses of the table's family
// (FamilyReport.Overlay): addresses on overlay,
// tunnel and virtual-bridge interfaces, on which the primary socket also
// listens. At most two usable unicast addresses are kept; a later call
// replaces them.
func (t *ObsTable) NoteOverlay(addrs []netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.overlay = t.overlay[:0]
	for _, a := range addrs {
		a = a.Unmap()
		if len(t.overlay) < maxOverlayEndpoints && t.family.Matches(a) && overlayCandidate(a) && !slices.Contains(t.overlay, a) {
			t.overlay = append(t.overlay, a)
		}
	}
}

// Endpoints returns what a server-side table may hand to the peer, at most 12
// and without repeats, in this order: verified server observations (primary,
// second, sibling sockets, each by mapping creation order); STUN and
// port-mapping addresses that pass AdmitReported; the primary socket's
// local port on its first verified IP, unless an observation holds it already
// (EndpointLocalPort: a NAT that keeps the local port on the path toward the
// peer maps it there); at most four LAN addresses, the local addresses of the
// primary and sibling sockets that are private or IPv4 link-local, or a
// verified public IP of a host without NAT; at most two overlay addresses
// (NoteOverlay) at the primary socket's port. Loopback, multicast, unspecified
// and IPv6 link-local addresses never qualify, and an address in 100.64/10 is
// an overlay address, never a LAN one. The coordinator forwards private LAN
// endpoints only to a peer on the same LAN (pair.same_lan), private
// port-mapping addresses only to a peer behind the same public IP, and overlay
// endpoints only to a peer that has some too (pair.shared_overlay).
func (t *ObsTable) Endpoints() []protocol.Endpoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	scope := t.classScopeLocked()
	verified := t.verifiedIPsLocked(scope)
	var out []protocol.Endpoint
	add := func(a netip.AddrPort, src protocol.EndpointSource, sock uint8, v bool) bool {
		if len(out) == maxEndpoints || slices.ContainsFunc(out, func(e protocol.Endpoint) bool { return e.Addr == a }) {
			return false
		}
		out = append(out, protocol.Endpoint{Addr: a, Source: src, Socket: sock, Verified: v})
		return true
	}
	var guess netip.AddrPort // the primary socket's local port on its verified IP
	var guessSock uint8
	for _, kind := range [...]protocol.SocketKind{protocol.SocketPrimary, protocol.SocketSecond, protocol.SocketSibling} {
		for _, s := range t.sockets {
			if s.Kind != kind {
				continue
			}
			var rows []Row
			for _, r := range t.rows {
				if r.Key.Socket == s.ID && t.verifiedServerRowLocked(r, scope) {
					rows = append(rows, r)
				}
			}
			slices.SortStableFunc(rows, func(a, b Row) int { return cmp.Compare(a.FirstSeq, b.FirstSeq) })
			for _, r := range rows {
				add(r.Observed, endpointSource(kind), s.ID, true)
			}
			if kind == protocol.SocketPrimary && len(rows) > 0 && s.Local.Port() != 0 && !guess.IsValid() {
				guess, guessSock = netip.AddrPortFrom(rows[0].Observed.Addr(), s.Local.Port()), s.ID
			}
		}
	}
	for _, src := range [...]Source{SourceSTUN, SourcePortMap} {
		for _, r := range t.rows {
			if r.Key.Source == src && r.Observed.IsValid() && t.admitReportedLocked(src, r.Observed, verified) {
				add(r.Observed, selfReportedSource(src), r.Key.Socket, false)
			}
		}
	}
	if guess.IsValid() {
		add(guess, protocol.EndpointLocalPort, guessSock, false) // nothing when an observation holds it
	}
	lan := 0
	for _, s := range t.sockets {
		lanSocket := s.Kind == protocol.SocketPrimary || s.Kind == protocol.SocketSibling
		if lan < maxLANEndpoints && lanSocket && usableIn(t.family, s.Local) && lanCandidate(s.Local, verified) &&
			add(s.Local, protocol.EndpointLAN, s.ID, false) {
			lan++
		}
	}
	if p, ok := t.socketOfKindLocked(protocol.SocketPrimary); ok && p.Local.Port() != 0 {
		for _, a := range t.overlay {
			add(netip.AddrPortFrom(a, p.Local.Port()), protocol.EndpointOverlay, p.ID, false)
		}
	}
	return out
}

func endpointSource(k protocol.SocketKind) protocol.EndpointSource {
	switch k {
	case protocol.SocketSecond:
		return protocol.EndpointSecond
	case protocol.SocketSibling:
		return protocol.EndpointSibling
	}
	return protocol.EndpointServer
}

func selfReportedSource(src Source) protocol.EndpointSource {
	if src == SourcePortMap {
		return protocol.EndpointPortmap
	}
	return protocol.EndpointSTUN
}

// lanCandidate applies the LAN rule to a local socket address. The
// shared space 100.64/10 is no LAN: Tailscale and the carriers number their
// overlays and subscribers there.
func lanCandidate(a netip.AddrPort, verified []netip.Addr) bool {
	ip := a.Addr().Unmap()
	switch {
	case !ip.IsValid() || a.Port() == 0 || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || IsCGN(ip):
		return false
	case ip.Is6() && ip.IsLinkLocalUnicast():
		return false // the peer cannot use it without our zone
	case ip.IsPrivate() || ip.IsLinkLocalUnicast():
		return true
	}
	return slices.Contains(verified, ip)
}

// overlayCandidate reports whether a reported overlay address can be aimed
// at: a unicast address that is not loopback, unspecified or IPv6 link
// local.
func overlayCandidate(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() && !(ip.Is6() && ip.IsLinkLocalUnicast()) &&
		ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

package nat

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/protocol"
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

func (t *ObsTable) verifiedIPsLocked(scope netaddr.Scope) []netip.Addr {
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
func (t *ObsTable) verifiedServerRowLocked(r Row, scope netaddr.Scope) bool {
	if !r.Verified || !r.Observed.IsValid() || netaddr.ScopeOf(r.Observed.Addr()) != scope {
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
// verified, or a usable LAN-scope one (netaddr.Private: a LAN or CGNAT
// candidate upstream). Other sources are never self-reported.
func AdmitSelfReported(src Source, a netip.AddrPort, verified []netip.Addr) bool {
	ip := a.Addr().Unmap()
	if !ip.IsValid() || a.Port() == 0 {
		return false
	}
	switch src {
	case SourceSTUN:
		return slices.Contains(verified, ip)
	case SourcePortMap:
		// A gateway on the client's own network may map from a private,
		// CGN or link-local address: the address an upstream router of a
		// double NAT hands out. The client and the coordinator take the
		// same set as upstream-LAN candidates.
		return slices.Contains(verified, ip) || netaddr.Private(ip) && !netaddr.Unusable(ip)
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
		netaddr.Public(ip) && t.family.Matches(ip) && t.lanObservedLocked()
}

// NoteOverlay records the host's overlay addresses of the table's family
// (FamilyReport.Overlay): addresses on overlay,
// tunnel and virtual-bridge interfaces, on which the primary socket also
// listens. At most two usable unicast addresses are kept; a later call
// replaces them.
func (t *ObsTable) NoteOverlay(addrs []netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.overlay = overlayAddrs(t.family, addrs)
}

// overlayAddrs keeps the overlay addresses of family fam a view may list:
// the first protocol.MaxOverlayAddrs distinct ones that pass overlayCandidate,
// unmapped.
func overlayAddrs(fam protocol.Family, addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if len(out) < protocol.MaxOverlayAddrs && fam.Matches(a) && overlayCandidate(a) && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
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
	var l endpointList
	for _, kind := range socketKinds {
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
			l.observed(s, rows, true)
		}
	}
	for _, src := range [...]Source{SourceSTUN, SourcePortMap} {
		for _, r := range t.rows {
			if r.Key.Source == src && r.Observed.IsValid() && t.admitReportedLocked(src, r.Observed, verified) {
				l.add(r.Observed, selfReportedSource(src), r.Key.Socket, false)
			}
		}
	}
	l.addGuess()
	for _, s := range t.sockets {
		l.addLAN(t.family, s, verified)
	}
	if p, ok := t.socketOfKindLocked(protocol.SocketPrimary); ok {
		l.addOverlay(p, t.overlay)
	}
	return l.out
}

// SelfReportedView is the family view of a client built from its own report
// alone, for a family no server observation verifies: its provisional
// traits and the endpoints Endpoints would list were every value it
// reports admitted, none of them verified — the observed values of its
// probe rows, its STUN answers and its port mapping, the local-port guess,
// the LAN addresses of its primary and sibling sockets and then the host's
// global addresses at the primary socket's port (a host without NAT is
// reached there), and its overlay addresses at that port. A value that no
// table would hold (protocol.UsableEndpoint), or that no peer could reach
// (netaddr.UsableTarget: loopback, broadcast, zoneless link-local), is left
// out.
func SelfReportedView(fr protocol.FamilyReport) protocol.FamilyView {
	fam := fr.Family
	fv := protocol.FamilyView{Family: fam, Traits: fr.Traits}
	fv.Traits.Family = fam
	// PortAnchorMs is on the server's axis, which a client cannot know; the
	// punch-time mappings re-anchor the prediction instead.
	fv.Traits.PortAnchorMs = 0
	// The wire admits loopback, the limited broadcast and zoneless
	// link-local; no peer can reach a client there.
	usable := func(a netip.AddrPort) bool { return protocol.UsableEndpoint(fam, a) && netaddr.UsableTarget(a) }
	var (
		l       endpointList
		primary SocketMeta
		public  []netip.Addr // the host's global addresses: a host without NAT is reached there
		ok      bool
	)
	for _, a := range fr.LocalAddrs {
		if a = a.Unmap(); fam.Matches(a) && netaddr.Public(a) && !slices.Contains(public, a) {
			public = append(public, a)
		}
	}
	for _, kind := range socketKinds {
		for _, sk := range fr.Sockets {
			if sk.Kind != kind {
				continue
			}
			s := SocketMeta{ID: sk.ID, Kind: sk.Kind, Local: netaddr.Unmap(sk.Local)}
			if kind == protocol.SocketPrimary && !ok {
				primary, ok = s, true
			}
			var rows []Row
			for _, r := range sk.Rows {
				if a := netaddr.Unmap(r.Observed); usable(a) {
					rows = append(rows, Row{Observed: a, FirstSeq: r.FirstSeq})
				}
			}
			l.observed(s, rows, false)
		}
	}
	for _, r := range fr.STUN {
		if a := netaddr.Unmap(r.Observed); usable(a) {
			l.add(a, protocol.EndpointSTUN, primary.ID, false)
		}
	}
	if pm := fr.PortMap; pm != nil {
		if a := netaddr.Unmap(pm.External); usable(a) {
			l.add(a, protocol.EndpointPortmap, primary.ID, false)
		}
	}
	l.addGuess()
	for _, sk := range fr.Sockets {
		l.addLAN(fam, SocketMeta{ID: sk.ID, Kind: sk.Kind, Local: netaddr.Unmap(sk.Local)}, public)
	}
	if ok {
		for _, a := range public {
			l.addLAN(fam, SocketMeta{ID: primary.ID, Kind: primary.Kind, Local: netip.AddrPortFrom(a, primary.Local.Port())}, public)
		}
		l.addOverlay(primary, overlayAddrs(fam, fr.Overlay))
	}
	fv.Endpoints = l.out
	if fv.Traits.Samples == 0 && len(fv.Endpoints) > 0 {
		fv.Traits.Samples = 1
	}
	return fv
}

// socketKinds is the order in which a view lists the sockets' observations.
var socketKinds = [...]protocol.SocketKind{protocol.SocketPrimary, protocol.SocketSecond, protocol.SocketSibling}

// endpointList builds the endpoints of a family view by the rules of
// Endpoints: at most protocol.MaxEndpoints, no address twice, at most
// protocol.MaxLANTargets LAN ones.
type endpointList struct {
	out       []protocol.Endpoint
	guess     netip.AddrPort // the primary socket's local port on its first observed IP
	lan       int
	guessSock uint8
}

// add appends a, unless the list is full or holds it already, and reports
// whether it did.
func (l *endpointList) add(a netip.AddrPort, src protocol.EndpointSource, sock uint8, verified bool) bool {
	if len(l.out) == protocol.MaxEndpoints || slices.ContainsFunc(l.out, func(e protocol.Endpoint) bool { return e.Addr == a }) {
		return false
	}
	l.out = append(l.out, protocol.Endpoint{Addr: a, Source: src, Socket: sock, Verified: verified})
	return true
}

// observed adds the observed values of socket s's rows by mapping creation
// order and notes the local-port guess of the first primary socket with an
// observation.
func (l *endpointList) observed(s SocketMeta, rows []Row, verified bool) {
	slices.SortStableFunc(rows, func(a, b Row) int { return cmp.Compare(a.FirstSeq, b.FirstSeq) })
	for _, r := range rows {
		l.add(r.Observed, endpointSource(s.Kind), s.ID, verified)
	}
	if s.Kind == protocol.SocketPrimary && len(rows) > 0 && s.Local.Port() != 0 && !l.guess.IsValid() {
		l.guess, l.guessSock = netip.AddrPortFrom(rows[0].Observed.Addr(), s.Local.Port()), s.ID
	}
}

// addGuess adds the local-port guess (EndpointLocalPort): nothing when an
// observation holds it already.
func (l *endpointList) addGuess() {
	if l.guess.IsValid() {
		l.add(l.guess, protocol.EndpointLocalPort, l.guessSock, false)
	}
}

// addLAN adds the local address of a primary or sibling socket s when it
// passes the LAN rule (lanCandidate) with public as the host's public IPs.
func (l *endpointList) addLAN(fam protocol.Family, s SocketMeta, public []netip.Addr) {
	lanSocket := s.Kind == protocol.SocketPrimary || s.Kind == protocol.SocketSibling
	if l.lan < protocol.MaxLANTargets && lanSocket && protocol.UsableEndpoint(fam, s.Local) && lanCandidate(s.Local, public) &&
		l.add(s.Local, protocol.EndpointLAN, s.ID, false) {
		l.lan++
	}
}

// addOverlay adds the overlay addresses at the primary socket's port.
func (l *endpointList) addOverlay(primary SocketMeta, overlay []netip.Addr) {
	if primary.Local.Port() == 0 {
		return
	}
	for _, a := range overlay {
		l.add(netip.AddrPortFrom(a, primary.Local.Port()), protocol.EndpointOverlay, primary.ID, false)
	}
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

// lanCandidate applies the LAN rule to a local socket address: a usable
// target that is netaddr.Private, or a verified IP of a host without NAT.
// The shared space 100.64/10 is no LAN: Tailscale and the carriers number
// their overlays and subscribers there.
func lanCandidate(a netip.AddrPort, verified []netip.Addr) bool {
	ip := a.Addr().Unmap()
	if !netaddr.UsableTarget(a) || netaddr.IsCGN(ip) {
		return false
	}
	return netaddr.Private(ip) || slices.Contains(verified, ip)
}

// overlayCandidate reports whether a reported overlay address can be aimed
// at: one that is not netaddr.Unusable.
func overlayCandidate(ip netip.Addr) bool { return !netaddr.Unusable(ip) }

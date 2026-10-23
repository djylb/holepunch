package nat

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/protocol"
)

// Classify derives the family's traits from the table without changing it. The
// result is provisional; natprobe's merge recomputes it from its own records
// and clears the flag.
//
// The primary socket's samples are the first values it got from the
// main-group observers of the classification scope, ordered by first send
// seq (mapping creation order). The scope is global when any main observer
// is global, otherwise private: a LAN-only or loopback deployment still
// classifies, while a private observer next to global ones only proves LAN
// reachability. The cross-address sources of the primary socket are
// natprobe's alt group and the peer, in the same scope.
//
// STUN is a hint: a STUN value is self-reported evidence from a third party, so
// it can never raise a confidence above the Medium that natprobe's single-IP
// samples give (it sets no CrossIP), and it changes none of natprobe's
// conclusions — another port is no ADM, another IP no MultiExit, a second value
// at a STUN point no drift. It can only take trust away: when natprobe found
// one mapping and a STUN server saw the primary socket at another port of a
// public IP natprobe saw, the mapping depends on the path to the observer, and
// PathDependent tells the planner not to trust the EIM conclusion.
// STUNConflicts counts the contradicting STUN points, and a STUN server that
// never answers leaves the table as it was.
func (t *ObsTable) Classify() protocol.Traits {
	t.mu.Lock()
	defer t.mu.Unlock()
	tr := protocol.Traits{Family: t.family, Provisional: true, Hairpin: t.hairpin}
	p, ok := t.socketOfKindLocked(protocol.SocketPrimary)
	if !ok {
		return tr
	}
	scope := t.classScopeLocked()
	samples := t.firstValuesLocked(p.ID, scope)
	tr.Samples = uint8(len(samples))
	var pub netip.Addr
	if len(samples) > 0 {
		pub = samples[0].Observed.Addr()
	}
	tr.CGNAT = t.cgnatLocked(p, pub)
	if len(samples) == 0 {
		return tr
	}
	first := samples[0].Observed
	tr.Observed, tr.PublicIP = first, first.Addr()
	if lanObserved(samples, scope) {
		// The server's public observers saw a private address: the
		// client reaches the server without NAT, so the samples describe
		// that path and nothing of the client's NAT toward the Internet.
		tr.LANObserved, tr.NoNAT = true, protocol.TriUnknown
		return tr
	}
	tr.NoNAT = noNAT(p, samples, scope)
	xs := t.crossRowsLocked(p.ID, scope, SourceServerAlt, SourcePeer)
	tr.MultiExit = distinctIPs(samples, xs) >= 2
	tr.Drifted = t.anyDriftLocked()
	tr.MultiHomed = t.multiHomedLocked(first.Addr(), scope)

	classifyMapping(&tr, samples, xs, t.secondVariesLocked(scope))
	if tr.Drifted && tr.MappingConf > protocol.ConfLow {
		tr.MappingConf = protocol.ConfLow
	}
	if tr.Mapping == protocol.MapEIM && tr.NoNAT != protocol.TriTrue {
		_, tr.PathDependent = t.stunConflictsLocked(p, scope)
	}
	switch tr.Mapping {
	case protocol.MapEIM:
		if first.Port() == p.Local.Port() {
			tr.PortAlloc, tr.PortAllocConf = protocol.AllocPreserving, confIf(len(samples) >= 2, protocol.ConfHigh, protocol.ConfMedium)
		}
	case protocol.MapADM:
		if first.Port() == p.Local.Port() {
			tr.PortAlloc, tr.PortAllocConf = protocol.AllocPreserving, protocol.ConfHigh
		} else {
			classifyPorts(&tr, t.perIPMappingsLocked(p.ID, samples, scope), nil)
		}
	case protocol.MapAPDM:
		t.classifyAllocationLocked(&tr, samples, p, scope)
	case protocol.MapUnknown:
		// Port allocation stays unclassified without a mapping.
	}
	t.classifyFilteringLocked(&tr, p, scope)
	return tr
}

// sample is the first value one main-group observer saw at a socket.
type sample struct {
	Row
	group uint8
}

// classifyMapping applies the mapping rules in order. Several main
// groups (a server with several public IPs) compare across addresses
// directly; a single group is the usual one-IP deployment, where only the
// cross-address sources can tell EIM from ADM.
func classifyMapping(tr *protocol.Traits, samples []sample, xs []Row, secondVaries bool) {
	m := len(samples)
	first := samples[0].Observed
	withinVary, multiMember, allSame := false, false, true
	var groups []uint8
	for _, s := range samples {
		allSame = allSame && s.Observed == first
		if slices.Contains(groups, s.group) {
			continue
		}
		groups = append(groups, s.group)
		members := 0
		for _, o := range samples {
			if o.group != s.group {
				continue
			}
			members++
			withinVary = withinVary || o.Observed.Port() != s.Observed.Port()
		}
		multiMember = multiMember || members >= 2
	}
	switch {
	case tr.MultiExit:
		tr.Mapping, tr.MappingConf = protocol.MapUnknown, protocol.ConfLow // ports of different exits are not comparable
	case tr.NoNAT == protocol.TriTrue:
		tr.Mapping, tr.MappingConf = protocol.MapEIM, protocol.ConfHigh // no NAT: the address is its own mapping
	case m >= 2 && withinVary:
		tr.Mapping, tr.MappingConf = protocol.MapAPDM, protocol.ConfMedium
		if m >= 3 || secondVaries {
			tr.MappingConf = protocol.ConfHigh
		}
	case m >= 2 && len(groups) >= 2:
		tr.CrossIP = true
		switch {
		case allSame:
			tr.Mapping, tr.MappingConf = protocol.MapEIM, protocol.ConfHigh
		case multiMember:
			tr.Mapping, tr.MappingConf = protocol.MapADM, protocol.ConfHigh
		default:
			// One observer per group: endpoint dependent, but ADM and APDM
			// cannot be told apart.
			tr.Mapping, tr.MappingConf = protocol.MapAPDM, protocol.ConfLow
		}
	case m >= 2:
		// One server IP and consistent observers: Medium, not the Low that
		// made every single-IP cone look hard.
		tr.Mapping, tr.MappingConf = protocol.MapEIM, protocol.ConfMedium
		for _, x := range xs {
			tr.CrossIP = true
			if x.Observed == first {
				tr.MappingConf = protocol.ConfHigh
				continue
			}
			if x.Observed.Addr() == first.Addr() {
				tr.Mapping, tr.MappingConf = protocol.MapADM, protocol.ConfHigh
				break
			}
		}
	default:
		tr.Mapping, tr.MappingConf = protocol.MapUnknown, protocol.ConfLow
	}
}

// classifyFilteringLocked applies the filtering rules to the primary
// socket's evidence at observers of the classification scope.
func (t *ObsTable) classifyFilteringLocked(tr *protocol.Traits, p SocketMeta, scope netaddr.Scope) {
	var ed, es, ad, as int
	for _, f := range t.filters {
		if f.Socket != p.ID {
			continue
		}
		if o := t.observerLocked(f.Observer); o == nil || o.Scope != scope {
			continue
		}
		ed, es, ad, as = ed+int(f.ExtraDeclared), es+int(f.ExtraSeen), ad+int(f.AltDeclared), as+int(f.AltSeen)
	}
	unsolicited := slices.ContainsFunc(t.inbound, func(e inboundEvidence) bool { return e.Socket == p.ID })
	switch {
	case es > 0 || as > 0 || unsolicited:
		tr.Filtering, tr.FilteringConf = protocol.FiltNotPDF, protocol.ConfHigh
		switch {
		case as > 0 || unsolicited || tr.NoNAT == protocol.TriTrue:
			tr.Filtering = protocol.FiltEIF
		case ad > 0:
			tr.Filtering, tr.FilteringConf = protocol.FiltADF, confIf(ad >= 2, protocol.ConfHigh, protocol.ConfMedium)
		}
	case ed > 0:
		// Every settled declaration was waited out without its extra.
		tr.Filtering, tr.FilteringConf = protocol.FiltPDF, confIf(ed >= 2, protocol.ConfHigh, protocol.ConfMedium)
	default:
		tr.Filtering, tr.FilteringConf = protocol.FiltUnknown, protocol.ConfNone
	}
}

// classScopeLocked is global when any main-group observer is global,
// otherwise private when any is private (a LAN-only deployment), else global.
func (t *ObsTable) classScopeLocked() netaddr.Scope {
	private := false
	for _, o := range t.observers {
		if o.Alt {
			continue
		}
		switch o.Scope {
		case netaddr.ScopeGlobal:
			return netaddr.ScopeGlobal
		case netaddr.ScopePrivate:
			private = true
		case netaddr.ScopeNone:
			// An observer without a usable address decides nothing.
		}
	}
	if private {
		return netaddr.ScopePrivate
	}
	return netaddr.ScopeGlobal
}

// firstValuesLocked returns, for socket sock, the first value each main-group
// observer of the scope saw, ordered by first send seq (ties by observer id).
func (t *ObsTable) firstValuesLocked(sock uint8, scope netaddr.Scope) []sample {
	var out []sample
	for _, o := range t.observers {
		if o.Alt || o.Scope != scope {
			continue
		}
		if r, ok := t.firstValueLocked(PointKey{Socket: sock, Source: SourceServer, Observer: o.ID}); ok {
			out = append(out, sample{Row: r, group: o.Group})
		}
	}
	slices.SortStableFunc(out, func(a, b sample) int {
		if c := cmp.Compare(a.FirstSeq, b.FirstSeq); c != 0 {
			return c
		}
		return int(a.Key.Observer) - int(b.Key.Observer)
	})
	return out
}

// firstValueLocked returns the earliest value seen at point k.
func (t *ObsTable) firstValueLocked(k PointKey) (Row, bool) {
	var best *Row
	for i := range t.rows {
		r := &t.rows[i]
		if r.Key == k && r.Observed.IsValid() && (best == nil || r.FirstSeen < best.FirstSeen) {
			best = r
		}
	}
	if best == nil {
		return Row{}, false
	}
	return *best, true
}

// crossRowsLocked returns the points of socket sock of the given cross-address
// sources (alt group, peer, STUN), one row per point holding the point's first
// value, in insertion order of the points. Only differences between points are
// mapping evidence: a later value at the same point is drift, which
// anyDriftLocked reports and which must not turn a consistent EIM into ADM or
// MultiExit. The first value is the one the classification of the main group
// uses too (firstValuesLocked).
func (t *ObsTable) crossRowsLocked(sock uint8, scope netaddr.Scope, sources ...Source) []Row {
	var xs []Row
	for _, r := range t.rows {
		if r.Key.Socket != sock || !r.Observed.IsValid() || !slices.Contains(sources, r.Key.Source) {
			continue
		}
		if r.Key.Source == SourceServerAlt {
			if o := t.observerLocked(r.Key.Observer); o == nil || o.Scope != scope {
				continue
			}
		}
		if slices.ContainsFunc(xs, func(x Row) bool { return x.Key == r.Key }) {
			continue
		}
		if first, _ := t.firstValueLocked(r.Key); netaddr.ScopeOf(first.Observed.Addr()) == scope {
			xs = append(xs, first)
		}
	}
	return xs
}

// STUNConflicts returns how many STUN points of the primary socket saw a
// value that contradicts natprobe's: a
// public IP no server observer saw, or another port where every server
// observer — main and alt group — saw the same mapping. A STUN value on a
// mapping natprobe found endpoint dependent, or with no server sample to
// compare, contradicts nothing. natprobe counts them in
// natprobe.MergeDiag.STUNConflicts; the second kind also makes Classify
// mark the traits PathDependent.
func (t *ObsTable) STUNConflicts() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.socketOfKindLocked(protocol.SocketPrimary)
	if !ok || t.lanObservedLocked() {
		return 0 // a LAN-observed table has no public value to contradict
	}
	n, _ := t.stunConflictsLocked(p, t.classScopeLocked())
	return n
}

// stunConflictsLocked counts the contradicting STUN points of primary socket
// p (STUNConflicts) and reports whether one of them saw another port of a
// public IP natprobe saw: a path-dependent mapping.
func (t *ObsTable) stunConflictsLocked(p SocketMeta, scope netaddr.Scope) (n int, otherPort bool) {
	var server []netip.AddrPort
	for _, s := range t.firstValuesLocked(p.ID, scope) {
		server = append(server, s.Observed)
	}
	for _, x := range t.crossRowsLocked(p.ID, scope, SourceServerAlt) {
		server = append(server, x.Observed)
	}
	if len(server) == 0 {
		return 0, false
	}
	independent := !slices.ContainsFunc(server, func(a netip.AddrPort) bool { return a != server[0] })
	for _, x := range t.crossRowsLocked(p.ID, scope, SourceSTUN) {
		otherIP := !slices.ContainsFunc(server, func(a netip.AddrPort) bool { return a.Addr() == x.Observed.Addr() })
		switch {
		case otherIP:
			n++
		case independent && x.Observed != server[0]:
			n++
			otherPort = true
		}
	}
	return n, otherPort
}

// anyDriftLocked reports a point with two or more values, or a server row whose
// point natprobe saw change value. A STUN point is left out: a third party's
// second answer is no evidence against natprobe's mapping.
func (t *ObsTable) anyDriftLocked() bool {
	for i, r := range t.rows {
		if !r.Observed.IsValid() || r.Key.Source == SourceSTUN {
			continue
		}
		if r.Changes > 0 {
			return true
		}
		for _, o := range t.rows[i+1:] {
			if o.Key == r.Key && o.Observed.IsValid() && o.Observed != r.Observed {
				return true
			}
		}
	}
	return false
}

// multiHomedLocked reports a sibling whose public IP differs from the
// primary's (same scope).
func (t *ObsTable) multiHomedLocked(pub netip.Addr, scope netaddr.Scope) bool {
	for _, s := range t.sockets {
		if s.Kind != protocol.SocketSibling {
			continue
		}
		for _, v := range t.firstValuesLocked(s.ID, scope) {
			if v.Observed.Addr() != pub {
				return true
			}
		}
	}
	return false
}

// secondVariesLocked reports whether the second socket also saw different
// ports at different observers.
func (t *ObsTable) secondVariesLocked(scope netaddr.Scope) bool {
	s, ok := t.socketOfKindLocked(protocol.SocketSecond)
	if !ok {
		return false
	}
	vals := t.firstValuesLocked(s.ID, scope)
	for _, v := range vals {
		if v.Observed.Port() != vals[0].Observed.Port() {
			return true
		}
	}
	return false
}

// cgnatLocked: a mapped external address in private or shared space while the
// server sees a public IP → true (High); a local address in shared space →
// true (Medium; Traits carries no CGNAT confidence); a mapped external address
// equal to the public IP → false; otherwise unknown.
func (t *ObsTable) cgnatLocked(p SocketMeta, pub netip.Addr) protocol.Tri {
	var mapped []netip.Addr
	for _, r := range t.rows {
		if r.Key.Source == SourcePortMap && r.Observed.IsValid() {
			mapped = append(mapped, r.Observed.Addr())
		}
	}
	publicSeen := netaddr.Public(pub)
	for _, ext := range mapped {
		if publicSeen && netaddr.ScopeOf(ext) == netaddr.ScopePrivate {
			return protocol.TriTrue
		}
	}
	if netaddr.IsCGN(p.Local.Addr()) {
		return protocol.TriTrue
	}
	if pub.IsValid() && slices.Contains(mapped, pub) {
		return protocol.TriFalse
	}
	return protocol.TriUnknown
}

// lanObserved reports whether public observers (scope global) saw the
// primary socket at private addresses only: a client that reaches the server
// over a LAN route or through a hairpin without source NAT.
func lanObserved(samples []sample, scope netaddr.Scope) bool {
	if scope != netaddr.ScopeGlobal || len(samples) == 0 {
		return false
	}
	for _, s := range samples {
		if netaddr.ScopeOf(s.Observed.Addr()) != netaddr.ScopePrivate {
			return false
		}
	}
	return true
}

// LANObserved reports whether the table's public observers saw its primary
// socket at private addresses only (protocol.Traits.LANObserved).
func (t *ObsTable) LANObserved() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lanObservedLocked()
}

// lanObservedLocked is lanObserved for the table's primary socket.
func (t *ObsTable) lanObservedLocked() bool {
	p, ok := t.socketOfKindLocked(protocol.SocketPrimary)
	if !ok {
		return false
	}
	scope := t.classScopeLocked()
	return lanObserved(t.firstValuesLocked(p.ID, scope), scope)
}

// noNAT: every server value equals the local address, which is global (or
// private in a private-scope deployment) → true; a mix → unknown (the
// contradiction has no confidence field to lower); none → false.
func noNAT(p SocketMeta, samples []sample, scope netaddr.Scope) protocol.Tri {
	local := p.Local
	localOK := local.IsValid() && (netaddr.Public(local.Addr()) || scope == netaddr.ScopePrivate)
	all, some := true, false
	for _, s := range samples {
		if s.Observed == local {
			some = true
		} else {
			all = false
		}
	}
	switch {
	case all && localOK:
		return protocol.TriTrue
	case some:
		return protocol.TriUnknown
	}
	return protocol.TriFalse
}

func distinctIPs(samples []sample, xs []Row) int {
	var ips []netip.Addr
	add := func(a netip.Addr) {
		if !slices.Contains(ips, a) {
			ips = append(ips, a)
		}
	}
	for _, s := range samples {
		add(s.Observed.Addr())
	}
	for _, x := range xs {
		add(x.Observed.Addr())
	}
	return len(ips)
}

func confIf(c bool, yes, no protocol.Conf) protocol.Conf {
	if c {
		return yes
	}
	return no
}

package nattest

import (
	"container/list"
	"net/netip"
	"slices"
	"time"
)

// famMode is how a NAT device treats one address family.
type famMode uint8

const (
	modeTranslate famMode = iota // NAT44 / NAT66
	modeIdentity                 // no translation, stateful firewall
	modeNPT                      // NPTv6 prefix translation
)

// mapKey identifies a mapping. Which fields are set follows the Mapping
// behaviour of the path; exit is set when ExitPolicy PerDestIP makes the
// external address depend on the destination, and path is the index of the
// destination's NATConfig.Routes entry plus one, 0 for the device's own.
type mapKey struct {
	in    netip.AddrPort
	rip   netip.Addr
	rport uint16
	exit  netip.Addr
	path  uint8
}

// pathRule is how one path through a device translates: the device's own
// fields (path 0) or a Route's.
type pathRule struct {
	alloc     PortAlloc
	mapping   Mapping
	filtering Filtering
	proxy     bool
}

// rule returns the translation of path k of the family.
func (f *natFam) rule(k uint8) pathRule {
	if k == 0 || int(k) > len(f.routes) {
		return pathRule{mapping: f.mapping, filtering: f.filtering, alloc: f.alloc}
	}
	return f.routes[k-1]
}

// pathOf is the path a packet toward dst takes (mapKey.path).
func (nat *NAT) pathOf(dst netip.Addr) uint8 {
	for i, r := range nat.cfg.Routes {
		for _, p := range r.Dst {
			if p.Contains(dst) {
				return uint8(i + 1)
			}
		}
	}
	return 0
}

// mapEntry is one mapping, or one firewall flow of an Identity / NPTv6 device.
// Times are network time.
type mapEntry struct {
	f       *natFam
	key     mapKey
	in, ext netip.AddrPort
	remote  netip.AddrPort // destination part of the key

	created, lastOut, lastIn, refresh time.Duration
	nOut, nIn                         uint64

	// Filter state, as conntrack keeps it: the last outbound packet per
	// remote endpoint and per remote IP. Each permission expires on its own
	// after MappingTimeout, independently of the mapping.
	perm    map[netip.AddrPort]time.Duration
	permIP  map[netip.Addr]time.Duration
	permCap int // size at which stale permissions are swept

	// aliases are the keys of the flows that inbound packets opened on an
	// endpoint-dependent mapping, as conntrack opens them: a reply to such a
	// packet leaves through the mapping that admitted it. A mapping keeps at
	// most MaxMappings of them, so that one that admits everyone stays
	// bounded under a scan; a reply beyond them takes a mapping of its own.
	aliases []mapKey

	elem *list.Element // position in NAT.lru
}

// natFam is the state of one address family of a NAT device. It is guarded
// by NAT.mu, except the fields that addressing reads under Network.topo:
// mode, lanPrefix and site never change, nextLAN changes only under topo.
type natFam struct {
	v6        bool
	mode      famMode
	mapping   Mapping
	filtering Filtering
	alloc     PortAlloc
	routes    []pathRule // NATConfig.Routes, path k at k-1
	step      int
	lo, hi    int

	ext       []netip.Addr // external addresses (modeTranslate)
	lanPrefix netip.Prefix // LAN of modeTranslate and modeNPT
	site      netip.Prefix // public /64 of modeNPT, and of modeIdentity on the core
	nextLAN   uint64

	byKey  map[mapKey]*mapEntry
	byExt  map[netip.AddrPort]*mapEntry
	used   map[netip.Addr]*portBitmap // external ports held by mappings
	cursor map[netip.Addr]int         // Sequential cursor per external IP
	rr     int                        // RoundRobin position

	noise portNoise
}

func (f *natFam) isExternal(a netip.Addr) bool {
	switch f.mode {
	case modeTranslate:
		return slices.Contains(f.ext, a)
	case modeNPT:
		return f.site.Contains(a)
	default: // modeIdentity
		return false
	}
}

// swapPrefix replaces the /64 prefix of a with to's.
func swapPrefix(a netip.Addr, to netip.Prefix) netip.Addr {
	b := a.As16()
	p := to.Addr().As16()
	copy(b[:8], p[:8])
	return netip.AddrFrom16(b)
}

func (f *natFam) nptOut(a netip.Addr) netip.Addr {
	if f.lanPrefix.Contains(a) {
		return swapPrefix(a, f.site)
	}
	return a
}

func (f *natFam) nptIn(a netip.Addr) netip.Addr {
	if f.site.Contains(a) {
		return swapPrefix(a, f.lanPrefix)
	}
	return a
}

// toInternal maps an external endpoint of the family to the LAN endpoint
// behind it, for the stateless parts of NPTv6.
func (f *natFam) toInternal(ep netip.AddrPort) netip.AddrPort {
	if f.mode == modeNPT {
		return netip.AddrPortFrom(f.nptIn(ep.Addr()), ep.Port())
	}
	return ep
}

func (nat *NAT) expired(m *mapEntry, now time.Duration) bool {
	return nat.timeout >= 0 && now-m.refresh >= nat.timeout
}

// fresh reports whether state last refreshed at t is still within
// MappingTimeout.
func (nat *NAT) fresh(t, now time.Duration) bool {
	return nat.timeout < 0 || now-t < nat.timeout
}

func (nat *NAT) removeLocked(m *mapEntry) {
	f := m.f
	delete(f.byKey, m.key)
	for _, k := range m.aliases {
		if f.byKey[k] == m {
			delete(f.byKey, k)
		}
	}
	if f.byExt[m.ext] == m {
		delete(f.byExt, m.ext)
	}
	if f.mode == modeTranslate {
		if b := f.used[m.ext.Addr()]; b != nil {
			b.clear(m.ext.Port())
		}
	}
	nat.lru.Remove(m.elem)
}

// purgeExpiredLocked removes expired mappings. The LRU list is ordered by
// refresh time, so the scan stops at the first live mapping from the back.
func (nat *NAT) purgeExpiredLocked(now time.Duration) {
	if nat.timeout < 0 {
		return
	}
	for e := nat.lru.Back(); e != nil; {
		m := e.Value.(*mapEntry)
		if !nat.expired(m, now) {
			return
		}
		prev := e.Prev()
		nat.removeLocked(m)
		nat.cnt.expired++
		e = prev
	}
}

// flushLocked removes the mappings and the port noise of family f, or of all
// families when f is nil.
func (nat *NAT) flushLocked(f *natFam) {
	for e := nat.lru.Front(); e != nil; {
		next := e.Next()
		if m := e.Value.(*mapEntry); f == nil || m.f == f {
			nat.removeLocked(m)
			nat.cnt.expired++
		}
		e = next
	}
	for _, ff := range nat.families() {
		if f == nil || ff == f {
			ff.noise.reset()
		}
	}
}

// keyOut is the mapping key of an outbound packet from src to dst, and the
// exit address the destination selects (PerDestIP), if any.
func (nat *NAT) keyOut(f *natFam, src, dst netip.AddrPort) (mapKey, netip.Addr) {
	key := mapKey{in: src}
	var exit netip.Addr
	if f.mode == modeTranslate {
		key.path = nat.pathOf(dst.Addr())
		switch f.rule(key.path).mapping {
		case EIM, Identity: // keyed by the internal endpoint alone
		case ADM:
			key.rip = dst.Addr()
		case APDM:
			key.rip, key.rport = dst.Addr(), dst.Port()
		}
		if len(f.ext) > 1 && nat.cfg.ExitPolicy == PerDestIP {
			b := dst.Addr().As16()
			exit = f.ext[nat.hash(b[:])%uint64(len(f.ext))]
			key.exit = exit
		}
	}
	return key, exit
}

// mapOut finds or creates the mapping for an outbound packet from src to dst.
func (nat *NAT) mapOut(f *natFam, src, dst netip.AddrPort, now time.Duration) (*mapEntry, dropReason) {
	key, exit := nat.keyOut(f, src, dst)
	if m := f.byKey[key]; m != nil {
		if !nat.expired(m, now) {
			return m, dropNone
		}
		nat.removeLocked(m)
		nat.cnt.expired++
	}
	nat.purgeExpiredLocked(now)
	m := &mapEntry{f: f, key: key, in: src, created: now, refresh: now}
	switch f.mode {
	case modeTranslate:
		if !exit.IsValid() {
			exit = nat.chooseExit(f, src)
		}
		nat.realizeNoise(f, now)
		port, ok := nat.allocPort(f, f.rule(key.path).alloc, exit, src.Port(), now)
		if !ok {
			return nil, dropNoPort
		}
		m.ext = netip.AddrPortFrom(exit, port)
		f.bitmap(exit).set(port)
		if key.rip.IsValid() {
			m.remote = netip.AddrPortFrom(key.rip, key.rport)
		}
	case modeIdentity:
		m.ext = src
	case modeNPT:
		m.ext = netip.AddrPortFrom(f.nptOut(src.Addr()), src.Port())
	}
	f.byKey[key] = m
	f.byExt[m.ext] = m
	m.elem = nat.lru.PushFront(m)
	nat.cnt.created++
	for nat.lru.Len() > nat.cfg.MaxMappings {
		back := nat.lru.Back()
		if back == nil {
			break
		}
		nat.removeLocked(back.Value.(*mapEntry))
		nat.cnt.evicted++
	}
	return m, dropNone
}

func (nat *NAT) chooseExit(f *natFam, src netip.AddrPort) netip.Addr {
	if len(f.ext) == 1 {
		return f.ext[0]
	}
	switch nat.cfg.ExitPolicy {
	case PerSourcePort:
		b, _ := src.MarshalBinary()
		return f.ext[nat.hash(b)%uint64(len(f.ext))]
	case RoundRobin:
		a := f.ext[f.rr%len(f.ext)]
		f.rr++
		return a
	default: // SingleExit; PerDestIP picks its exit in keyOut
		return f.ext[0]
	}
}

// hash is FNV-1a salted per NAT, so that two NATs spread the same endpoints
// differently over their exits.
func (nat *NAT) hash(b []byte) uint64 {
	h := nat.salt ^ 0xcbf29ce484222325
	for _, c := range b {
		h ^= uint64(c)
		h *= 0x100000001b3
	}
	return h
}

// refreshOut records an outbound packet on m: it refreshes the mapping and
// opens the filter towards dst.
func (nat *NAT) refreshOut(m *mapEntry, dst netip.AddrPort, now time.Duration) {
	m.lastOut, m.refresh = now, now
	m.nOut++
	if m.perm == nil {
		m.perm = make(map[netip.AddrPort]time.Duration, 4)
		m.permIP = make(map[netip.Addr]time.Duration, 4)
		m.permCap = 64
	}
	m.perm[dst] = now
	m.permIP[dst.Addr()] = now
	if len(m.perm) > m.permCap {
		// A mapping that sprays many destinations would otherwise keep every
		// stale permission; sweep them and let the threshold follow the live
		// set.
		if nat.timeout >= 0 {
			for k, t := range m.perm {
				if now-t >= nat.timeout {
					delete(m.perm, k)
				}
			}
			for k, t := range m.permIP {
				if now-t >= nat.timeout {
					delete(m.permIP, k)
				}
			}
		}
		m.permCap = max(64, 2*len(m.perm))
	}
	nat.lru.MoveToFront(m.elem)
}

func (nat *NAT) permits(f *natFam, m *mapEntry, src netip.AddrPort, now time.Duration) bool {
	switch f.rule(m.key.path).filtering {
	case EIF, Open:
		return true
	case ADF:
		t, ok := m.permIP[src.Addr()]
		return ok && nat.fresh(t, now)
	default:
		t, ok := m.perm[src]
		return ok && nat.fresh(t, now)
	}
}

// acceptInLocked filters an inbound packet whose destination is an external
// endpoint of f and, when it passes, rewrites p.dst to the internal endpoint.
func (nat *NAT) acceptInLocked(f *natFam, p *packet, now time.Duration) dropReason {
	m := f.byExt[p.dst]
	if m != nil && nat.expired(m, now) {
		nat.removeLocked(m)
		nat.cnt.expired++
		m = nil
	}
	if m == nil {
		if f.mode != modeTranslate && f.filtering == Open {
			p.dst = f.toInternal(p.dst)
			nat.cnt.in++
			return dropNone
		}
		return dropFiltered
	}
	if nat.scan != nil && nat.scan.bannedInternal(m.in.Addr(), now) {
		return dropBan
	}
	if !nat.permits(f, m, p.src, now) {
		return dropFiltered
	}
	nat.trackInLocked(f, m, p.src)
	m.nIn++
	m.lastIn = now
	if nat.cfg.RefreshOnInbound {
		m.refresh = now
		if _, ok := m.perm[p.src]; ok {
			m.perm[p.src] = now
		}
		if _, ok := m.permIP[p.src.Addr()]; ok {
			m.permIP[p.src.Addr()] = now
		}
		nat.lru.MoveToFront(m.elem)
	}
	p.dst = m.in
	nat.cnt.in++
	return dropNone
}

// trackInLocked records the flow an admitted inbound packet from src opened
// on an endpoint-dependent mapping m, as conntrack does: the reply from the
// internal endpoint to src, whose own key differs — the filtering (ADF,
// EIF, Open) admitted an endpoint the mapping was not made for — leaves
// through m instead of taking a new mapping, which the sender's filter
// would not admit. A flow the internal endpoint
// already has a mapping for keeps it, and a proxy route opens none
// (Route.Proxy).
func (nat *NAT) trackInLocked(f *natFam, m *mapEntry, src netip.AddrPort) {
	if r := f.rule(m.key.path); f.mode != modeTranslate || r.mapping == EIM || r.proxy || len(m.aliases) >= nat.cfg.MaxMappings {
		return
	}
	key, _ := nat.keyOut(f, m.in, src)
	if key == m.key || f.byKey[key] != nil {
		return
	}
	f.byKey[key] = m
	m.aliases = append(m.aliases, key)
}

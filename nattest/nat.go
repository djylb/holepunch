package nattest

import (
	"container/list"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// NAT is a simulated NAT device: a home router, a carrier-grade NAT or a
// stateful firewall. Create it with [Network.NAT] or [NAT.NAT]. All methods
// are safe for concurrent use.
type NAT struct {
	n         *Network
	name      string
	idx       int
	cfg       NATConfig // normalized; immutable
	parent    *realm
	parentNAT *NAT
	lan       *realm
	uplink    *link
	timeout   time.Duration // MappingTimeout; < 0 never expires
	inert     bool          // created after Network.Close: never forwards anything

	mu        sync.Mutex // guards everything below
	rng       *rand.Rand
	salt      uint64
	f4, f6    *natFam // nil when the family is not available
	lru       list.List
	blackhole time.Duration                 // network time until which everything is dropped
	upstream  func(dst netip.AddrPort) bool // DropUpstream's match; nil for none
	scan      *scanState
	flows     map[flowKey]*classFlow // the Classifier's flows; nil until the first
	flowCap   int
	cnt       natCounters

	drops dropCounters // also written by the uplink, outside mu
}

// natCounters are the NAT's event counters, guarded by NAT.mu.
type natCounters struct {
	created, expired, evicted uint64
	out, in                   uint64
	filtered, hairpin, bans   uint64
	noiseAllocs               uint64
}

func (nat *NAT) fam(v6 bool) *natFam {
	if v6 {
		return nat.f6
	}
	return nat.f4
}

func (nat *NAT) families() []*natFam {
	out := make([]*natFam, 0, 2)
	for _, f := range [...]*natFam{nat.f4, nat.f6} {
		if f != nil {
			out = append(out, f)
		}
	}
	return out
}

func (n *Network) newNAT(parent *realm, parentNAT *NAT, cfg NATConfig) *NAT {
	cfg = cfg.normalized()
	n.topo.Lock()
	defer n.topo.Unlock()
	idx := len(n.nats) + 1
	nat := &NAT{
		n: n, idx: idx, cfg: cfg, parent: parent, parentNAT: parentNAT,
		timeout: cfg.MappingTimeout,
		rng:     n.rng("nat", idx),
	}
	nat.salt = nat.rng.Uint64()
	nat.name = n.uniqueNATName(cfg.Name, idx)
	nat.lan = &realm{nat: nat, owners: make(map[netip.Addr]any)}
	nat.uplink = newLink(cfg.Uplink, &nat.drops, n.rng("nat-link", idx))
	if cfg.ScanDefense != nil {
		nat.scan = newScanState(*cfg.ScanDefense)
	}
	if n.closed.Load() || (parentNAT != nil && parentNAT.inert) {
		nat.inert = true
		nat.f4 = nat.newFam(false, modeTranslate)
		return nat
	}

	var ext4, ext6 []netip.Addr
	for _, a := range cfg.ExternalIPs {
		switch a = a.Unmap(); {
		case !a.IsValid():
		case a.Is4():
			ext4 = append(ext4, a)
		default:
			ext6 = append(ext6, a)
		}
	}

	if cfg.Mapping == Identity {
		nat.f4 = nat.newFam(false, modeIdentity)
	} else {
		f := nat.newFam(false, modeTranslate)
		f.lanPrefix = cfg.LANPrefix.Masked()
		if !f.lanPrefix.IsValid() || !f.lanPrefix.Addr().Is4() {
			f.lanPrefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(idx), 0, 0}), 16)
		}
		f.ext = n.natExternal(parent, false, ext4)
		nat.f4 = f
	}
	if v := cfg.IPv6; v != nil {
		nat.f6 = n.newFam6(nat, parent, *v, ext6)
	}
	for _, f := range nat.families() {
		for _, a := range f.ext {
			n.register(parent, a, nat)
		}
		if f.mode == modeTranslate && cfg.PortNoisePPS > 0 {
			f.noise.next = n.now() + nat.noiseGap()
		}
	}
	n.nats = append(n.nats, nat)
	return nat
}

// newFam6 sets up the IPv6 family of nat; topo is held.
func (n *Network) newFam6(nat *NAT, parent *realm, v IPv6Config, ext []netip.Addr) *natFam {
	if !parent.hasFamily(true) {
		panic("nattest: NAT " + nat.name + " has IPv6 but its parent realm has none")
	}
	switch v.Mode {
	case NAT66:
		f := nat.newFam(true, modeTranslate)
		f.lanPrefix = ulaSite(nat.idx)
		f.ext = n.natExternal(parent, true, ext)
		return f
	case NPTv6:
		if parent != n.core {
			panic("nattest: NPTv6 is only supported on NATs attached to the core")
		}
		f := nat.newFam(true, modeNPT)
		f.filtering = v.Firewall
		f.lanPrefix = ulaSite(nat.idx)
		n.nextSite++
		f.site = publicSite(n.nextSite)
		return f
	default: // NoNAT, and any unknown mode
		f := nat.newFam(true, modeIdentity)
		f.filtering = v.Firewall
		if parent == n.core {
			// A device on the core delegates a /64 of its own; deeper devices
			// share the address space of the realm above.
			n.nextSite++
			f.site = publicSite(n.nextSite)
		}
		return f
	}
}

func (n *Network) uniqueNATName(name string, idx int) string {
	if name == "" {
		name = fmt.Sprintf("nat%d", idx)
	}
	k := n.natNames[name] + 1
	n.natNames[name] = k
	if k > 1 {
		name = fmt.Sprintf("%s#%d", name, k)
	}
	return name
}

func (nat *NAT) newFam(v6 bool, mode famMode) *natFam {
	c := nat.cfg
	return &natFam{
		v6: v6, mode: mode,
		mapping: c.Mapping, filtering: c.Filtering, alloc: c.PortAlloc, routes: routeRules(c.Routes), step: c.PortStep,
		lo: int(c.PortRange[0]), hi: int(c.PortRange[1]),
		byKey:  make(map[mapKey]*mapEntry),
		byExt:  make(map[netip.AddrPort]*mapEntry),
		used:   make(map[netip.Addr]*portBitmap),
		cursor: make(map[netip.Addr]int),
	}
}

// natExternal validates explicit external addresses, or allocates one; topo
// is held.
func (n *Network) natExternal(parent *realm, v6 bool, explicit []netip.Addr) []netip.Addr {
	for _, a := range explicit {
		if n.ownedUp(parent, a) != nil {
			panic(fmt.Sprintf("nattest: external address %v already in use", a))
		}
	}
	if len(explicit) > 0 {
		return explicit
	}
	return []netip.Addr{n.allocAddr(parent, v6)}
}

// NAT attaches a NAT device inside this NAT's LAN, for example a home router
// behind a carrier-grade NAT: n.NAT(cgnat).NAT(home).
func (nat *NAT) NAT(cfg NATConfig) *NAT { return nat.n.newNAT(nat.lan, nat, cfg) }

// Host attaches a host to the NAT's LAN. Without arguments it gets an automatic
// IPv4 address, and an IPv6 one when the NAT has IPv6; pass
// netip.IPv4Unspecified() or netip.IPv6Unspecified() for an automatic address
// of one family, or explicit addresses. It panics if an explicit address is in
// use or its family is not available.
func (nat *NAT) Host(lan ...netip.Addr) *Host {
	if len(lan) == 0 {
		lan = []netip.Addr{netip.IPv4Unspecified()}
		if nat.f6 != nil {
			lan = append(lan, netip.IPv6Unspecified())
		}
	}
	return nat.n.newHost(nat.lan, nat, lan)
}

// ExternalIPs returns the current external addresses of the translated
// families; it is empty for a device that translates nothing (Identity,
// NoNAT, NPTv6).
func (nat *NAT) ExternalIPs() []netip.Addr {
	nat.mu.Lock()
	defer nat.mu.Unlock()
	return nat.externalLocked()
}

func (nat *NAT) externalLocked() []netip.Addr {
	var out []netip.Addr
	for _, f := range nat.families() {
		if f.mode == modeTranslate {
			out = append(out, f.ext...)
		}
	}
	return out
}

// ExpireAll drops every mapping, filter state and port-noise reservation, as
// a reboot of the device would. The Sequential cursors survive, so the next
// allocations continue where the old ones stopped.
func (nat *NAT) ExpireAll() {
	nat.mu.Lock()
	defer nat.mu.Unlock()
	nat.flushLocked(nil)
}

// Rebind replaces the external addresses, as after a WAN reconnect, and
// flushes the mappings of the affected families; packets to the old addresses
// are no longer routed. The addresses are grouped by family, and a translated
// family that gets none keeps its old ones, except that Rebind(nil) gives
// every translated family one fresh automatic address. It panics if an
// address is already in use.
func (nat *NAT) Rebind(ext []netip.Addr) {
	n := nat.n
	n.topo.Lock()
	defer n.topo.Unlock()
	nat.mu.Lock()
	defer nat.mu.Unlock()
	if nat.inert || n.closed.Load() {
		return
	}
	var byFam [2][]netip.Addr
	for _, a := range ext {
		switch a = a.Unmap(); {
		case !a.IsValid():
		case a.Is6():
			byFam[1] = append(byFam[1], a)
		default:
			byFam[0] = append(byFam[0], a)
		}
	}
	for _, addrs := range byFam { // validate before changing anything
		for _, a := range addrs {
			if o := n.ownedUp(nat.parent, a); o != nil && o != any(nat) {
				panic(fmt.Sprintf("nattest: external address %v already in use", a))
			}
		}
	}
	for i, f := range [...]*natFam{nat.f4, nat.f6} {
		if f == nil || f.mode != modeTranslate || (len(ext) > 0 && len(byFam[i]) == 0) {
			continue
		}
		for _, a := range f.ext {
			n.unregister(nat.parent, a)
		}
		next := byFam[i]
		if len(next) == 0 {
			next = []netip.Addr{n.allocAddr(nat.parent, f.v6)}
		}
		nat.flushLocked(f)
		clear(f.used)
		clear(f.cursor)
		f.ext = next
		for _, a := range next {
			n.register(nat.parent, a, nat)
		}
	}
}

// Blackhole silently drops everything that crosses the device, in both
// directions, for d. A non-positive d ends a blackhole.
func (nat *NAT) Blackhole(d time.Duration) {
	nat.mu.Lock()
	defer nat.mu.Unlock()
	if d <= 0 {
		nat.blackhole = 0
		return
	}
	nat.blackhole = nat.n.now() + d
}

// DropUpstream loses, from now on, every packet the NAT forwards toward
// its uplink whose destination match reports true, as a path that loses
// it beyond the device would: the packet is translated first, so it
// creates or refreshes its mapping and filter state like any other, and
// is counted as uplink loss. Packets looped back by hairpinning stay
// inside and are not matched. A nil match ends it. match is called
// without any lock of the network held and must not block.
func (nat *NAT) DropUpstream(match func(dst netip.AddrPort) bool) {
	nat.mu.Lock()
	defer nat.mu.Unlock()
	nat.upstream = match
}

// SetLink replaces the impairments of the NAT's uplink. Packets already in
// flight keep their delay.
func (nat *NAT) SetLink(l LinkConfig) { nat.uplink.set(l) }

// MappingInfo is a snapshot of one mapping, or of one flow of a firewall
// that translates nothing.
type MappingInfo struct {
	Internal netip.AddrPort `json:"internal"`
	External netip.AddrPort `json:"external"`
	// Remote is the destination part of the mapping key: zero for EIM, with
	// port 0 for ADM.
	Remote  netip.AddrPort `json:"remote,omitzero"`
	Created time.Time      `json:"created"`
	LastOut time.Time      `json:"last_out"`
	LastIn  time.Time      `json:"last_in,omitzero"`
	Expires time.Time      `json:"expires,omitzero"` // zero = never
	Out     uint64         `json:"out"`
	In      uint64         `json:"in"`
	// Permits lists the remote endpoints the mapping has sent to within
	// MappingTimeout, sorted: the filter state of ADF and APDF.
	Permits []netip.AddrPort `json:"permits,omitempty"`
}

// Mappings returns the live mappings, sorted by internal endpoint, remote and
// external endpoint.
func (nat *NAT) Mappings() []MappingInfo {
	n := nat.n
	nat.mu.Lock()
	defer nat.mu.Unlock()
	now := n.now()
	nat.purgeExpiredLocked(now)
	out := make([]MappingInfo, 0, nat.lru.Len())
	for e := nat.lru.Front(); e != nil; e = e.Next() {
		m := e.Value.(*mapEntry)
		mi := MappingInfo{
			Internal: m.in, External: m.ext, Remote: m.remote,
			Created: n.wall(m.created), LastOut: n.wall(m.lastOut), Out: m.nOut, In: m.nIn,
		}
		if m.nIn > 0 {
			mi.LastIn = n.wall(m.lastIn)
		}
		if nat.timeout >= 0 {
			mi.Expires = n.wall(m.refresh + nat.timeout)
		}
		for ep, t := range m.perm {
			if nat.fresh(t, now) {
				mi.Permits = append(mi.Permits, ep)
			}
		}
		slices.SortFunc(mi.Permits, netip.AddrPort.Compare)
		out = append(out, mi)
	}
	slices.SortFunc(out, func(a, b MappingInfo) int {
		if c := a.Internal.Compare(b.Internal); c != 0 {
			return c
		}
		if c := a.Remote.Compare(b.Remote); c != 0 {
			return c
		}
		return a.External.Compare(b.External)
	})
	return out
}

// Stats returns a snapshot of the NAT's counters, with expiry and port noise
// brought up to date first.
func (nat *NAT) Stats() NATStats {
	nat.mu.Lock()
	defer nat.mu.Unlock()
	now := nat.n.now()
	nat.purgeExpiredLocked(now)
	st := NATStats{
		MappingsCreated:  nat.cnt.created,
		MappingsExpired:  nat.cnt.expired,
		MappingsEvicted:  nat.cnt.evicted,
		MappingsActive:   nat.lru.Len(),
		PacketsOut:       nat.cnt.out,
		PacketsIn:        nat.cnt.in,
		FilteredInbound:  nat.cnt.filtered,
		HairpinDelivered: nat.cnt.hairpin,
		ScanBans:         nat.cnt.bans,
		Dropped:          nat.drops.snapshot(),
	}
	for _, f := range nat.families() {
		nat.realizeNoise(f, now)
		st.NoiseActive += f.noise.active()
	}
	st.NoiseAllocs = nat.cnt.noiseAllocs
	return st
}

// routeRules are the translations of a device's routes, path k at k-1.
func routeRules(rs []Route) []pathRule {
	out := make([]pathRule, len(rs))
	for i, r := range rs {
		out[i] = pathRule{mapping: r.Mapping, filtering: r.Filtering, alloc: r.PortAlloc, proxy: r.Proxy}
	}
	return out
}

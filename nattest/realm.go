package nattest

import (
	"net/netip"
)

// realm is one address space: the core or the LAN of a NAT device. Its
// owners map routes an address to the host that has it, or to the child NAT
// device that answers for it (a NAT's external address, or an address of an
// Identity / NPTv6 LAN behind it). The owners of every realm are guarded by
// Network.topo.
type realm struct {
	nat    *NAT               // router of this LAN; nil for the core
	owners map[netip.Addr]any // *Host or *NAT
}

func (r *realm) hasFamily(v6 bool) bool {
	return r.nat == nil || r.nat.fam(v6) != nil
}

func (n *Network) lookup(r *realm, a netip.Addr) any {
	n.topo.RLock()
	defer n.topo.RUnlock()
	return r.owners[a]
}

// Automatic public addresses come from the documentation and benchmarking
// ranges, which are global unicast but never routed on the real Internet:
// TEST-NET-3, TEST-NET-2 and TEST-NET-1 first, then 198.18.0.0/15; IPv6 sites
// are /64s of 2001:db8::/32.
func publicV4(i int) netip.Addr {
	blocks := [...][3]byte{{203, 0, 113}, {198, 51, 100}, {192, 0, 2}}
	if i < 254*len(blocks) {
		b := blocks[i/254]
		return netip.AddrFrom4([4]byte{b[0], b[1], b[2], byte(i%254 + 1)})
	}
	i -= 254 * len(blocks)
	return addrInPrefix(netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, 0, 0}), 15), uint64(i+1))
}

// publicSite returns the k-th public IPv6 /64, 2001:db8:x:k::/64.
func publicSite(k int) netip.Prefix {
	var a [16]byte
	a[0], a[1], a[2], a[3] = 0x20, 0x01, 0x0d, 0xb8
	a[4], a[5], a[6], a[7] = byte(k>>24), byte(k>>16), byte(k>>8), byte(k)
	return netip.PrefixFrom(netip.AddrFrom16(a), 64)
}

// ulaSite returns the unique local /64 of the idx-th NAT, fd00:0:idx::/64.
func ulaSite(idx int) netip.Prefix {
	var a [16]byte
	a[0] = 0xfd
	a[4], a[5] = byte(idx>>8), byte(idx)
	return netip.PrefixFrom(netip.AddrFrom16(a), 64)
}

// addrInPrefix returns the address at offset off from the start of p.
func addrInPrefix(p netip.Prefix, off uint64) netip.Addr {
	if p.Addr().Is4() {
		b := p.Addr().As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v += uint32(off)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := p.Addr().As16()
	lo := uint64(0)
	for i := 8; i < 16; i++ {
		lo = lo<<8 | uint64(b[i])
	}
	lo += off
	for i := 15; i >= 8; i-- {
		b[i] = byte(lo)
		lo >>= 8
	}
	return netip.AddrFrom16(b)
}

// allocAddr returns a free address of the given family in realm r; topo is
// held. A public host gets a whole IPv6 /64, like a real subscriber.
func (n *Network) allocAddr(r *realm, v6 bool) netip.Addr {
	if r.nat == nil {
		for {
			var a netip.Addr
			if v6 {
				n.nextSite++
				a = addrInPrefix(publicSite(n.nextSite), 1)
			} else {
				a = publicV4(n.nextPub4)
				n.nextPub4++
			}
			if r.owners[a] == nil {
				return a
			}
		}
	}
	f := r.nat.fam(v6)
	pool := f.lanPrefix
	if f.mode == modeIdentity {
		if !f.site.IsValid() {
			// An Identity LAN without its own site shares the parent's
			// address space.
			return n.allocAddr(r.nat.parent, v6)
		}
		pool = f.site
	}
	for {
		f.nextLAN++
		a := addrInPrefix(pool, f.nextLAN)
		if !pool.Contains(a) {
			panic("nattest: LAN address pool of " + r.nat.name + " exhausted")
		}
		if n.ownedUp(r, a) == nil {
			return a
		}
	}
}

// ownedUp reports who owns a in r or in a realm above r into which a is
// routed unchanged (Identity) or prefix-translated (NPTv6); topo is held.
func (n *Network) ownedUp(r *realm, a netip.Addr) any {
	for {
		if o := r.owners[a]; o != nil {
			return o
		}
		up, ok := r.upward(a)
		if !ok {
			return nil
		}
		r, a = r.nat.parent, up
	}
}

// register makes owner reachable at a in r and in every realm above r that
// routes a downwards through an Identity or NPTv6 device; topo is held.
func (n *Network) register(r *realm, a netip.Addr, owner any) {
	r.owners[a] = owner
	for {
		up, ok := r.upward(a)
		if !ok {
			return
		}
		nat := r.nat
		r, a = nat.parent, up
		r.owners[a] = nat
	}
}

// unregister undoes register; topo is held.
func (n *Network) unregister(r *realm, a netip.Addr) {
	delete(r.owners, a)
	for {
		up, ok := r.upward(a)
		if !ok {
			return
		}
		r, a = r.nat.parent, up
		delete(r.owners, a)
	}
}

// upward returns the address under which a, an address of r, is visible in
// the parent realm, and false when r's router translates a (or r is the
// core) so that a is not visible above.
func (r *realm) upward(a netip.Addr) (netip.Addr, bool) {
	if r.nat == nil {
		return netip.Addr{}, false
	}
	f := r.nat.fam(a.Is6())
	if f == nil {
		return netip.Addr{}, false
	}
	switch f.mode {
	case modeIdentity:
		return a, true
	case modeNPT:
		return f.nptOut(a), true
	default: // modeTranslate
		return netip.Addr{}, false
	}
}

// prefixBits returns the prefix length a host at a in r sees on its
// interface.
func (n *Network) prefixBits(r *realm, a netip.Addr) int {
	def := 24
	if a.Is6() {
		def = 64
	}
	if r.nat == nil {
		return def
	}
	f := r.nat.fam(a.Is6())
	switch {
	case f.mode == modeIdentity && f.site.IsValid():
		return 64
	case f.mode == modeIdentity:
		return n.prefixBits(r.nat.parent, a)
	case f.lanPrefix.Contains(a):
		return f.lanPrefix.Bits()
	}
	return def
}

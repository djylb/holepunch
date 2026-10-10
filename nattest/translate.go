package nattest

// This file holds the per-packet decisions of a NAT device. A packet crosses
// a device as one router hop: it needs a TTL above 1 to be forwarded, and only
// a forwarded packet creates or refreshes state, so a
// packet with TTL 1 dies at the first device without opening it.

// outcome is the result of an outbound translation.
type outcome uint8

const (
	outDropped outcome = iota
	outUp              // translated; continues in the parent realm
	outHairpin         // translated and looped back into the LAN
)

// outbound translates a packet leaving the NAT's LAN. The packet belongs to
// the NAT afterwards: it is dropped, or prepared for its next hop.
func (nat *NAT) outbound(p *packet) outcome {
	n := nat.n
	nat.mu.Lock()
	now := n.now() // under the lock, so that the NAT sees time in order
	// The family exists: a host has an address of a family only when its
	// NAT carries it, and a device answers only for addresses of its own
	// families.
	f := nat.fam(p.dst.Addr().Is6())
	// dropLocked counts and drops p and releases the lock.
	dropLocked := func(why dropReason) outcome {
		nat.drops.add(why)
		nat.mu.Unlock()
		n.drop(p, nat.name, why)
		return outDropped
	}
	switch {
	case nat.inert:
		return dropLocked(dropClosed)
	case now < nat.blackhole:
		return dropLocked(dropBlackhole)
	case p.ttl <= 1:
		return dropLocked(dropTTL)
	case nat.scan != nil && (nat.scan.bannedInternal(p.src.Addr(), now) || nat.scan.bannedExternal(p.dst.Addr(), now)):
		return dropLocked(dropBan)
	}
	hairpin := f.isExternal(p.dst.Addr())
	if hairpin && !nat.cfg.Hairpin {
		return dropLocked(dropNoHairpin)
	}
	m, why := nat.mapOut(f, p.src, p.dst, now)
	if m == nil {
		return dropLocked(why)
	}
	nat.refreshOut(m, p.dst, now)
	if nat.scan != nil && !hairpin && nat.scan.recordOut(p.src.Addr(), p.dst, now) {
		nat.cnt.bans++
		return dropLocked(dropBan)
	}
	p.src = m.ext
	p.ttl--
	nat.cnt.out++
	if !hairpin && nat.cfg.Classifier != nil && !nat.classifyLocked(p.src, p.dst, p.data, now) {
		// Cut beyond the device, after it mapped the packet (Classifier).
		return dropLocked(dropClassified)
	}
	if hairpin {
		// The looped packet is an inbound packet to the receiver's mapping
		// and passes the same filter as one from outside.
		if why = nat.acceptInLocked(f, p, now); why != dropNone {
			nat.countInboundDrop(why)
			nat.mu.Unlock()
			n.drop(p, nat.name, why)
			return outDropped
		}
		nat.cnt.hairpin++
		p.realm, p.act = nat.lan, actRoute
		nat.mu.Unlock()
		n.log.add(n, evHairpin, nat.name, p, dropNone)
		return outHairpin
	}
	p.realm = nat.parent
	p.act = actRoute
	if nat.parent == n.core {
		p.act = actEnterCore
	}
	upstream := nat.upstream
	nat.mu.Unlock()
	n.log.add(n, evOut, nat.name, p, dropNone)
	if upstream != nil && upstream(p.dst) {
		nat.drops.add(dropLoss) // lost beyond the device, after it mapped the packet
		n.drop(p, nat.name, dropLoss)
		return outDropped
	}
	return outUp
}

// inbound translates a packet arriving from the parent realm and reports
// whether it continues into the LAN; a dropped packet is released.
func (nat *NAT) inbound(p *packet) bool {
	n := nat.n
	nat.mu.Lock()
	now := n.now()
	f := nat.fam(p.dst.Addr().Is6()) // exists, as in outbound
	why := dropNone
	switch {
	case nat.inert:
		why = dropClosed
	case now < nat.blackhole:
		why = dropBlackhole
	case p.ttl <= 1:
		why = dropTTL
	case nat.scan != nil && nat.scan.bannedExternal(p.src.Addr(), now):
		why = dropBan
	}
	if why == dropNone {
		why = nat.acceptInLocked(f, p, now)
		if why == dropFiltered && nat.scan != nil && nat.scan.recordUnsolicited(p.src.Addr(), now) {
			nat.cnt.bans++
		}
	}
	if why != dropNone {
		nat.countInboundDrop(why)
		nat.mu.Unlock()
		n.drop(p, nat.name, why)
		return false
	}
	p.ttl--
	p.realm, p.act = nat.lan, actRoute
	nat.mu.Unlock()
	n.log.add(n, evIn, nat.name, p, dropNone)
	return true
}

// countInboundDrop counts a rejected inbound packet: filtering has its own
// counter (NATStats.FilteredInbound), everything else is a drop.
func (nat *NAT) countInboundDrop(why dropReason) {
	if why == dropFiltered {
		nat.cnt.filtered++
		return
	}
	nat.drops.add(why)
}

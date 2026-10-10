package nattest

import (
	"net/netip"
	"sync"
	"time"
)

// action is the next step of a packet.
type action uint8

const (
	actEnterCore action = iota + 1 // TTL and core link, then actRoute in the core
	actRoute                       // route by destination inside p.realm
	actNATIn                       // inbound translation at p.nat
	actDeliver                     // queue on a socket of p.host
)

// packet is one UDP datagram on its way through the network. Every NAT it
// crosses rewrites its addresses. A packet has exactly one owner at a time
// (the goroutine processing it, the scheduler heap or a socket's queue), so
// it needs no lock; it returns to the pool when it is read or dropped.
type packet struct {
	src, dst netip.AddrPort
	ttl      int
	data     []byte
	buf      []byte // pooled backing array of data

	act   action
	realm *realm
	nat   *NAT
	host  *Host
}

// maxPooledPayload keeps occasional jumbo payloads out of the pool.
const maxPooledPayload = 64 << 10

var packetPool = sync.Pool{New: func() any { return &packet{buf: make([]byte, 0, 2048)} }}

func newPacket(b []byte) *packet {
	p := packetPool.Get().(*packet)
	p.data = append(p.buf[:0], b...)
	if cap(p.data) <= maxPooledPayload {
		p.buf = p.data[:0]
	}
	return p
}

func (p *packet) clone() *packet {
	c := newPacket(p.data)
	c.src, c.dst, c.ttl = p.src, p.dst, p.ttl
	c.act, c.realm, c.nat, c.host = p.act, p.realm, p.nat, p.host
	return c
}

func (p *packet) release() {
	p.data = nil
	p.realm, p.nat, p.host = nil, nil, nil
	packetPool.Put(p)
}

// drop records and releases a packet.
func (n *Network) drop(p *packet, where string, why dropReason) {
	n.log.add(n, evDrop, where, p, why)
	p.release()
}

// process advances p hop by hop until it is delivered, dropped or has to
// wait for a link delay; it is then queued on the scheduler, which resumes it
// at its arrival time. Each hop is judged with the state of that moment, so a
// remote NAT sees the packet when it arrives, not when it was sent.
func (n *Network) process(p *packet) {
	for {
		switch p.act {
		case actEnterCore:
			if p.ttl <= n.coreHops {
				n.drops.add(dropTTL)
				n.drop(p, "core", dropTTL)
				return
			}
			p.ttl -= n.coreHops
			p.act, p.realm = actRoute, n.core
			if !n.traverse(p, n.coreLink, dirUp, "core") {
				return
			}
		case actRoute:
			if !n.route(p) {
				return
			}
		case actNATIn:
			if !p.nat.inbound(p) {
				return
			}
		default: // actDeliver
			p.host.deliver(p)
			return
		}
	}
}

// route moves p one step inside its realm: to a host of the realm, into a
// child NAT that answers for the destination, or out through the realm's own
// NAT. It reports whether p continues synchronously.
func (n *Network) route(p *packet) bool {
	switch o := n.lookup(p.realm, p.dst.Addr()).(type) {
	case *Host:
		p.act, p.host = actDeliver, o
		return true
	case *NAT:
		p.act, p.nat = actNATIn, o
		return n.traverse(p, o.uplink, dirDown, o.name)
	}
	nat := p.realm.nat
	if nat == nil {
		n.drops.add(dropNoRoute)
		n.drop(p, "core", dropNoRoute)
		return false
	}
	switch nat.outbound(p) {
	case outUp:
		return n.traverse(p, nat.uplink, dirUp, nat.name)
	case outHairpin:
		return true
	default: // outDropped
		return false
	}
}

// traverse applies a link to p. It reports whether p continues
// synchronously; otherwise p was dropped or queued and no longer belongs to
// the caller.
func (n *Network) traverse(p *packet, l *link, dir int, where string) bool {
	v := l.pass(n.now(), len(p.data), p.dst.Addr().Is6(), dir)
	if v.drop != dropNone {
		n.drop(p, where, v.drop)
		return false
	}
	if v.dup {
		c := p.clone()
		if v.dupDelay > 0 {
			n.schedule(c, v.dupDelay)
		} else {
			n.process(c)
		}
	}
	if v.delay > 0 {
		n.schedule(p, v.delay)
		return false
	}
	return true
}

// schedule queues p to resume after d.
func (n *Network) schedule(p *packet, d time.Duration) {
	if !n.sched.push(event{at: n.now() + d, p: p}) {
		n.drops.add(dropClosed)
		p.release()
	}
}

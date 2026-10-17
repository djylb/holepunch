package natprobe

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpsock"
)

// extraReadBuffer is the receive buffer of the extra-reply sockets, which are
// never read: the kernel need not keep much for them.
const extraReadBuffer = 1024

// listener is one observer socket. It serves one observer per address slot
// of its group: ids (og+k)*8 + pi for k < slots.
type listener struct {
	raw  net.PacketConn
	conn packetConn
	// msg is set on a wildcard socket that reports each datagram's
	// destination: replies leave from it.
	msg   msgConn
	fam   protocol.Family
	advs  []netip.Addr // the group's Advertise, by slot
	pool  *pool        // the group's extra-reply pool
	dead  atomic.Bool  // stopped after a reader-loop panic
	port  uint16
	id    uint8 // the observer id of its first slot, for names and logs
	og    uint8 // the observer group of its first slot
	slots uint8 // its group's address slots
	pi    uint8 // its port index in the group
	group uint8 // its config group
	alt   bool
	flags uint8 // slotAlt, slotPrivate, slotPublic
}

// serves reports whether aux, a probe's observer id, is one of l's.
func (l *listener) serves(aux uint16) bool {
	og := aux / portsPerGroup
	return aux%portsPerGroup == uint16(l.pi) && og >= uint16(l.og) && og < uint16(l.og)+uint16(l.slots)
}

// msgConn is the control-data interface of *net.UDPConn: the destination of
// a datagram read, the source of one written (udpsock).
type msgConn interface {
	ReadMsgUDPAddrPort(b, oob []byte) (n, oobn, flags int, addr netip.AddrPort, err error)
	WriteMsgUDPAddrPort(b, oob []byte, addr netip.AddrPort) (n, oobn int, err error)
}

// pool is a fixed set of extra-reply sockets of one group. They are only
// written to, and in turn, so the extra's source port varies.
type pool struct {
	conns []packetConn
	msgs  []msgConn // the same sockets, when they can name their source; nil otherwise
	ports []uint16
	next  atomic.Uint32
}

func (p *pool) usable() bool { return p != nil && len(p.conns) > 0 }

// pick returns the next socket in turn. The index is reduced in uint32: an
// int conversion first would turn negative on 32-bit platforms once the
// counter passes 2^31.
func (p *pool) pick() (packetConn, msgConn, uint16) {
	i := p.next.Add(1) % uint32(len(p.conns))
	var m msgConn
	if p.msgs != nil {
		m = p.msgs[i]
	}
	return p.conns[i], m, p.ports[i]
}

// bind opens the listeners and the pools of every group and hands each
// socket to g, so that a failure half way, or Close, closes what was opened.
func (s *Server) bind(g *life.Group) ([]*listener, [2]*pool, error) {
	var ls []*listener
	var alt [2]*pool
	og := 0
	for gi, grp := range s.cfg.Groups {
		fam := protocol.FamilyOf(grp.Bind)
		wildcard := grp.Bind.IsUnspecified()
		n := s.cfg.PortCount
		var flags uint8
		if grp.Alt {
			n, flags = 1, slotAlt
		}
		switch grp.Scope {
		case ScopeAuto: // each announced address's own (handle.Announce)
		case ScopePrivate:
			flags |= slotPrivate
		case ScopePublic:
			flags |= slotPublic
		}
		var group []*listener
		for pi := range n {
			port := 0
			if s.cfg.BasePort > 0 {
				port = s.cfg.BasePort + pi
			}
			id := uint8(og*portsPerGroup + pi)
			pc, lp, err := s.open(g, fmt.Sprintf("natprobe/listener[%d]", id), string(fam), netip.AddrPortFrom(grp.Bind, uint16(port)), 0)
			if err != nil {
				return nil, alt, err
			}
			if lp == 0 {
				if port == 0 {
					// The kernel chose a port the conn does not tell: the
					// observer could not be advertised.
					return nil, alt, fmt.Errorf("natprobe: listen %s %v: unknown local port", fam, grp.Bind)
				}
				lp = uint16(port)
			}
			l := &listener{id: id, og: uint8(og), slots: uint8(grp.Slots), pi: uint8(pi), group: uint8(gi), fam: fam,
				alt: grp.Alt, flags: flags, raw: pc, conn: adaptConn(pc), port: lp, advs: grp.Advertise}
			if wildcard {
				l.msg = dstConn(pc)
			}
			group = append(group, l)
		}
		p := &pool{}
		for k := range s.cfg.ExtraSockets {
			pc, port, err := s.open(g, fmt.Sprintf("natprobe/extra[%d/%d]", gi, k), string(fam), netip.AddrPortFrom(grp.Bind, 0), extraReadBuffer)
			if err != nil {
				return nil, alt, err
			}
			if port != 0 {
				p.conns = append(p.conns, adaptConn(pc))
				p.ports = append(p.ports, port)
				if m, ok := pc.(msgConn); ok && wildcard {
					p.msgs = append(p.msgs, m)
				}
			}
		}
		if len(p.msgs) != len(p.conns) {
			p.msgs = nil
		}
		for _, l := range group {
			l.pool = p
		}
		if grp.Alt {
			alt[famIndex(fam)] = p
		}
		ls = append(ls, group...)
		og += grp.Slots
	}
	return ls, alt, nil
}

// dstConn switches on the destination reports of a wildcard socket and
// returns it as a msgConn, or nil when it cannot report them: an injected
// conn without control data, or a system without the option. The conn's
// methods are its Listen's code, called inside a recover boundary.
func dstConn(pc net.PacketConn) msgConn {
	m, ok := pc.(msgConn)
	if !ok {
		return nil
	}
	var err error
	if life.Safe("natprobe/dstaddr", func() { err = udpsock.EnableDstAddr(pc) }) != nil || err != nil {
		return nil
	}
	return m
}

// open binds one socket through Listen, hands it to g, sets its receive
// buffer when readBuffer > 0 and returns it with its local port (0 when
// unknown). An injected Listen and every method of the conn it returns are
// the caller's code: they run inside recover boundaries, and a panic is a
// bind failure that Start reports, with the socket already owned by g so
// that Start's failure path closes it.
func (s *Server) open(g *life.Group, name, network string, laddr netip.AddrPort, readBuffer int) (pc net.PacketConn, port uint16, err error) {
	listen := s.cfg.Listen
	if listen == nil {
		listen = defaultListen
	}
	if perr := life.Safe("natprobe/listen", func() { pc, err = listen(network, laddr) }); perr != nil {
		return nil, 0, fmt.Errorf("natprobe: listen %s %v: %w", network, laddr, perr)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("natprobe: listen %s %v: %w", network, laddr, err)
	}
	if life.IsNil(pc) {
		return nil, 0, fmt.Errorf("natprobe: listen %s %v: nil conn", network, laddr)
	}
	if !g.Own(name, pc) {
		return nil, 0, fmt.Errorf("natprobe: server closed: %w", net.ErrClosed)
	}
	if perr := life.Safe("natprobe/listen", func() {
		if rb, ok := pc.(interface{ SetReadBuffer(int) error }); ok && readBuffer > 0 {
			_ = rb.SetReadBuffer(readBuffer)
		}
		port = localAddrPort(pc).Port()
	}); perr != nil {
		return nil, 0, fmt.Errorf("natprobe: listen %s %v: %w", network, laddr, perr)
	}
	return pc, port, nil
}

// wildcardFamilies returns the families of the wildcard groups on a host
// with at least two global addresses of that family: replies of a
// wildcard socket leave from the address the kernel routes by, which may not
// be the one the client probed.
func wildcardFamilies(groups []ObserverGroup, prefixes []netip.Prefix) []protocol.Family {
	var global [2]int
	for _, p := range prefixes {
		if a := p.Addr().Unmap(); nat.ScopeOf(a) == nat.ScopeGlobal {
			global[famIndex(protocol.FamilyOf(a))]++
		}
	}
	var out []protocol.Family
	for _, grp := range groups {
		fam := protocol.FamilyOf(grp.Bind)
		if grp.Bind.IsUnspecified() && global[famIndex(fam)] >= 2 && !slices.Contains(out, fam) {
			out = append(out, fam)
		}
	}
	return out
}

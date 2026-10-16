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
)

// extraReadBuffer is the receive buffer of the extra-reply sockets, which are
// never read: the kernel need not keep much for them.
const extraReadBuffer = 1024

// listener is one observer socket.
type listener struct {
	id    uint8 // observer id = group*8 + port index; checked against the probe's aux
	group uint8
	fam   protocol.Family
	alt   bool
	flags uint8 // slotAlt, slotPrivate
	raw   net.PacketConn
	conn  packetConn
	adv   netip.AddrPort // advertised address
	pool  *pool          // the group's extra-reply pool
	dead  atomic.Bool    // stopped after a reader-loop panic
}

// pool is a fixed set of extra-reply sockets of one group. They are only
// written to, and in turn, so the extra's source port varies.
type pool struct {
	conns []packetConn
	ports []uint16
	next  atomic.Uint32
}

func (p *pool) usable() bool { return p != nil && len(p.conns) > 0 }

// pick returns the next socket in turn. The index is reduced in uint32: an
// int conversion first would turn negative on 32-bit platforms once the
// counter passes 2^31.
func (p *pool) pick() (packetConn, uint16) {
	i := p.next.Add(1) % uint32(len(p.conns))
	return p.conns[i], p.ports[i]
}

// bind opens the listeners and the pools of every group and hands each
// socket to g, so that a failure half way, or Close, closes what was opened.
func (s *Server) bind(g *life.Group) ([]*listener, [2]*pool, error) {
	var ls []*listener
	var alt [2]*pool
	for gi, grp := range s.cfg.Groups {
		fam := protocol.FamilyOf(grp.Bind)
		n := s.cfg.PortCount
		var flags uint8
		if grp.Alt {
			n, flags = 1, slotAlt
		}
		if nat.ScopeOf(grp.Advertise) == nat.ScopePrivate {
			flags |= slotPrivate
		}
		var group []*listener
		for pi := range n {
			port := 0
			if s.cfg.BasePort > 0 {
				port = s.cfg.BasePort + pi
			}
			id := uint8(gi*portsPerGroup + pi)
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
			group = append(group, &listener{id: id, group: uint8(gi), fam: fam, alt: grp.Alt, flags: flags,
				raw: pc, conn: adaptConn(pc), adv: netip.AddrPortFrom(grp.Advertise, lp)})
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
			}
		}
		for _, l := range group {
			l.pool = p
		}
		if grp.Alt {
			alt[famIndex(fam)] = p
		}
		ls = append(ls, group...)
	}
	return ls, alt, nil
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

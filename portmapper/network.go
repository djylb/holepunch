package portmapper

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/udpsock"
)

// opener opens a request socket bound to local:0 for one request bounded by
// ctx. The protocol code gets Mapper.openRequest as an opener rather than the
// Mapper itself.
type opener func(ctx context.Context, local netip.Addr) (*reqConn, error)

// reqConn is a request socket: opened through Config.Network for a single
// request, used by a single goroutine, closed when the request ends. The end
// of the request's context closes it at once, which interrupts a blocked read
// or write. Its read deadline is only ever set by the goroutine that reads,
// to schedule retransmissions: a socket the library owns is interrupted by
// closing it, never by moving its deadline from another goroutine.
type reqConn struct {
	pc   net.PacketConn
	stop func() bool // unregisters the close on the end of ctx
	once sync.Once
}

// openRequest opens a request socket through Config.Network. It switches
// the Windows ICMP reports off on it: a gateway that does not speak PCP or
// NAT-PMP answers "port unreachable", which Windows would report on the
// socket's next read. A failed switch is ignored,
// since a conn that keeps its reports only ends that exchange early; a
// panic in the conn fails the request, like any other.
func (m *Mapper) openRequest(ctx context.Context, local netip.Addr) (*reqConn, error) {
	var pc net.PacketConn
	var err error
	if perr := life.Safe("Network.ListenPacket", func() {
		pc, err = m.cfg.Network.ListenPacket(ctx, "udp4", netip.AddrPortFrom(local, 0), purposePortmap)
	}); perr != nil {
		return nil, perr
	}
	if err == nil && !life.IsNil(pc) {
		err = life.Safe("udpsock.DisableICMPReports", func() { _ = udpsock.DisableICMPReports(pc) })
	}
	if err != nil {
		if !life.IsNil(pc) { // the switch panicked, or the Network broke its contract: do not leak the conn
			_ = life.Safe("PacketConn.Close", func() { _ = pc.Close() })
		}
		return nil, err
	}
	if life.IsNil(pc) {
		return nil, errNoConn
	}
	c := &reqConn{pc: pc}
	c.stop = context.AfterFunc(ctx, c.closeOnce)
	return c, nil
}

func (c *reqConn) closeOnce() {
	c.once.Do(func() { _ = life.Safe("PacketConn.Close", func() { _ = c.pc.Close() }) })
}

// Close ends the request: when it returns, the socket is closed.
func (c *reqConn) Close() {
	c.stop()
	c.closeOnce()
}

// outbound returns the local IPv4 address that routes out of the host.
func (m *Mapper) outbound(ctx context.Context) (netip.Addr, error) {
	var a netip.Addr
	var err error
	if perr := life.Safe("Network.OutboundAddr", func() { a, err = m.cfg.Network.OutboundAddr(ctx, "udp4") }); perr != nil {
		return netip.Addr{}, perr
	}
	if err != nil {
		// No route out means no default gateway either.
		return netip.Addr{}, fmt.Errorf("%w: outbound address: %w", ErrNoGateway, err)
	}
	if a = a.Unmap(); !a.Is4() || a.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("%w: no IPv4 outbound address (%s)", ErrUnsupported, a)
	}
	return a, nil
}

package e2e

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/internal/leak"
	"github.com/djylb/holepunch/nattest"
)

// errInjectedRead is the socket read error of the udp_read_error fault: not a
// timeout and not an ICMP-class error, so the library ends that socket's read
// loop.
var errInjectedRead = &net.OpError{Op: "read", Net: "udp", Err: syscall.EIO}

// clientNet is the Network of one client: a nattest Host behind a thin wrapper
// that can drop inbound packets by source (a silent peer: the NATs drop every
// packet from it), fail reads (the udp_read_error fault), run a hook on
// ListenPacket and SetHopLimit (user-implementation panics) and record the
// destination ports of every sent packet (port randomness, per-target counts).
// The wrapped conns keep exactly the capabilities of the Host's sockets that
// the library probes for (leak.Wrap), so the library takes the same code
// paths as on a bare Host; Host.MarkHandover finds the sockets by address.
type clientNet struct {
	h         *nattest.Host
	drop      atomic.Pointer[func(netip.AddrPort) bool]
	listen    atomic.Pointer[func(purpose string)]
	hop       atomic.Pointer[func(hops int)]
	sent      map[netip.AddrPort]int // packets per destination, while recording
	mu        sync.Mutex
	failReads atomic.Bool
	rec       bool
}

var _ holepunch.Network = (*clientNet)(nil)

func newClientNet(h *nattest.Host) *clientNet { return &clientNet{h: h} }

// dropFrom makes the sockets discard every inbound packet for which f is
// true; nil restores normal delivery.
func (c *clientNet) dropFrom(f func(netip.AddrPort) bool) {
	if f == nil {
		c.drop.Store(nil)
		return
	}
	c.drop.Store(&f)
}

// record starts counting packets per destination.
func (c *clientNet) record() {
	c.mu.Lock()
	c.rec, c.sent = true, map[netip.AddrPort]int{}
	c.mu.Unlock()
}

// sentTo returns a copy of the per-destination packet counts.
func (c *clientNet) sentTo() map[netip.AddrPort]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[netip.AddrPort]int, len(c.sent))
	for k, v := range c.sent {
		out[k] = v
	}
	return out
}

func (c *clientNet) noteSent(to netip.AddrPort) {
	c.mu.Lock()
	if c.rec {
		c.sent[netip.AddrPortFrom(to.Addr().Unmap(), to.Port())]++
	}
	c.mu.Unlock()
}

// ListenPacket opens a socket on the Host and wraps it (leak.Wrap).
func (c *clientNet) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	if f := c.listen.Load(); f != nil {
		(*f)(purpose)
	}
	pc, err := c.h.ListenPacket(ctx, network, laddr, purpose)
	if err != nil {
		return nil, err
	}
	return leak.Wrap(pc, leak.Hooks{
		ReadErr: func() error {
			if c.failReads.Load() {
				return errInjectedRead
			}
			return nil
		},
		Drop: func(from netip.AddrPort) bool {
			f := c.drop.Load()
			return f != nil && (*f)(from)
		},
		Sent: c.noteSent,
		HopLimit: func(hops int) {
			if f := c.hop.Load(); f != nil {
				(*f)(hops)
			}
		},
	}), nil
}

// InterfaceAddrs delegates to the Host.
func (c *clientNet) InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error) {
	return c.h.InterfaceAddrs()
}

// OutboundAddr delegates to the Host.
func (c *clientNet) OutboundAddr(ctx context.Context, network string) (netip.Addr, error) {
	return c.h.OutboundAddr(ctx, network)
}

// LookupNetIP delegates to the Host.
func (c *clientNet) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return c.h.LookupNetIP(ctx, network, host)
}

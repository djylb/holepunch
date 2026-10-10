package e2e

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/djylb/holepunch"
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
// The wrapped conns keep every capability the library probes for — HopLimiter,
// ReadFromUDPAddrPort, WriteToUDPAddrPort, SetReadBuffer and SetWriteBuffer —
// so the library takes the same code paths as on a bare Host; Host.MarkHandover
// finds the sockets by address.
type clientNet struct {
	h         *nattest.Host
	drop      atomic.Pointer[func(netip.AddrPort) bool]
	listen    atomic.Pointer[func(purpose string)]
	hop       atomic.Pointer[func(hops int)]
	sent      map[netip.AddrPort]int // packets per destination, while recording
	conns     []*wconn
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

// ListenPacket opens a socket on the Host and wraps it.
func (c *clientNet) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	if f := c.listen.Load(); f != nil {
		(*f)(purpose)
	}
	pc, err := c.h.ListenPacket(ctx, network, laddr, purpose)
	if err != nil {
		return nil, err
	}
	w := &wconn{inner: pc.(innerConn), net: c, purpose: purpose}
	c.mu.Lock()
	c.conns = append(c.conns, w)
	c.mu.Unlock()
	return w, nil
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

// innerConn is the method set of a nattest socket that the wrapper forwards.
type innerConn interface {
	net.PacketConn
	SetHopLimit(hops int) error
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

// wconn is one wrapped socket.
type wconn struct {
	inner   innerConn
	net     *clientNet
	purpose string
}

func (w *wconn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	for {
		if w.net.failReads.Load() {
			return 0, netip.AddrPort{}, errInjectedRead
		}
		n, from, err := w.inner.ReadFromUDPAddrPort(b)
		if err == nil {
			if f := w.net.drop.Load(); f != nil && (*f)(from) {
				continue
			}
		}
		return n, from, err
	}
}

func (w *wconn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := w.ReadFromUDPAddrPort(b)
	if err != nil {
		return n, nil, err
	}
	return n, net.UDPAddrFromAddrPort(from), nil
}

func (w *wconn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	n, err := w.inner.WriteToUDPAddrPort(b, addr)
	if err == nil {
		w.net.noteSent(addr)
	}
	return n, err
}

func (w *wconn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: errors.New("e2e: not a UDP address")}
	}
	return w.WriteToUDPAddrPort(b, ua.AddrPort())
}

func (w *wconn) SetHopLimit(hops int) error {
	if f := w.net.hop.Load(); f != nil {
		(*f)(hops)
	}
	return w.inner.SetHopLimit(hops)
}

func (w *wconn) Close() error                       { return w.inner.Close() }
func (w *wconn) LocalAddr() net.Addr                { return w.inner.LocalAddr() }
func (w *wconn) SetDeadline(t time.Time) error      { return w.inner.SetDeadline(t) }
func (w *wconn) SetReadDeadline(t time.Time) error  { return w.inner.SetReadDeadline(t) }
func (w *wconn) SetWriteDeadline(t time.Time) error { return w.inner.SetWriteDeadline(t) }
func (w *wconn) SetReadBuffer(bytes int) error      { return w.inner.SetReadBuffer(bytes) }
func (w *wconn) SetWriteBuffer(bytes int) error     { return w.inner.SetWriteBuffer(bytes) }

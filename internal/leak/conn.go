package leak

import (
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/djylb/holepunch/internal/netaddr"
)

// Hooks intercept the calls of a conn wrapped by Wrap; a nil hook passes
// the call through. The hooks run on the caller's goroutine and may run
// concurrently.
type Hooks struct {
	// ReadErr runs before every read; a non-nil error fails the read with it.
	ReadErr func() error
	// Drop runs on every packet read; true discards the packet and the read
	// goes on with the next one.
	Drop func(from netip.AddrPort) bool
	// Sent runs after every successful write, with its destination.
	Sent func(to netip.AddrPort)
	// HopLimit runs before SetHopLimit reaches the wrapped conn.
	HopLimit func(hops int)
	// Close runs on every Close, before it reaches the wrapped conn.
	Close func()
}

// Wrap returns pc with the hooks h. The result has ReadFromUDPAddrPort and
// WriteToUDPAddrPort — through ReadFrom and WriteTo when pc lacks them, the
// library's own fallback — and exactly the optional capabilities of pc the
// library probes for: HopLimiter, syscall.Conn, SetReadBuffer and
// SetWriteBuffer, so wrapping changes no optional capability the library
// probes for; the address-port methods are always there, as on the
// library's own sockets. The result is a pointer, so it is comparable (life.Group.Disown
// compares conns).
func Wrap(pc net.PacketConn, h Hooks) net.PacketConn {
	hc := &hookedConn{inner: pc, h: h}
	hc.udp, _ = pc.(addrPortConn)
	caps := capabilitiesOf(pc)
	if caps.hop != nil {
		caps.hop = hookedHop{inner: caps.hop, h: h.HopLimit}
	}
	return withCapabilities(hc, caps)
}

// addrPortConn is the allocation-free read and write of a UDP conn.
type addrPortConn interface {
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
}

// hookedConn is the conn of Wrap without its optional capabilities.
type hookedConn struct {
	inner net.PacketConn
	udp   addrPortConn // inner's, or nil
	h     Hooks
}

func (c *hookedConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	for {
		if c.h.ReadErr != nil {
			if err := c.h.ReadErr(); err != nil {
				return 0, netip.AddrPort{}, err
			}
		}
		n, from, err := c.read(b)
		if err == nil && c.h.Drop != nil && c.h.Drop(from) {
			continue
		}
		return n, from, err
	}
}

// read reads one packet from the wrapped conn.
func (c *hookedConn) read(b []byte) (int, netip.AddrPort, error) {
	if c.udp != nil {
		return c.udp.ReadFromUDPAddrPort(b)
	}
	n, addr, err := c.inner.ReadFrom(b)
	return n, netaddr.AddrPortOf(addr), err
}

func (c *hookedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := c.ReadFromUDPAddrPort(b)
	if err != nil {
		return n, nil, err
	}
	return n, net.UDPAddrFromAddrPort(from), nil
}

func (c *hookedConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	var (
		n   int
		err error
	)
	if c.udp != nil {
		n, err = c.udp.WriteToUDPAddrPort(b, addr)
	} else {
		n, err = c.inner.WriteTo(b, net.UDPAddrFromAddrPort(addr))
	}
	if err == nil && c.h.Sent != nil {
		c.h.Sent(addr)
	}
	return n, err
}

func (c *hookedConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		// Not a destination the hooks can name: the wrapped conn decides.
		return c.inner.WriteTo(b, addr)
	}
	return c.WriteToUDPAddrPort(b, ua.AddrPort())
}

// hookedHop is the HopLimiter of a wrapped conn that has one.
type hookedHop struct {
	inner HopLimiter
	h     func(hops int)
}

func (c hookedHop) SetHopLimit(hops int) error {
	if c.h != nil {
		c.h(hops)
	}
	return c.inner.SetHopLimit(hops)
}

// Close forwards every call, so that the wrapped conn keeps its own
// idempotency semantics.
func (c *hookedConn) Close() error {
	if c.h.Close != nil {
		c.h.Close()
	}
	return c.inner.Close()
}

func (c *hookedConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *hookedConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *hookedConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *hookedConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

type (
	readBufferSetter  interface{ SetReadBuffer(bytes int) error }
	writeBufferSetter interface{ SetWriteBuffer(bytes int) error }
)

// capabilities holds the optional interfaces of a conn; a nil field means the
// conn lacks that capability.
type capabilities struct {
	hop  HopLimiter
	sys  syscall.Conn
	rbuf readBufferSetter
	wbuf writeBufferSetter
}

func capabilitiesOf(pc net.PacketConn) capabilities {
	var c capabilities
	c.hop, _ = pc.(HopLimiter)
	c.sys, _ = pc.(syscall.Conn)
	c.rbuf, _ = pc.(readBufferSetter)
	c.wbuf, _ = pc.(writeBufferSetter)
	return c
}

// udpPacketConn is a net.PacketConn with the address-port calls.
type udpPacketConn interface {
	net.PacketConn
	addrPortConn
}

// withCapabilities returns base, address-port calls included, extended with
// exactly the capabilities present in c. Go cannot add methods at run time,
// so each of the 16 combinations is its own struct type; the embedded
// interfaces forward the calls. Pointers are returned so that the result is
// always comparable (life.Group.Disown compares conns).
func withCapabilities(base udpPacketConn, c capabilities) net.PacketConn {
	const (
		hop = 1 << iota
		sys
		rbuf
		wbuf
	)
	mask := 0
	if c.hop != nil {
		mask |= hop
	}
	if c.sys != nil {
		mask |= sys
	}
	if c.rbuf != nil {
		mask |= rbuf
	}
	if c.wbuf != nil {
		mask |= wbuf
	}
	type pc = udpPacketConn
	switch mask {
	case hop:
		return &struct {
			pc
			HopLimiter
		}{base, c.hop}
	case sys:
		return &struct {
			pc
			syscall.Conn
		}{base, c.sys}
	case hop | sys:
		return &struct {
			pc
			HopLimiter
			syscall.Conn
		}{base, c.hop, c.sys}
	case rbuf:
		return &struct {
			pc
			readBufferSetter
		}{base, c.rbuf}
	case hop | rbuf:
		return &struct {
			pc
			HopLimiter
			readBufferSetter
		}{base, c.hop, c.rbuf}
	case sys | rbuf:
		return &struct {
			pc
			syscall.Conn
			readBufferSetter
		}{base, c.sys, c.rbuf}
	case hop | sys | rbuf:
		return &struct {
			pc
			HopLimiter
			syscall.Conn
			readBufferSetter
		}{base, c.hop, c.sys, c.rbuf}
	case wbuf:
		return &struct {
			pc
			writeBufferSetter
		}{base, c.wbuf}
	case hop | wbuf:
		return &struct {
			pc
			HopLimiter
			writeBufferSetter
		}{base, c.hop, c.wbuf}
	case sys | wbuf:
		return &struct {
			pc
			syscall.Conn
			writeBufferSetter
		}{base, c.sys, c.wbuf}
	case hop | sys | wbuf:
		return &struct {
			pc
			HopLimiter
			syscall.Conn
			writeBufferSetter
		}{base, c.hop, c.sys, c.wbuf}
	case rbuf | wbuf:
		return &struct {
			pc
			readBufferSetter
			writeBufferSetter
		}{base, c.rbuf, c.wbuf}
	case hop | rbuf | wbuf:
		return &struct {
			pc
			HopLimiter
			readBufferSetter
			writeBufferSetter
		}{base, c.hop, c.rbuf, c.wbuf}
	case sys | rbuf | wbuf:
		return &struct {
			pc
			syscall.Conn
			readBufferSetter
			writeBufferSetter
		}{base, c.sys, c.rbuf, c.wbuf}
	case hop | sys | rbuf | wbuf:
		return &struct {
			pc
			HopLimiter
			syscall.Conn
			readBufferSetter
			writeBufferSetter
		}{base, c.hop, c.sys, c.rbuf, c.wbuf}
	}
	return base
}

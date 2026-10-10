package leak

import (
	"net"
	"syscall"
)

// trackedConn forwards the net.PacketConn methods to the wrapped conn and
// reports its first Close to the owner.
type trackedConn struct {
	net.PacketConn
	owner   *TrackingNetwork
	purpose string
}

// Close closes the wrapped conn. Every call is forwarded so that the wrapped
// conn keeps its own idempotency semantics; only the first is counted.
func (c *trackedConn) Close() error {
	c.owner.closed(c)
	return c.PacketConn.Close()
}

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

// withCapabilities returns base extended with exactly the capabilities
// present in c. Go cannot add methods at run time, so each of the 16
// combinations is its own struct type; the embedded interfaces forward the
// calls to the wrapped conn. Pointers are returned so that the result is
// always comparable (life.Group.Disown compares conns).
func withCapabilities(base net.PacketConn, c capabilities) net.PacketConn {
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
	type pc = net.PacketConn
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

package nattest

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// defaultHopLimit is the TTL of a socket that never called SetHopLimit.
	defaultHopLimit = 64
	// maxUDPPayload4 and maxUDPPayload6 are the largest UDP payloads of an
	// IPv4 and an IPv6 datagram.
	maxUDPPayload4 = 65507
	maxUDPPayload6 = 65527
)

// family bits of conn.fams.
const (
	famV4 uint8 = 1 << iota
	famV6
)

func famBit(v6 bool) uint8 {
	if v6 {
		return famV6
	}
	return famV4
}

// conn is the UDP socket returned by Host.ListenPacket and Host.Listen. Next
// to net.PacketConn it implements SetHopLimit (holepunch.HopLimiter),
// ReadFromUDPAddrPort and WriteToUDPAddrPort (the allocation-free path
// natprobe uses) and SetReadBuffer/SetWriteBuffer. Every exported method
// except LocalAddr counts towards HostStats.WritesAfterHandover once the
// socket is marked; the view returned by Host.MarkHandover calls the
// unexported implementations and is not counted.
type conn struct {
	h       *Host
	purpose string
	fams    uint8      // famV4 | famV6
	ip      netip.Addr // bound address; invalid for a wildcard
	port    uint16
	rec     *socketRecord

	inbox   chan *packet
	closing chan struct{} // closed by close
	closed  atomic.Bool
	once    sync.Once
	rd, wd  deadline

	hops     atomic.Int32 // 0 = defaultHopLimit
	handover atomic.Bool
	rbuf     atomic.Int64 // SetReadBuffer limit in bytes; 0 = packets only
	queued   atomic.Int64 // bytes in inbox
}

func (c *conn) localAP() netip.AddrPort {
	ip := c.ip
	if !ip.IsValid() {
		ip = netip.IPv6Unspecified()
		if c.fams == famV4 {
			ip = netip.IPv4Unspecified()
		}
	}
	return netip.AddrPortFrom(ip, c.port)
}

func (c *conn) opErr(op string, addr netip.AddrPort, err error) error {
	e := &net.OpError{Op: op, Net: "udp", Source: net.UDPAddrFromAddrPort(c.localAP()), Err: err}
	if addr.IsValid() {
		e.Addr = net.UDPAddrFromAddrPort(addr)
	}
	return e
}

// touch counts a call on a socket after its handover.
func (c *conn) touch() {
	if c.handover.Load() {
		c.h.stats.afterHandover.Add(1)
	}
}

func (c *conn) readFrom(b []byte) (int, netip.AddrPort, error) {
	if c.closed.Load() {
		return 0, netip.AddrPort{}, c.opErr("read", netip.AddrPort{}, net.ErrClosed)
	}
	rd := c.rd.wait()
	if isClosed(rd) {
		// An expired deadline wins over queued data, as on an OS socket.
		return 0, netip.AddrPort{}, c.opErr("read", netip.AddrPort{}, os.ErrDeadlineExceeded)
	}
	var p *packet
	select {
	case p = <-c.inbox:
	default:
		select {
		case p = <-c.inbox:
		case <-c.closing:
			return 0, netip.AddrPort{}, c.opErr("read", netip.AddrPort{}, net.ErrClosed)
		case <-rd:
			return 0, netip.AddrPort{}, c.opErr("read", netip.AddrPort{}, os.ErrDeadlineExceeded)
		}
	}
	n := copy(b, p.data) // a short buffer truncates, as on Linux
	src := p.src
	c.queued.Add(-int64(len(p.data)))
	p.release()
	return n, src, nil
}

func (c *conn) writeTo(b []byte, dst netip.AddrPort) (int, error) {
	h := c.h
	if c.closed.Load() {
		return 0, c.opErr("write", dst, net.ErrClosed)
	}
	if c.wd.expired() {
		return 0, c.opErr("write", dst, os.ErrDeadlineExceeded)
	}
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	ip := dst.Addr()
	if !ip.IsValid() || ip.IsUnspecified() || dst.Port() == 0 {
		return 0, c.opErr("write", dst, syscall.EINVAL)
	}
	v6 := ip.Is6()
	if c.fams&famBit(v6) == 0 || (c.ip.IsValid() && c.ip.Is6() != v6) {
		return 0, c.opErr("write", dst, syscall.EAFNOSUPPORT)
	}
	if (!v6 && len(b) > maxUDPPayload4) || len(b) > maxUDPPayload6 {
		return 0, c.opErr("write", dst, syscall.EMSGSIZE)
	}
	if !ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsPrivate() {
		return 0, c.opErr("write", dst, syscall.ENETUNREACH)
	}
	if err := h.takeWriteFail(c.purpose); err != nil {
		h.stats.injectedWrite.Add(1)
		return 0, c.opErr("write", dst, err)
	}
	local := ip.IsLoopback() || h.owns(ip)
	srcIP := c.ip
	if !srcIP.IsValid() {
		srcIP = ip // loopback and own addresses answer from themselves
		if !local {
			srcIP = h.addrOf(v6)
		}
		if !srcIP.IsValid() {
			return 0, c.opErr("write", dst, syscall.ENETUNREACH)
		}
	}
	n := h.n
	if n.closed.Load() {
		return 0, c.opErr("write", dst, net.ErrClosed)
	}
	h.stats.recordSend(n, c.rec, dst, b)
	n.sent.Add(1)
	p := newPacket(b)
	p.src = netip.AddrPortFrom(srcIP, c.port)
	p.dst = dst
	p.ttl = c.hopLimit()
	n.log.add(n, evSend, h.name, p, dropNone)
	switch {
	case local:
		p.act, p.host = actDeliver, h
	case h.realm == n.core:
		p.act = actEnterCore
	default:
		p.act, p.realm = actRoute, h.realm
	}
	n.process(p)
	return len(b), nil
}

func (c *conn) hopLimit() int {
	if v := c.hops.Load(); v > 0 {
		return int(v)
	}
	return defaultHopLimit
}

func (c *conn) setHopLimit(hops int) error {
	if hops < 0 || hops > 255 {
		return c.opErr("set", netip.AddrPort{}, syscall.EINVAL)
	}
	if c.closed.Load() {
		return c.opErr("set", netip.AddrPort{}, net.ErrClosed)
	}
	c.hops.Store(int32(hops))
	c.h.stats.setHopLimit(c.rec, hops)
	return nil
}

// enqueue queues p for reading; it reports the reason when it cannot.
func (c *conn) enqueue(p *packet) dropReason {
	if c.closed.Load() {
		return dropNoSocket
	}
	size := int64(len(p.data))
	if rb := c.rbuf.Load(); rb > 0 && c.queued.Load()+size > rb {
		return dropInboxFull
	}
	c.queued.Add(size)
	select {
	case c.inbox <- p:
		return dropNone
	default:
		c.queued.Add(-size)
		return dropInboxFull
	}
}

func (c *conn) close() error {
	first := false
	c.once.Do(func() {
		first = true
		c.closed.Store(true)
		close(c.closing)
		c.rd.stop()
		c.wd.stop()
		c.h.unbind(c)
		c.h.stats.closeSocket(c.rec)
		for {
			select {
			case p := <-c.inbox:
				p.release()
			default:
				return
			}
		}
	})
	if !first {
		return c.opErr("close", netip.AddrPort{}, net.ErrClosed)
	}
	return nil
}

func (c *conn) setDeadline(read, write bool, t time.Time) error {
	if c.closed.Load() {
		return c.opErr("set", netip.AddrPort{}, net.ErrClosed)
	}
	if read {
		c.rd.set(c.h.n, t)
	}
	if write {
		c.wd.set(c.h.n, t)
	}
	return nil
}

func (c *conn) setReadBuffer(bytes int) error {
	if c.closed.Load() {
		return c.opErr("set", netip.AddrPort{}, net.ErrClosed)
	}
	if bytes > 0 {
		c.rbuf.Store(int64(bytes))
	}
	return nil
}

func (c *conn) setWriteBuffer() error {
	if c.closed.Load() {
		return c.opErr("set", netip.AddrPort{}, net.ErrClosed)
	}
	return nil
}

func toAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a == nil {
			return netip.AddrPort{}, false
		}
		return a.AddrPort(), true
	case nil:
		return netip.AddrPort{}, false
	default:
		ap, err := netip.ParseAddrPort(a.String())
		return ap, err == nil
	}
}

func (c *conn) writeToAddr(b []byte, addr net.Addr) (int, error) {
	ap, ok := toAddrPort(addr)
	if !ok {
		return 0, &net.OpError{Op: "write", Net: "udp", Source: net.UDPAddrFromAddrPort(c.localAP()), Addr: addr, Err: syscall.EINVAL}
	}
	return c.writeTo(b, ap)
}

func (c *conn) readFromAddr(b []byte) (int, net.Addr, error) {
	n, ap, err := c.readFrom(b)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

// LocalAddr returns the bound address; a wildcard socket reports the
// unspecified address of its family.
func (c *conn) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(c.localAP()) }

// ReadFrom implements net.PacketConn.
func (c *conn) ReadFrom(b []byte) (int, net.Addr, error) { c.touch(); return c.readFromAddr(b) }

// ReadFromUDPAddrPort is ReadFrom without allocating an address.
func (c *conn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	c.touch()
	return c.readFrom(b)
}

// WriteTo implements net.PacketConn. It never blocks: the packet is
// translated by the first NAT, and delivered when every link on its path has
// zero delay, before WriteTo returns.
func (c *conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.touch()
	return c.writeToAddr(b, addr)
}

// WriteToUDPAddrPort is WriteTo with a netip destination.
func (c *conn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	c.touch()
	return c.writeTo(b, addr)
}

// Close closes the socket; a second Close returns an error wrapping
// net.ErrClosed.
func (c *conn) Close() error { c.touch(); return c.close() }

// SetDeadline sets both deadlines.
func (c *conn) SetDeadline(t time.Time) error { c.touch(); return c.setDeadline(true, true, t) }

// SetReadDeadline implements net.PacketConn on the network's clock.
func (c *conn) SetReadDeadline(t time.Time) error { c.touch(); return c.setDeadline(true, false, t) }

// SetWriteDeadline implements net.PacketConn on the network's clock. Writes
// never block, so only an expired deadline has an effect.
func (c *conn) SetWriteDeadline(t time.Time) error { c.touch(); return c.setDeadline(false, true, t) }

// SetHopLimit sets the IP TTL / hop limit of later packets, 1 to 255; 0
// restores the default of 64 (holepunch.HopLimiter).
func (c *conn) SetHopLimit(hops int) error { c.touch(); return c.setHopLimit(hops) }

// SetReadBuffer limits the bytes waiting to be read; packets beyond it are
// dropped as DroppedInboxFull. The queue also holds at most 1024 packets.
func (c *conn) SetReadBuffer(bytes int) error { c.touch(); return c.setReadBuffer(bytes) }

// SetWriteBuffer is accepted and has no effect, since writes never block.
func (c *conn) SetWriteBuffer(_ int) error { c.touch(); return c.setWriteBuffer() }

// callerConn is the view of a socket returned by Host.MarkHandover, through
// which the application uses the socket after the handover; its calls are not
// counted as WritesAfterHandover.
type callerConn struct{ c *conn }

func (w callerConn) LocalAddr() net.Addr                       { return w.c.LocalAddr() }
func (w callerConn) ReadFrom(b []byte) (int, net.Addr, error)  { return w.c.readFromAddr(b) }
func (w callerConn) WriteTo(b []byte, a net.Addr) (int, error) { return w.c.writeToAddr(b, a) }
func (w callerConn) Close() error                              { return w.c.close() }
func (w callerConn) SetDeadline(t time.Time) error             { return w.c.setDeadline(true, true, t) }
func (w callerConn) SetReadDeadline(t time.Time) error         { return w.c.setDeadline(true, false, t) }
func (w callerConn) SetWriteDeadline(t time.Time) error        { return w.c.setDeadline(false, true, t) }
func (w callerConn) SetHopLimit(hops int) error                { return w.c.setHopLimit(hops) }
func (w callerConn) SetReadBuffer(bytes int) error             { return w.c.setReadBuffer(bytes) }
func (w callerConn) SetWriteBuffer(_ int) error                { return w.c.setWriteBuffer() }

func (w callerConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	return w.c.readFrom(b)
}

func (w callerConn) WriteToUDPAddrPort(b []byte, a netip.AddrPort) (int, error) {
	return w.c.writeTo(b, a)
}

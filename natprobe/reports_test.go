package natprobe

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
)

// ICMP reports are not read failures: a listener whose reads keep returning
// them counts none, never pauses for them, and answers the next probe.
func TestServerSkipsICMPReports(t *testing.T) {
	var left atomic.Int64
	left.Store(4 * readErrorBurst)
	listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
		c, err := defaultListen(network, laddr)
		if err != nil {
			return nil, err
		}
		return &reportConn{PacketConn: c, left: &left}, nil
	}
	reg := NewRegistry(RegistryConfig{})
	s := startServer(t, ServerConfig{Registry: reg, Listen: listen, ReadersPerListener: 1})
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	if reps := c.exchange(observerAddr(t, s, 0), probeOpts{obs: 0}, 1); len(reps) != 1 {
		t.Fatalf("%d replies after the reports; stats %+v", len(reps), s.Stats())
	}
	if left.Load() > 0 {
		t.Fatalf("%d reports never read", left.Load())
	}
	if st := s.Stats(); st.ReadErrors != 0 {
		t.Fatalf("reports counted as read errors: %d", st.ReadErrors)
	}
}

// reportConn fails its first reads with "connection reset", the way Windows
// reports an ICMP "port unreachable" on a socket that keeps its reports on.
type reportConn struct {
	net.PacketConn
	left *atomic.Int64
}

func (c *reportConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.left.Add(-1) >= 0 {
		return 0, nil, &net.OpError{Op: "read", Net: "udp4", Err: os.NewSyscallError("recvfrom", syscall.ECONNRESET)}
	}
	return c.PacketConn.ReadFrom(b)
}

// A datagram longer than the read buffer, which Windows reports as an error
// with the truncated bytes, is a foreign packet, not a read failure: a flood
// of them never pauses the reader, and the next probe is answered. Each conn
// has its own flood, so the single reader of the probed listener has counted
// all of its own before it reads the probe.
func TestServerOversizedDatagrams(t *testing.T) {
	const oversized = 4 * readErrorBurst
	listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
		c, err := defaultListen(network, laddr)
		if err != nil {
			return nil, err
		}
		tc := &truncatingConn{PacketConn: c}
		tc.left.Store(oversized)
		return tc, nil
	}
	reg := NewRegistry(RegistryConfig{})
	s := startServer(t, ServerConfig{Registry: reg, Listen: listen, ReadersPerListener: 1})
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	if reps := c.exchange(observerAddr(t, s, 0), probeOpts{obs: 0}, 1); len(reps) != 1 {
		t.Fatalf("%d replies after the oversized datagrams; stats %+v", len(reps), s.Stats())
	}
	st := s.Stats()
	if st.ReadErrors != 0 || st.Foreign < oversized || st.PacketsIn < oversized+1 || st.BytesIn < oversized*2048 {
		t.Fatalf("stats %+v", st)
	}
}

// truncatingConn's first reads return a full buffer and an error, the way
// Windows reports a datagram longer than the buffer (WSAEMSGSIZE).
type truncatingConn struct {
	net.PacketConn
	left atomic.Int64
}

func (c *truncatingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.left.Add(-1) >= 0 {
		return len(b), nil, &net.OpError{Op: "read", Net: "udp4", Err: errors.New("message too long")}
	}
	return c.PacketConn.ReadFrom(b)
}

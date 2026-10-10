package natprobe

import (
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
	c.send(observerAddr(t, s, 0), probeOpts{obs: 0})
	if reps := c.await(1); len(reps) != 1 {
		t.Fatalf("%d replies after the reports", len(reps))
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

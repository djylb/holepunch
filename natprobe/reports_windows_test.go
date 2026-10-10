package natprobe

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/udpicmp"
)

// A reply to a client that went away comes back as ICMP "port unreachable".
// Windows reports it on the listener's next read unless the report is
// switched off; either way the reader keeps going and answers the next
// probe. The default Listen switches the reports
// off; an injected Listen may not, and the reader skips them.
func TestListenerSurvivesPortUnreachable(t *testing.T) {
	t.Run("default listen", func(t *testing.T) {
		reg := NewRegistry(RegistryConfig{})
		s := startServer(t, ServerConfig{Registry: reg, ReadersPerListener: 1})
		probeAfterUnreachable(t, s, reg, nil)
	})
	t.Run("injected listen with reports on", func(t *testing.T) {
		var seen atomic.Int64
		listen := func(network string, laddr netip.AddrPort) (net.PacketConn, error) {
			c, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(laddr))
			if err != nil {
				return nil, err
			}
			if err := udpicmp.EnableReports(c); err != nil {
				_ = c.Close()
				return nil, err
			}
			return &seenConn{PacketConn: c, seen: &seen}, nil
		}
		reg := NewRegistry(RegistryConfig{})
		s := startServer(t, ServerConfig{Registry: reg, Listen: listen, ReadersPerListener: 1})
		probeAfterUnreachable(t, s, reg, &seen)
	})
}

// probeAfterUnreachable sends from observer 0's socket to a closed port,
// waits for the report when seen counts them, and then expects observer 0
// to answer a probe with no read error counted.
func probeAfterUnreachable(t *testing.T, s *Server, reg *Registry, seen *atomic.Int64) {
	t.Helper()
	obs := observerAddr(t, s, 0)
	var l *listener
	for _, x := range s.listeners {
		if x.adv == obs {
			l = x
		}
	}
	if l == nil {
		t.Fatal("no listener for observer 0")
	}
	closed := closedPort(t)
	if _, err := l.raw.WriteTo([]byte("gone"), net.UDPAddrFromAddrPort(closed)); err != nil {
		t.Fatal(err)
	}
	if seen != nil {
		deadline := time.Now().Add(waitBound(t))
		for seen.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if seen.Load() == 0 {
			t.Fatal("no ICMP report reached the reader")
		}
	}
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	c.send(obs, probeOpts{obs: 0})
	if reps := c.await(1); len(reps) != 1 {
		t.Fatalf("%d replies after port unreachable", len(reps))
	}
	if st := s.Stats(); st.ReadErrors != 0 || st.DeadListeners != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// seenConn counts the ICMP reports its reads return.
type seenConn struct {
	net.PacketConn
	seen *atomic.Int64
}

func (c *seenConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(b)
	if udpicmp.IsReport(err) {
		c.seen.Add(1)
	}
	return n, a, err
}

// closedPort returns a loopback port that nothing listens on.
func closedPort(t *testing.T) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo4, 0)))
	if err != nil {
		t.Fatal(err)
	}
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = c.Close()
	return ap
}

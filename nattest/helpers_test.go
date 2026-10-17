package nattest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/clock"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// newNet creates a network that is closed at the end of the test; a failed
// test logs the beginning of its dump.
func newNet(t testing.TB, opts ...Option) *Network {
	t.Helper()
	n := NewNetwork(opts...)
	t.Cleanup(func() {
		if t.Failed() {
			var sb strings.Builder
			_ = n.Dump(&sb)
			s := sb.String()
			if len(s) > 8000 {
				s = s[:8000] + "\n...(truncated)"
			}
			t.Logf("dump:\n%s", s)
		}
		if err := n.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return n
}

// fakeNet creates a network driven by a fake clock.
func fakeNet(t testing.TB, opts ...Option) (*Network, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(t, time.Time{})
	return newNet(t, append([]Option{WithClock(clk)}, opts...)...), clk
}

// udp is the method set of the sockets of a Host.
type udp interface {
	net.PacketConn
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	SetHopLimit(int) error
}

// listen opens a wildcard IPv4 socket on port.
func listen(t testing.TB, h *Host, port uint16) udp {
	t.Helper()
	return listenOn(t, h, "udp4", netip.AddrPortFrom(netip.Addr{}, port))
}

func listenOn(t testing.TB, h *Host, network string, laddr netip.AddrPort) udp {
	t.Helper()
	c, err := h.ListenPacket(context.Background(), network, laddr, "test")
	if err != nil {
		t.Fatalf("listen %s %v: %v", network, laddr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(udp)
}

func send(t testing.TB, c udp, dst netip.AddrPort, payload string) {
	t.Helper()
	if _, err := c.WriteToUDPAddrPort([]byte(payload), dst); err != nil {
		t.Fatalf("write to %v: %v", dst, err)
	}
}

// queued reports how many packets wait in c's receive queue.
func queued(c udp) int {
	switch v := c.(type) {
	case *conn:
		return len(v.inbox)
	case callerConn:
		return len(v.c.inbox)
	}
	panic("not a nattest socket")
}

// recvNow reads a packet that must already be queued: zero-delay paths
// deliver inside WriteTo, and a fake clock delivers inside Advance.
func recvNow(t testing.TB, c udp) (string, netip.AddrPort) {
	t.Helper()
	if queued(c) == 0 {
		t.Fatalf("no packet queued on %v", c.LocalAddr())
	}
	b := make([]byte, 65536)
	n, src, err := c.ReadFromUDPAddrPort(b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b[:n]), src
}

func expectNone(t testing.TB, c udp) {
	t.Helper()
	if k := queued(c); k != 0 {
		t.Fatalf("expected no packet on %v, have %d", c.LocalAddr(), k)
	}
}

// recvWait reads with a real-time timeout.
func recvWait(t testing.TB, c udp, d time.Duration) (string, netip.AddrPort) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	b := make([]byte, 65536)
	n, src, err := c.ReadFromUDPAddrPort(b)
	if err != nil {
		t.Fatalf("read on %v: %v", c.LocalAddr(), err)
	}
	return string(b[:n]), src
}

// drain reads every queued packet and returns how many there were.
func drain(c udp) int {
	k := 0
	b := make([]byte, 65536)
	for queued(c) > 0 {
		_, _, _ = c.ReadFromUDPAddrPort(b)
		k++
	}
	return k
}

func ext(t testing.TB, nat *NAT) netip.Addr {
	t.Helper()
	ips := nat.ExternalIPs()
	if len(ips) == 0 {
		t.Fatalf("%s has no external address", nat.name)
	}
	return ips[0]
}

// srcAt sends a probe from c to obs and returns the source the observer
// sees: c's mapping towards obs.
func srcAt(t testing.TB, c, obs udp) netip.AddrPort {
	t.Helper()
	send(t, c, addrOf(obs), "probe")
	_, src := recvNow(t, obs)
	return src
}

// srcAtAfter is srcAt on a network with link delays driven by clk.
func srcAtAfter(t testing.TB, clk *clock.Fake, c, obs udp) netip.AddrPort {
	t.Helper()
	send(t, c, addrOf(obs), "probe")
	clk.Advance(time.Second)
	_, src := recvNow(t, obs)
	return src
}

// observer creates a public host listening on its IPv4 address at port.
func observer(t testing.TB, n *Network, port uint16) (*Host, udp) {
	t.Helper()
	h := n.PublicHost(netip.IPv4Unspecified())
	return h, listenOn(t, h, "udp4", netip.AddrPortFrom(h.Addrs()[0], port))
}

func addrOf(c net.PacketConn) netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }

func isClosedErr(err error) bool { return errors.Is(err, net.ErrClosed) }

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// mustPanic runs f and fails the test unless it panics.
func mustPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected a panic", what)
		}
	}()
	f()
}

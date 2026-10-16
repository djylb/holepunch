package portmapper

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/clock"
	"github.com/djylb/holepunch/internal/leak"
	"github.com/djylb/holepunch/protocol"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

var loopback = netip.MustParseAddr("127.0.0.1")

// loopNetwork is the operating system network of the tests: real UDP
// sockets, outbound address 127.0.0.1, where the fakes live. Its fields
// inject failures.
type loopNetwork struct {
	mu          sync.Mutex
	purposes    map[string]int
	listenPanic bool
	listenErr   error
	outPanic    bool
	outErr      error
	outbound    netip.Addr
}

func (n *loopNetwork) ListenPacket(_ context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	n.mu.Lock()
	if n.purposes == nil {
		n.purposes = map[string]int{}
	}
	n.purposes[purpose]++
	p, err := n.listenPanic, n.listenErr
	n.mu.Unlock()
	if p {
		panic("ListenPacket exploded")
	}
	if err != nil {
		return nil, err
	}
	return net.ListenUDP(network, net.UDPAddrFromAddrPort(laddr))
}

func (n *loopNetwork) InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error) {
	lo := net.Interface{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback}
	return []net.Interface{lo}, [][]netip.Prefix{{netip.MustParsePrefix("127.0.0.1/8")}}, nil
}

func (n *loopNetwork) OutboundAddr(_ context.Context, _ string) (netip.Addr, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.outPanic {
		panic("OutboundAddr exploded")
	}
	if n.outErr != nil {
		return netip.Addr{}, n.outErr
	}
	if n.outbound.IsValid() {
		return n.outbound, nil
	}
	return loopback, nil
}

func (n *loopNetwork) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return nil, errors.New("no DNS in tests")
}

func (n *loopNetwork) purposeCounts() map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]int{}
	for k, v := range n.purposes {
		out[k] = v
	}
	return out
}

func (n *loopNetwork) set(fn func(*loopNetwork)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	fn(n)
}

// closedUDPPort returns a loopback UDP port nothing listens on.
func closedUDPPort(t testing.TB) uint16 {
	t.Helper()
	c := listenLoopback(t)
	port := portOf(c)
	_ = c.Close()
	return port
}

// testEnv selects the fakes a test Mapper talks to.
type testEnv struct {
	gw  *fakeGW
	igd *fakeIGD
	clk clock.Clock
}

type testMapper struct {
	*Mapper
	net *loopNetwork
	tn  *leak.TrackingNetwork

	closeErrExpected bool // the test checks Close's error itself
}

// newTestMapper returns a Mapper whose gateway is 127.0.0.1, whose sockets
// come from a TrackingNetwork over loopback, and whose PCP / NAT-PMP and SSDP
// ports point at the fakes. Without a fakeGW the gateway answers both
// protocols with "unsupported", fast, like a gateway that runs neither;
// without a fakeIGD SSDP goes to a closed port. Multicast SSDP is off so that
// tests never see real devices. Cleanup closes the Mapper and checks that
// every request socket was closed.
func newTestMapper(t testing.TB, cfg Config, env testEnv) *testMapper {
	t.Helper()
	ln := &loopNetwork{}
	tn := leak.NewTrackingNetwork(ln)
	if cfg.Network == nil {
		cfg.Network = tn
	}
	if cfg.AttemptTimeout == 0 {
		cfg.AttemptTimeout = 500 * time.Millisecond
	}
	m := New(cfg)
	if cfg.Gateway == nil {
		m.discover = func(context.Context) (netip.Addr, error) { return loopback, nil }
	}
	if env.clk != nil {
		m.clk = env.clk
	}
	m.ssdpMulticast = false
	gw := env.gw
	if gw == nil {
		gw = newFakeGW(t)
		gw.set(func(f *fakeGW) { f.pcpMode, f.natMode = serveUnsupported, serveUnsupported })
	}
	m.pcpPort = gw.port
	if env.igd != nil {
		m.ssdpPort = env.igd.ssdpPort
	} else {
		m.ssdpPort = closedUDPPort(t)
	}
	tm := &testMapper{Mapper: m, net: ln, tn: tn}
	t.Cleanup(func() {
		if err := m.Close(); err != nil && !tm.closeErrExpected {
			t.Errorf("Mapper.Close() = %v", err)
		}
		if err := tn.CheckClosed(); err != nil {
			t.Errorf("sockets left open: %v", err)
		}
	})
	return tm
}

func listenLoopback(t testing.TB) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func portOf(c net.PacketConn) uint16 {
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func on(b bool) *bool { return &b }

// policy builds a PortMappingPolicy; methods lists the enabled ones (none:
// all enabled through nil switches).
func policy(lease uint32, methods ...protocol.PortMapMethod) protocol.PortMappingPolicy {
	p := protocol.PortMappingPolicy{LeaseSeconds: lease}
	if len(methods) > 0 {
		p.EnablePCP, p.EnableNATPMP, p.EnableUPnP = on(false), on(false), on(false)
		for _, m := range methods {
			switch m {
			case protocol.PortMapPCP:
				p.EnablePCP = on(true)
			case protocol.PortMapNATPMP:
				p.EnableNATPMP = on(true)
			case protocol.PortMapUPnP:
				p.EnableUPnP = on(true)
			}
		}
	}
	return p
}

// waitBound is how long a test waits for something that must happen on
// real loopback sockets: until shortly before the test binary's deadline,
// so that a loaded machine — every package's tests in parallel under the
// race detector — slows the test down instead of failing it. Without a
// deadline it is a minute.
func waitBound(t *testing.T) time.Duration {
	d, ok := t.Deadline()
	if !ok {
		return time.Minute
	}
	return max(time.Until(d)*9/10, time.Second)
}

// waitFor polls cond until it holds, at most waitBound.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	d := waitBound(t)
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// goroutineBase records the goroutines running now; noLeak checks that only
// those are left (goleak retries while goroutines wind down).
func goroutineBase() goleak.Option { return goleak.IgnoreCurrent() }

func noLeak(t *testing.T, base goleak.Option) {
	t.Helper()
	if err := goleak.Find(base); err != nil {
		t.Fatal(err)
	}
}

// waitPending waits until the fake clock has n timers armed, at most
// waitBound.
func waitPending(t *testing.T, fc *clock.Fake, n int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitBound(t))
	defer cancel()
	if err := fc.WaitPending(ctx, n); err != nil {
		t.Fatalf("waiting for %d timers: %v", n, err)
	}
}

// boundSlack is what a test allows beyond a documented time bound for the
// scheduling delays of a loaded machine.
const boundSlack = 500 * time.Millisecond

// within fails the test if d exceeds limit.
func within(t *testing.T, what string, d, limit time.Duration) {
	t.Helper()
	if d > limit {
		t.Fatalf("%s took %s, want <= %s", what, d, limit)
	}
}

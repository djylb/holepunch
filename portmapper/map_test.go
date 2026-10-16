package portmapper

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/clock"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

func TestMapPCP(t *testing.T) {
	gw := newFakeGW(t)
	m := newTestMapper(t, Config{}, testEnv{gw: gw})
	pc := listenLoopback(t)

	info, release, err := m.Map(context.Background(), pc, protocol.PortMappingPolicy{})
	if err != nil {
		t.Fatalf("Map() error = %v", err)
	}
	want := protocol.PortMappingInfo{
		Method:   protocol.PortMapPCP,
		External: netip.AddrPortFrom(gw.ext, portOf(pc)),
		Internal: netip.AddrPortFrom(loopback, portOf(pc)),
		Lease:    time.Hour,
	}
	if info != want {
		t.Fatalf("Map() = %+v, want %+v", info, want)
	}
	if r := info.Report(); r.LeaseSeconds != 3600 || r.Method != protocol.PortMapPCP || r.External != want.External {
		t.Fatalf("Report() = %+v", r)
	}
	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
	if got := m.net.purposeCounts(); got[purposePortmap] == 0 || len(got) != 1 {
		t.Fatalf("socket purposes = %v, want only %q", got, purposePortmap)
	}
}

func TestMapNATPMPWhenPCPUnsupported(t *testing.T) {
	gw := newFakeGW(t)
	gw.set(func(f *fakeGW) { f.pcpMode = serveUnsupported; f.grant = 120 })
	fc := clock.NewFake(t, time.Time{})
	// UNSUPP_VERSION ends the PCP attempt at once, long before the attempt
	// bound, which is far beyond what a loaded machine adds.
	m := newTestMapper(t, Config{AttemptTimeout: 5 * time.Second}, testEnv{gw: gw, clk: fc})
	pc := listenLoopback(t)
	base := goroutineBase()

	start := time.Now()
	info, release, err := m.Map(context.Background(), pc, policy(600))
	if err != nil {
		t.Fatalf("Map() error = %v", err)
	}
	within(t, "Map() after UNSUPP_VERSION", time.Since(start), 2*time.Second)
	if info.Method != protocol.PortMapNATPMP || info.External != netip.AddrPortFrom(gw.ext, portOf(pc)) || info.Lease != 2*time.Minute {
		t.Fatalf("Map() = %+v", info)
	}
	waitPending(t, fc, 1)
	fc.Advance(time.Minute) // half of the granted 120 s
	waitFor(t, "NAT-PMP renewal", func() bool { return gw.counts().natRenews == 1 })
	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
	if c := gw.counts(); c.natCreates != 1 || c.natDeletes != 1 || gw.active() != 0 {
		t.Fatalf("counts = %+v active = %d", c, gw.active())
	}
	noLeak(t, base)
}

func TestMapUPnPVariants(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service string
	}{
		{"igd2", svcIGD2},
		{"igd1", svcIGD1},
		{"ppp1", svcPPP1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			igd := newFakeIGD(t, tc.service)
			fc := clock.NewFake(t, time.Time{})
			m := newTestMapper(t, Config{}, testEnv{igd: igd, clk: fc})
			pc := listenLoopback(t)
			base := goroutineBase()

			info, release, err := m.Map(context.Background(), pc, policy(120))
			if err != nil {
				t.Fatalf("Map() error = %v", err)
			}
			want := protocol.PortMappingInfo{
				Method:   protocol.PortMapUPnP,
				External: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.9"), portOf(pc)),
				Internal: netip.AddrPortFrom(loopback, portOf(pc)),
				Lease:    2 * time.Minute,
			}
			if info != want {
				t.Fatalf("Map() = %+v, want %+v", info, want)
			}
			waitPending(t, fc, 1)
			fc.Advance(time.Minute)
			waitFor(t, "UPnP renewal", func() bool { _, r, _, _ := igd.counts(); return r == 1 })
			if err := release(); err != nil {
				t.Fatalf("release() error = %v", err)
			}
			adds, _, deletes, active := igd.counts()
			if adds != 1 || deletes != 1 || active != 0 {
				t.Fatalf("adds=%d deletes=%d active=%d, want 1/1/0", adds, deletes, active)
			}
			noLeak(t, base)
		})
	}
}

func TestMapUPnPPermanentOnly(t *testing.T) {
	igd := newFakeIGD(t, svcIGD1)
	igd.set(func(f *fakeIGD) { f.permanentOnly = true })
	fc := clock.NewFake(t, time.Time{})
	m := newTestMapper(t, Config{}, testEnv{igd: igd, clk: fc})
	pc := listenLoopback(t)

	info, release, err := m.Map(context.Background(), pc, protocol.PortMappingPolicy{})
	if err != nil {
		t.Fatalf("Map() error = %v", err)
	}
	if info.Lease != 0 || info.Report().LeaseSeconds != 0 {
		t.Fatalf("Lease = %s, want 0 for a permanent mapping", info.Lease)
	}
	if n := fc.Pending(); n != 0 {
		t.Fatalf("%d renewal timers for a permanent mapping", n)
	}
	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
	if adds, renews, deletes, active := igd.counts(); adds != 1 || renews != 0 || deletes != 1 || active != 0 {
		t.Fatalf("adds=%d renews=%d deletes=%d active=%d", adds, renews, deletes, active)
	}
}

func TestMapUPnPPortConflict(t *testing.T) {
	igd := newFakeIGD(t, svcIGD1)
	m := newTestMapper(t, Config{}, testEnv{igd: igd})
	pc := listenLoopback(t)
	igd.set(func(f *fakeIGD) { f.active[portOf(pc)] = upnpEntry{internal: "192.0.2.1:1"} })

	info, release, err := m.Map(context.Background(), pc, protocol.PortMappingPolicy{})
	if err != nil {
		t.Fatalf("Map() error = %v", err)
	}
	if info.External.Port() == portOf(pc) {
		t.Fatalf("External = %s reuses a conflicting port", info.External)
	}
	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
	if _, _, _, active := igd.counts(); active != 1 { // only the other host's entry
		t.Fatalf("active = %d, want 1", active)
	}
}

func TestMapUPnPExternalAddressUnusable(t *testing.T) {
	igd := newFakeIGD(t, svcIGD2)
	igd.set(func(f *fakeIGD) { f.external = "0.0.0.0" })
	m := newTestMapper(t, Config{}, testEnv{igd: igd})
	_, _, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapUPnP))
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "unusable external address") {
		t.Fatalf("Map() error = %v, want ErrUnsupported about the external address", err)
	}
	if adds, _, _, _ := igd.counts(); adds != 0 {
		t.Fatalf("%d mappings added for a gateway without a usable external address", adds)
	}
}

func TestMapPreferenceOrder(t *testing.T) {
	gw := newFakeGW(t)
	// PCP answers once NAT-PMP has probed: the methods probe in parallel,
	// and Map stops the others as soon as the preferred one succeeds.
	gw.set(func(f *fakeGW) { f.holdPCP = true })
	igd := newFakeIGD(t, svcIGD2)
	m := newTestMapper(t, Config{}, testEnv{gw: gw, igd: igd})
	pc := listenLoopback(t)

	info, release, err := m.Map(context.Background(), pc, protocol.PortMappingPolicy{})
	if err != nil || info.Method != protocol.PortMapPCP {
		t.Fatalf("Map() = %+v, %v; want PCP", info, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	// The probes of the other methods have no effect on the gateway.
	if c := gw.counts(); c.natCreates != 0 || c.natExtQueries == 0 {
		t.Fatalf("NAT-PMP: %+v; want a probe and no mapping", c)
	}
	if adds, _, _, _ := igd.counts(); adds != 0 {
		t.Fatalf("UPnP mapping created: %d", adds)
	}

	// An explicit false turns a method off.
	info, release, err = m.Map(context.Background(), pc, policy(0, protocol.PortMapUPnP))
	if err != nil || info.Method != protocol.PortMapUPnP {
		t.Fatalf("Map(UPnP only) = %+v, %v", info, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	off := protocol.PortMappingPolicy{EnablePCP: on(false), EnableNATPMP: on(false), EnableUPnP: on(false)}
	if _, _, err := m.Map(context.Background(), pc, off); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Map(all disabled) error = %v, want ErrUnsupported", err)
	}
}

func TestLeaseDuration(t *testing.T) {
	for _, tc := range []struct {
		secs uint32
		want time.Duration
	}{
		{0, time.Hour}, {1, time.Minute}, {600, 10 * time.Minute}, {1 << 31, 24 * time.Hour},
	} {
		if got := leaseDuration(protocol.PortMappingPolicy{LeaseSeconds: tc.secs}); got != tc.want {
			t.Errorf("leaseDuration(%d) = %s, want %s", tc.secs, got, tc.want)
		}
	}
}

func TestEnabledMethods(t *testing.T) {
	all := []protocol.PortMapMethod{protocol.PortMapPCP, protocol.PortMapNATPMP, protocol.PortMapUPnP}
	if got := enabledMethods(protocol.PortMappingPolicy{}); !equalMethods(got, all) {
		t.Fatalf("nil switches: %v, want %v", got, all)
	}
	if got := enabledMethods(policy(0, protocol.PortMapUPnP, protocol.PortMapPCP)); !equalMethods(got, []protocol.PortMapMethod{protocol.PortMapPCP, protocol.PortMapUPnP}) {
		t.Fatalf("PCP and UPnP: %v, want preference order", got)
	}
}

func equalMethods(a, b []protocol.PortMapMethod) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMapFallsBackToUPnPWhenPortControlSilent(t *testing.T) {
	gw := newFakeGW(t)
	gw.set(func(f *fakeGW) { f.pcpMode, f.natMode = serveSilent, serveSilent })
	igd := newFakeIGD(t, svcIGD2)
	m := newTestMapper(t, Config{AttemptTimeout: 300 * time.Millisecond}, testEnv{gw: gw, igd: igd})

	start := time.Now()
	info, release, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
	if err != nil || info.Method != protocol.PortMapUPnP {
		t.Fatalf("Map() = %+v, %v; want UPnP", info, err)
	}
	// The probes run in parallel, each bounded by AttemptTimeout.
	within(t, "Map()", time.Since(start), 800*time.Millisecond)
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestMapContextCancel(t *testing.T) {
	gw := newFakeGW(t)
	gw.set(func(f *fakeGW) { f.pcpMode, f.natMode = serveSilent, serveSilent })
	m := newTestMapper(t, Config{AttemptTimeout: 5 * time.Second}, testEnv{gw: gw})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := m.Map(ctx, listenLoopback(t), protocol.PortMappingPolicy{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Map(cancelled ctx) error = %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	stop := time.AfterFunc(100*time.Millisecond, cancel)
	defer stop.Stop()
	start := time.Now()
	_, _, err := m.Map(ctx, listenLoopback(t), protocol.PortMappingPolicy{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Map() error = %v, want context.Canceled", err)
	}
	within(t, "Map() cancelled at 100ms", time.Since(start), 2*time.Second) // AttemptTimeout is 5 s
}

func TestMapCompensatesUncertainMappings(t *testing.T) {
	t.Run("PCP answer lost", func(t *testing.T) {
		gw := newFakeGW(t)
		gw.set(func(f *fakeGW) { f.pcpMode = serveNoReply; f.natMode = serveSilent })
		m := newTestMapper(t, Config{AttemptTimeout: 200 * time.Millisecond}, testEnv{gw: gw})
		_, _, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapPCP, protocol.PortMapNATPMP))
		if !errors.Is(err, ErrUnsupported) || !errors.Is(err, errNoResponse) {
			t.Fatalf("Map() error = %v, want ErrUnsupported after no response", err)
		}
		// The gateway created the mapping but its answer was lost: Map deletes it.
		waitFor(t, "compensating delete", func() bool { return gw.active() == 0 })
		if c := gw.counts(); c.pcpCreates != 1 || c.pcpDeletes != 1 {
			t.Fatalf("counts = %+v", c)
		}
	})
	t.Run("NAT-PMP answer lost", func(t *testing.T) {
		gw := newFakeGW(t)
		gw.set(func(f *fakeGW) { f.pcpMode = serveUnsupported; f.natMode = serveNoReply })
		m := newTestMapper(t, Config{AttemptTimeout: 200 * time.Millisecond}, testEnv{gw: gw})
		_, _, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapPCP, protocol.PortMapNATPMP))
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Map() error = %v, want ErrUnsupported", err)
		}
		waitFor(t, "compensating delete", func() bool { return gw.active() == 0 })
		if c := gw.counts(); c.natCreates != 1 || c.natDeletes != 1 {
			t.Fatalf("counts = %+v", c)
		}
	})
	t.Run("unusable answers", func(t *testing.T) {
		gw := newFakeGW(t)
		gw.set(func(f *fakeGW) { f.grant = 0 }) // zero lifetime: created but useless
		m := newTestMapper(t, Config{}, testEnv{gw: gw})
		_, _, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapPCP, protocol.PortMapNATPMP))
		if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "zero lifetime") {
			t.Fatalf("Map() error = %v, want ErrUnsupported about the lifetime", err)
		}
		waitFor(t, "deletes of unusable mappings", func() bool { return gw.active() == 0 })
		if c := gw.counts(); c.pcpCreates != 1 || c.pcpDeletes != 1 || c.natCreates != 1 || c.natDeletes != 1 {
			t.Fatalf("counts = %+v", c)
		}
	})
}

func TestMapUserCodePanics(t *testing.T) {
	t.Run("Network.ListenPacket", func(t *testing.T) {
		m := newTestMapper(t, Config{}, testEnv{})
		m.net.set(func(n *loopNetwork) { n.listenPanic = true })
		_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		var perr *life.PanicError
		if !errors.Is(err, ErrUnsupported) || !errors.As(err, &perr) || perr.Where() != "Network.ListenPacket" {
			t.Fatalf("Map() error = %v, want ErrUnsupported carrying the ListenPacket panic", err)
		}
		if s := m.g.Stats(); s.Panics != 0 {
			t.Fatalf("a recovered user panic reached the group: %+v", s)
		}
	})
	t.Run("Network.OutboundAddr", func(t *testing.T) {
		m := newTestMapper(t, Config{}, testEnv{})
		m.net.set(func(n *loopNetwork) { n.outPanic = true })
		_, _, err := m.Map(context.Background(), wildcardConn(t), protocol.PortMappingPolicy{})
		var perr *life.PanicError
		if !errors.As(err, &perr) || perr.Where() != "Network.OutboundAddr" {
			t.Fatalf("Map() error = %v, want the recovered OutboundAddr panic", err)
		}
	})
	t.Run("Config.Gateway", func(t *testing.T) {
		m := newTestMapper(t, Config{Gateway: func(context.Context) (netip.Addr, error) { panic("hook") }}, testEnv{})
		_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		var perr *life.PanicError
		if !errors.Is(err, ErrNoGateway) || !errors.As(err, &perr) {
			t.Fatalf("Map() error = %v, want ErrNoGateway carrying the panic", err)
		}
		if s := m.g.Stats(); s.Panics != 0 {
			t.Fatalf("a recovered user panic reached the group: %+v", s)
		}
	})
	t.Run("Config.Gateway error", func(t *testing.T) {
		// The lookup goroutine wraps the error outside the recover boundary;
		// fmt contains the panic of its Error method.
		m := newTestMapper(t, Config{Gateway: func(context.Context) (netip.Addr, error) { return netip.Addr{}, panicError{} }}, testEnv{})
		_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if !errors.Is(err, ErrNoGateway) || !errors.Is(err, panicError{}) {
			t.Fatalf("Map() error = %v, want ErrNoGateway wrapping the gateway error", err)
		}
		if s := m.g.Stats(); s.Panics != 0 || m.g.Context().Err() != nil {
			t.Fatalf("a panic in the gateway error reached the group: %+v, %v", s, context.Cause(m.g.Context()))
		}
	})
	t.Run("conn.LocalAddr", func(t *testing.T) {
		m := newTestMapper(t, Config{}, testEnv{})
		_, _, err := m.Map(context.Background(), localAddrConn{panics: true}, protocol.PortMappingPolicy{})
		var perr *life.PanicError
		if !errors.As(err, &perr) || perr.Where() != "conn.LocalAddr" {
			t.Fatalf("Map() error = %v, want the recovered LocalAddr panic", err)
		}
	})
}

// localAddrConn is a net.PacketConn of which Map may only call LocalAddr.
type localAddrConn struct {
	net.PacketConn // nil: any other call panics
	addr           net.Addr
	panics         bool
}

func (c localAddrConn) LocalAddr() net.Addr {
	if c.panics {
		panic("LocalAddr exploded")
	}
	return c.addr
}

// panicError is an error whose Error method panics.
type panicError struct{}

func (panicError) Error() string { panic("Error exploded") }

// textAddr is a net.Addr that is not a *net.UDPAddr.
type textAddr string

func (a textAddr) Network() string { return "udp" }
func (a textAddr) String() string  { return string(a) }

func wildcardConn(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func TestMapInvalidInput(t *testing.T) {
	gw := newFakeGW(t)
	m := newTestMapper(t, Config{}, testEnv{gw: gw})
	var typedNil *net.UDPConn
	for _, tc := range []struct {
		name string
		conn net.PacketConn
		want error
	}{
		{"nil conn", nil, errNilConn},
		{"typed nil conn", typedNil, errNilConn},
		{"no local address", localAddrConn{}, nil},
		{"typed nil local address", localAddrConn{addr: (*net.UDPAddr)(nil)}, nil},
		{"unparsable local address", localAddrConn{addr: textAddr("somewhere")}, nil},
		{"no port", localAddrConn{addr: textAddr("127.0.0.1:0")}, nil},
		{"IPv6", localAddrConn{addr: textAddr("[2001:db8::1]:4000")}, ErrUnsupported},
	} {
		_, _, err := m.Map(context.Background(), tc.conn, protocol.PortMappingPolicy{})
		if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: Map() error = %v, want %v", tc.name, err, tc.want)
		}
	}
	// A local address given as text works like a *net.UDPAddr.
	info, release, err := m.Map(context.Background(), localAddrConn{addr: textAddr("127.0.0.1:4321")}, policy(0, protocol.PortMapPCP))
	if err != nil || info.Internal != netip.MustParseAddrPort("127.0.0.1:4321") {
		t.Fatalf("Map(text address) = %+v, %v", info, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}

	for _, cfg := range []Config{{}, {Network: (*loopNetwork)(nil)}} {
		noNet := New(cfg)
		if _, _, err := noNet.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{}); !errors.Is(err, errNoNetwork) {
			t.Errorf("Map() with Network %T error = %v, want errNoNetwork", cfg.Network, err)
		}
		if err := noNet.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMapWildcardSocketUsesOutboundAddress(t *testing.T) {
	gw := newFakeGW(t)
	igd := newFakeIGD(t, svcIGD1)
	m := newTestMapper(t, Config{}, testEnv{gw: gw, igd: igd})
	pc := wildcardConn(t)
	for _, p := range []protocol.PortMappingPolicy{policy(0, protocol.PortMapPCP), policy(0, protocol.PortMapUPnP)} {
		info, release, err := m.Map(context.Background(), pc, p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Internal != netip.AddrPortFrom(loopback, portOf(pc)) {
			t.Fatalf("%s: Internal = %s, want the outbound address", info.Method, info.Internal)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMapOutboundAddressFailures(t *testing.T) {
	m := newTestMapper(t, Config{}, testEnv{})
	m.net.set(func(n *loopNetwork) { n.outErr = errors.New("network unreachable") })
	if _, _, err := m.Map(context.Background(), wildcardConn(t), protocol.PortMappingPolicy{}); !errors.Is(err, ErrNoGateway) {
		t.Fatalf("Map() without a route out: error = %v, want ErrNoGateway", err)
	}
	m.net.set(func(n *loopNetwork) { n.outErr, n.outbound = nil, netip.MustParseAddr("2001:db8::1") })
	if _, _, err := m.Map(context.Background(), wildcardConn(t), protocol.PortMappingPolicy{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Map() with an IPv6 route out: error = %v, want ErrUnsupported", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.net.set(func(n *loopNetwork) { n.outErr = context.Canceled; cancel() })
	if _, _, err := m.Map(ctx, wildcardConn(t), protocol.PortMappingPolicy{}); !errors.Is(err, context.Canceled) || errors.Is(err, ErrNoGateway) {
		t.Fatalf("Map(cancelled) error = %v, want the cancellation", err)
	}
}

func TestMapNoGateway(t *testing.T) {
	noRoute := func(context.Context) (netip.Addr, error) { return netip.Addr{}, errNoDefaultRoute }
	m := newTestMapper(t, Config{Gateway: noRoute}, testEnv{})
	// Without a gateway PCP and NAT-PMP are not tried, and UPnP finds no
	// device without multicast.
	for _, p := range []protocol.PortMappingPolicy{{}, policy(0, protocol.PortMapPCP, protocol.PortMapNATPMP)} {
		_, _, err := m.Map(context.Background(), listenLoopback(t), p)
		if !errors.Is(err, ErrNoGateway) || !errors.Is(err, errNoDefaultRoute) {
			t.Fatalf("Map(%+v) error = %v, want ErrNoGateway", p, err)
		}
	}
}

func TestMapListenPacketContract(t *testing.T) {
	cases := []struct {
		name   string
		listen func() (net.PacketConn, error)
		want   error
	}{
		{"nil conn without error", func() (net.PacketConn, error) { return nil, nil }, errNoConn},
		{"typed nil conn", func() (net.PacketConn, error) { return (*net.UDPConn)(nil), nil }, errNoConn},
		{"conn with error", func() (net.PacketConn, error) {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			return c, errListenBroken
		}, errListenBroken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fn := &funcNetwork{listen: tc.listen}
			m := newTestMapper(t, Config{Network: fn}, testEnv{})
			_, _, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapPCP))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Map() error = %v, want %v", err, tc.want)
			}
			if n := fn.openConns(); n != 0 {
				t.Fatalf("%d sockets returned alongside an error were left open", n)
			}
		})
	}
}

var errListenBroken = errors.New("listen broken")

// funcNetwork returns what listen returns and tracks the conns it handed out.
type funcNetwork struct {
	listen func() (net.PacketConn, error)
	mu     sync.Mutex
	conns  []net.PacketConn
}

func (n *funcNetwork) ListenPacket(_ context.Context, _ string, _ netip.AddrPort, _ string) (net.PacketConn, error) {
	c, err := n.listen()
	if !life.IsNil(c) {
		n.mu.Lock()
		n.conns = append(n.conns, c)
		n.mu.Unlock()
	}
	return c, err
}

func (n *funcNetwork) OutboundAddr(_ context.Context, _ string) (netip.Addr, error) {
	return loopback, nil
}

// openConns counts the conns that still accept writes.
func (n *funcNetwork) openConns() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	open := 0
	for _, c := range n.conns {
		if _, err := c.WriteTo([]byte{0}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); !errors.Is(err, net.ErrClosed) {
			open++
		}
	}
	return open
}

// TestMapBoundedWhenEveryStepIsSlow: PCP is silent, NAT-PMP answers its
// probe but not the mapping request, and UPnP answers its probe but hangs on
// the mapping request. The mapping requests share one bound with the
// parallel phase, so Map returns within twice AttemptTimeout.
func TestMapBoundedWhenEveryStepIsSlow(t *testing.T) {
	gw := newFakeGW(t)
	gw.set(func(f *fakeGW) { f.pcpMode, f.natMode = serveSilent, serveNoReply })
	igd := newFakeIGD(t, svcIGD2)
	igd.set(func(f *fakeIGD) { f.hangAdds = true })
	const attempt = 300 * time.Millisecond
	m := newTestMapper(t, Config{AttemptTimeout: attempt}, testEnv{gw: gw, igd: igd})
	base := goroutineBase()
	start := time.Now()
	_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Map() error = %v, want ErrUnsupported", err)
	}
	within(t, "Map()", time.Since(start), 2*attempt+150*time.Millisecond)
	// The NAT-PMP mapping that was created without an answer is deleted.
	gw.set(func(f *fakeGW) { f.natMode = serveOK })
	waitFor(t, "compensating NAT-PMP delete", func() bool { return gw.active() == 0 })
	noLeak(t, base)
}

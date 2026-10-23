package portmapper

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/protocol"
)

// TestMapHungGatewayIsBounded: a gateway lookup or gateway that hangs does
// not hold Map beyond its bounds.
func TestMapHungGatewayIsBounded(t *testing.T) {
	t.Run("gateway hook honours ctx", func(t *testing.T) {
		m := newTestMapper(t, Config{
			DiscoverTimeout: 200 * time.Millisecond,
			Gateway: func(ctx context.Context) (netip.Addr, error) {
				<-ctx.Done()
				return netip.Addr{}, ctx.Err()
			},
		}, testEnv{})
		start := time.Now()
		_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if !errors.Is(err, ErrNoGateway) {
			t.Fatalf("Map() error = %v, want ErrNoGateway", err)
		}
		within(t, "Map() with DiscoverTimeout 200ms", time.Since(start), 400*time.Millisecond)
	})
	t.Run("lookup ignores ctx, default DiscoverTimeout", func(t *testing.T) {
		unblock := make(chan struct{})
		m := newTestMapper(t, Config{}, testEnv{})
		m.discover = func(context.Context) (netip.Addr, error) {
			<-unblock
			return loopback, nil
		}
		start := time.Now()
		_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if !errors.Is(err, ErrNoGateway) {
			t.Fatalf("Map() error = %v, want ErrNoGateway", err)
		}
		within(t, "Map()", time.Since(start), defaultDiscoverTimeout+200*time.Millisecond)
		close(unblock)
	})
	t.Run("hung lookup is shared by concurrent Maps", func(t *testing.T) {
		var calls atomic.Int32
		unblock := make(chan struct{})
		m := newTestMapper(t, Config{DiscoverTimeout: 200 * time.Millisecond}, testEnv{})
		m.discover = func(context.Context) (netip.Addr, error) {
			calls.Add(1)
			<-unblock
			return loopback, nil
		}
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				start := time.Now()
				_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
				if !errors.Is(err, ErrNoGateway) {
					t.Errorf("Map() error = %v, want ErrNoGateway", err)
				}
				if d := time.Since(start); d > 450*time.Millisecond {
					t.Errorf("Map() took %s with DiscoverTimeout 200ms", d)
				}
			})
		}
		wg.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("lookup ran %d times, want 1 (single-flight)", got)
		}
		close(unblock)
		testkit.WaitFor(t, "cached gateway", func() bool {
			a, err := m.lookupGateway(context.Background())
			return err == nil && a == loopback
		})
	})
	t.Run("lookup still running at Close", func(t *testing.T) {
		started := make(chan struct{})
		m := newTestMapper(t, Config{
			DiscoverTimeout: 100 * time.Millisecond,
			Gateway: func(ctx context.Context) (netip.Addr, error) {
				close(started)
				<-ctx.Done()
				return netip.Addr{}, ctx.Err()
			},
		}, testEnv{})
		base := goroutineBase()
		if _, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{}); !errors.Is(err, ErrNoGateway) {
			t.Fatalf("Map() error = %v", err)
		}
		<-started
		if err := m.Close(); err != nil {
			t.Fatalf("Close() = %v", err)
		}
		noLeak(t, base)
	})
	t.Run("silent services", func(t *testing.T) {
		gw := newFakeGW(t)
		gw.set(func(f *fakeGW) { f.pcpMode, f.natMode = serveSilent, serveSilent })
		igd := newFakeIGD(t, svcIGD2)
		igd.set(func(f *fakeIGD) { f.ssdpSilent = true })
		m := newTestMapper(t, Config{AttemptTimeout: 300 * time.Millisecond}, testEnv{gw: gw, igd: igd})
		start := time.Now()
		_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Map() error = %v, want ErrUnsupported", err)
		}
		within(t, "Map() with AttemptTimeout 300ms", time.Since(start), 600*time.Millisecond)
	})
	t.Run("UPnP HTTP hangs", func(t *testing.T) {
		igd := newFakeIGD(t, svcIGD2)
		igd.set(func(f *fakeIGD) { f.hangHTTP = true })
		m := newTestMapper(t, Config{AttemptTimeout: 300 * time.Millisecond}, testEnv{igd: igd})
		base := goroutineBase()
		start := time.Now()
		_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Map() error = %v, want ErrUnsupported", err)
		}
		within(t, "Map() with AttemptTimeout 300ms", time.Since(start), 600*time.Millisecond)
		noLeak(t, base)
	})
}

func TestGatewayCache(t *testing.T) {
	var calls atomic.Int32
	addr := netip.MustParseAddr("192.168.1.1")
	fc := clock.NewFake(t, time.Time{})
	m := newTestMapper(t, Config{}, testEnv{clk: fc})
	m.discover = func(context.Context) (netip.Addr, error) {
		calls.Add(1)
		return netip.AddrFrom16(addr.As16()), nil // IPv4-mapped: unmapped by the cache
	}
	lookup := func() netip.Addr {
		t.Helper()
		a, err := m.lookupGateway(context.Background())
		if err != nil {
			t.Fatalf("lookupGateway() = %v", err)
		}
		return a
	}
	if lookup() != addr || calls.Load() != 1 {
		t.Fatal("first lookup")
	}
	fc.Advance(gatewayTTL - time.Second)
	if lookup(); calls.Load() != 1 {
		t.Fatal("cached entry not used")
	}
	fc.Advance(2 * time.Second)
	if lookup(); calls.Load() != 2 {
		t.Fatal("expired entry reused")
	}
	m.invalidateGateway(netip.MustParseAddr("10.9.9.9"))
	if lookup(); calls.Load() != 2 {
		t.Fatal("invalidating another address dropped the entry")
	}
	m.invalidateGateway(addr)
	if lookup(); calls.Load() != 3 {
		t.Fatal("invalidate did not drop the entry")
	}

	// Failures — an error, an IPv6 gateway, a panic — are ErrNoGateway and
	// cached briefly.
	for i, fail := range []func(context.Context) (netip.Addr, error){
		func(context.Context) (netip.Addr, error) { return netip.Addr{}, errors.New("no default route") },
		func(context.Context) (netip.Addr, error) { return netip.MustParseAddr("fe80::1"), nil },
		func(context.Context) (netip.Addr, error) { panic("broken routing table") },
	} {
		var n atomic.Int32
		m.discover = func(ctx context.Context) (netip.Addr, error) { n.Add(1); return fail(ctx) }
		m.gw.mu.Lock()
		m.gw.valid = false
		m.gw.mu.Unlock()
		for range 2 {
			if _, err := m.lookupGateway(context.Background()); !errors.Is(err, ErrNoGateway) {
				t.Fatalf("failure %d: err = %v, want ErrNoGateway", i, err)
			}
		}
		if n.Load() != 1 {
			t.Fatalf("failure %d: lookup ran %d times, want 1 (negative cache)", i, n.Load())
		}
		fc.Advance(gatewayNegativeTTL + time.Millisecond)
		_, _ = m.lookupGateway(context.Background())
		if n.Load() != 2 {
			t.Fatalf("failure %d: negative entry outlived its TTL", i)
		}
	}
}

func TestMapInvalidatesSilentGateway(t *testing.T) {
	gw := newFakeGW(t)
	gw.set(func(f *fakeGW) { f.pcpMode, f.natMode = serveSilent, serveSilent })
	var calls atomic.Int32
	m := newTestMapper(t, Config{AttemptTimeout: 100 * time.Millisecond}, testEnv{gw: gw})
	m.discover = func(context.Context) (netip.Addr, error) { calls.Add(1); return loopback, nil }
	for range 2 {
		if _, _, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapPCP, protocol.PortMapNATPMP)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Map() error = %v", err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("lookup ran %d times; a gateway that answers nothing must be looked up again", calls.Load())
	}
}

// A routing table the process may not read — Android refuses /proc/net/route to
// ordinary apps — fails Map at once with ErrNoGateway, before any request
// socket is opened: only port mapping is off.
func TestMapGatewayRefused(t *testing.T) {
	m := newTestMapper(t, Config{
		Gateway: func(context.Context) (netip.Addr, error) {
			return netip.Addr{}, &fs.PathError{Op: "open", Path: "/proc/net/route", Err: fs.ErrPermission}
		},
	}, testEnv{})
	start := time.Now()
	_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
	if !errors.Is(err, ErrNoGateway) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Map() error = %v, want ErrNoGateway wrapping the permission error", err)
	}
	within(t, "Map() with a refused routing table", time.Since(start), defaultDiscoverTimeout/2)
	if got := m.net.purposeCounts(); len(got) != 0 {
		t.Fatalf("sockets opened without a gateway: %v", got)
	}
}

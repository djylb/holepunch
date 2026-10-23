//go:build holepunch_faultinject

package portmapper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/protocol"
)

// Fault injection at the points portmap.map (each mapping
// request) and portmap.renew (each renewal). The process must survive every
// injected panic, and only the step that panicked may fail.

func TestFaultPortmapMap(t *testing.T) {
	t.Cleanup(faultinject.Reset)
	t.Run("PCP attempt panics: NAT-PMP takes over", func(t *testing.T) {
		faultinject.Reset()
		gw := newFakeGW(t)
		m := newTestMapper(t, Config{}, testEnv{gw: gw})
		// The PCP request is always the first portmap.map hit: the NAT-PMP
		// and UPnP mapping requests only follow a failed PCP attempt.
		defer faultinject.Arm(pointMap, faultinject.Panic(), 1)()
		info, release, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if err != nil || info.Method != protocol.PortMapNATPMP {
			t.Fatalf("Map() = %+v, %v; want NAT-PMP after the PCP attempt panicked", info, err)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
		if c := gw.counts(); c.pcpCreates != 0 {
			t.Fatalf("PCP mapping created by a panicked attempt: %+v", c)
		}
		if s := m.g.Stats(); s.Panics != 0 {
			t.Fatalf("panic escaped to the group: %+v", s)
		}
	})
	t.Run("NAT-PMP create panics in Map: UPnP takes over", func(t *testing.T) {
		faultinject.Reset()
		gw := newFakeGW(t)
		gw.set(func(f *fakeGW) { f.pcpMode = serveUnsupported })
		igd := newFakeIGD(t, svcIGD2)
		m := newTestMapper(t, Config{}, testEnv{gw: gw, igd: igd})
		// Hit 1 is the PCP request, which fails on UNSUPP_VERSION; hit 2 is
		// the NAT-PMP mapping request, made in Map's own goroutine.
		defer faultinject.Arm(pointMap, faultinject.Panic(), 2)()
		info, release, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if err != nil || info.Method != protocol.PortMapUPnP {
			t.Fatalf("Map() = %+v, %v; want UPnP after the NAT-PMP request panicked", info, err)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
		if c := gw.counts(); c.natCreates != 0 {
			t.Fatalf("NAT-PMP mapping created by a panicked request: %+v", c)
		}
	})
	t.Run("every request panics", func(t *testing.T) {
		faultinject.Reset()
		gw := newFakeGW(t)
		m := newTestMapper(t, Config{}, testEnv{gw: gw})
		disarm := faultinject.Arm(pointMap, faultinject.Panic(), 0)
		_, _, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapPCP, protocol.PortMapNATPMP))
		var perr *life.PanicError
		if !errors.Is(err, ErrUnsupported) || !errors.As(err, &perr) || !errors.Is(err, faultinject.ErrInjected) {
			t.Fatalf("Map() error = %v, want ErrUnsupported carrying the recovered panics", err)
		}
		disarm()
		info, release, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapNATPMP))
		if err != nil || info.Method != protocol.PortMapNATPMP {
			t.Fatalf("Map() after the panics = %+v, %v", info, err)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
		if s := m.g.Stats(); s.Panics != 0 {
			t.Fatalf("panic escaped to the group: %+v", s)
		}
	})
	t.Run("errors on every request", func(t *testing.T) {
		faultinject.Reset()
		gw := newFakeGW(t)
		igd := newFakeIGD(t, svcIGD2)
		m := newTestMapper(t, Config{}, testEnv{gw: gw, igd: igd})
		defer faultinject.Arm(pointMap, faultinject.Error(nil), 0)()
		_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if !errors.Is(err, ErrUnsupported) || !errors.Is(err, faultinject.ErrInjected) {
			t.Fatalf("Map() error = %v", err)
		}
		if got := faultinject.Fired(pointMap); got != 3 {
			t.Fatalf("%s fired %d times, want once per method", pointMap, got)
		}
		if gw.active() != 0 {
			t.Fatal("mapping left behind")
		}
	})
}

func TestFaultPortmapRenew(t *testing.T) {
	t.Cleanup(faultinject.Reset)
	t.Run("panic stops renewal, release still deletes", func(t *testing.T) {
		faultinject.Reset()
		gw := newFakeGW(t)
		fc := clock.NewFake(t, time.Time{})
		m := newTestMapper(t, Config{}, testEnv{gw: gw, clk: fc})
		base := goroutineBase()
		defer faultinject.Arm(pointRenew, faultinject.Panic(), 1)()
		_, release, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		waitPending(t, fc, 1)
		fc.Advance(30 * time.Minute)
		testkit.WaitFor(t, "renewal panic", func() bool { return faultinject.Fired(pointRenew) == 1 })
		noLeak(t, base) // the renewal goroutine ended after its panic
		if err := release(); err != nil {
			t.Fatalf("release() = %v", err)
		}
		if gw.active() != 0 || gw.counts().pcpRenews != 0 {
			t.Fatalf("after release: active %d, %+v", gw.active(), gw.counts())
		}
		if s := m.g.Stats(); s.Panics != 0 {
			t.Fatalf("panic escaped to the group: %+v", s)
		}
	})
	t.Run("failed renewals are retried", func(t *testing.T) {
		faultinject.Reset()
		gw := newFakeGW(t)
		fc := clock.NewFake(t, time.Time{})
		m := newTestMapper(t, Config{}, testEnv{gw: gw, clk: fc})
		disarm := faultinject.Arm(pointRenew, faultinject.Error(nil), 0)
		_, release, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		waitPending(t, fc, 1)
		fc.Advance(30 * time.Minute)
		testkit.WaitFor(t, "failed renewal", func() bool { return faultinject.Fired(pointRenew) == 1 && fc.Pending() == 1 })
		disarm()
		fc.Advance(15 * time.Minute) // retried at a quarter of the lifetime
		testkit.WaitFor(t, "retried renewal", func() bool { return gw.counts().pcpRenews == 1 })
		if err := release(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("renewal stuck: release still bounded", func(t *testing.T) {
		faultinject.Reset()
		gw := newFakeGW(t)
		fc := clock.NewFake(t, time.Time{})
		m := newTestMapper(t, Config{}, testEnv{gw: gw, clk: fc})
		disarm := faultinject.Arm(pointRenew, faultinject.Stall(0), 1)
		_, release, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		waitPending(t, fc, 1)
		fc.Advance(30 * time.Minute)
		testkit.WaitFor(t, "stalled renewal", func() bool { return faultinject.Fired(pointRenew) == 1 })
		start := time.Now()
		if err := release(); !errors.Is(err, errRenewStuck) {
			t.Fatalf("release() = %v, want errRenewStuck", err)
		}
		within(t, "release()", time.Since(start), releaseTimeout+boundSlack)
		disarm() // the renewal goroutine finishes; Close joins it
		if err := m.Close(); err != nil {
			t.Fatalf("Close() = %v", err)
		}
	})
}

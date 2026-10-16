package portmapper

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/clock"
	"github.com/djylb/holepunch/protocol"
)

// TestReleaseStopsRenewalAndDeletes: after release returns, the renewal
// goroutine has exited and the delete has reached the gateway; release is
// idempotent and leaves the socket open.
func TestReleaseStopsRenewalAndDeletes(t *testing.T) {
	gw := newFakeGW(t)
	fc := clock.NewFake(t, time.Time{})
	m := newTestMapper(t, Config{}, testEnv{gw: gw, clk: fc})
	pc := listenLoopback(t)
	base := goroutineBase()

	_, release, err := m.Map(context.Background(), pc, protocol.PortMappingPolicy{})
	if err != nil {
		t.Fatalf("Map() error = %v", err)
	}
	// Renewed at half the granted lifetime, with the nonce of the create.
	for i := 1; i <= 2; i++ {
		waitPending(t, fc, 1)
		fc.Advance(30 * time.Minute)
		waitFor(t, "PCP renewal", func() bool { return gw.counts().pcpRenews == i })
	}
	if c := gw.counts(); c.pcpRejects != 0 || c.natCreates != 0 {
		t.Fatalf("counts = %+v: renewals must reuse the nonce and NAT-PMP must not be used", c)
	}

	start := time.Now()
	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
	within(t, "release()", time.Since(start), releaseTimeout)
	c := gw.counts()
	if c.pcpDeletes != 1 || gw.active() != 0 {
		t.Fatalf("after release: counts = %+v, active = %d; want one delete, nothing active", c, gw.active())
	}
	noLeak(t, base) // the renewal goroutine is gone
	if n := fc.Pending(); n != 0 {
		t.Fatalf("%d timers still armed after release", n)
	}
	fc.Advance(2 * time.Hour)
	if got := gw.counts(); got.pcpRenews != c.pcpRenews || got.pcpCreates != 1 {
		t.Fatalf("activity after release: %+v", got)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := release(); err != nil {
				t.Errorf("repeated release() error = %v", err)
			}
		})
	}
	wg.Wait()
	if got := gw.counts().pcpDeletes; got != 1 {
		t.Fatalf("pcpDeletes = %d after repeated release, want 1", got)
	}
	if _, err := pc.WriteToUDPAddrPort([]byte("x"), netip.AddrPortFrom(loopback, gw.port)); err != nil {
		t.Fatalf("mapped socket unusable after release: %v", err)
	}
	m.mu.Lock()
	held := len(m.leases)
	m.mu.Unlock()
	if held != 0 {
		t.Fatalf("Mapper still holds %d leases after release", held)
	}
}

func TestReleaseBoundedWhenGatewayStopsAnswering(t *testing.T) {
	gw := newFakeGW(t)
	m := newTestMapper(t, Config{}, testEnv{gw: gw})
	_, release, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	gw.set(func(f *fakeGW) { f.dropDeletes = true })
	start := time.Now()
	err = release()
	within(t, "release()", time.Since(start), releaseTimeout+boundSlack)
	if !errors.Is(err, errNoResponse) {
		t.Fatalf("release() = %v although the gateway never confirmed the delete", err)
	}
	start = time.Now()
	if err2 := release(); !errors.Is(err2, err) {
		t.Fatalf("second release() = %v, want the first error %v", err2, err)
	}
	within(t, "second release()", time.Since(start), releaseTimeout/4) // not another wait for the gateway
}

func TestRenewalRecreatesAfterGatewayReboot(t *testing.T) {
	gw := newFakeGW(t)
	gw.set(func(f *fakeGW) { f.grant = 120 })
	fc := clock.NewFake(t, time.Time{})
	m := newTestMapper(t, Config{AttemptTimeout: 200 * time.Millisecond}, testEnv{gw: gw, clk: fc})
	_, release, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	// The gateway stops answering: the renewal fails and is retried at a
	// quarter of the lifetime.
	gw.set(func(f *fakeGW) { f.pcpMode = serveSilent })
	waitPending(t, fc, 1)
	before := gw.counts().received
	fc.Advance(time.Minute)
	waitFor(t, "failed renewal", func() bool { return gw.counts().received > before && fc.Pending() == 1 })
	// It comes back after a reboot with an empty table: the next renewal,
	// 30 s later, re-creates the mapping.
	gw.set(func(f *fakeGW) { f.pcpMode = serveOK; clear(f.pcpActive) })
	next, ok := fc.Next()
	if !ok || next.Sub(fc.Now()) != 30*time.Second {
		t.Fatalf("retry scheduled in %v (ok=%v), want 30 s after the failure", next.Sub(fc.Now()), ok)
	}
	fc.Advance(30 * time.Second)
	waitFor(t, "mapping re-created by renewal", func() bool { return gw.counts().pcpCreates == 2 })
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if gw.active() != 0 {
		t.Fatal("re-created mapping not deleted")
	}
}

func TestRenewalRetriesAtQuarterLease(t *testing.T) {
	igd := newFakeIGD(t, svcIGD1)
	fc := clock.NewFake(t, time.Time{})
	// Every exchange here is answered at once — the failing renewal with a
	// SOAP fault — so AttemptTimeout only bounds them: it is as long as the
	// test may wait, not a guess at how fast a loaded loopback answers.
	m := newTestMapper(t, Config{AttemptTimeout: waitBound(t)}, testEnv{igd: igd, clk: fc})
	_, release, err := m.Map(context.Background(), listenLoopback(t), policy(600))
	if err != nil {
		t.Fatal(err)
	}
	// A failed UPnP renewal is retried at a quarter of the lease.
	igd.set(func(f *fakeIGD) { f.failAdds = true })
	waitPending(t, fc, 1)
	fc.Advance(5 * time.Minute)
	waitFor(t, "failed renewal", func() bool {
		next, ok := fc.Next()
		return ok && next.Sub(fc.Now()) == 150*time.Second
	})
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestRenewAfter(t *testing.T) {
	for _, tc := range []struct {
		lifetime time.Duration
		ok       bool
		want     time.Duration
	}{
		{time.Hour, true, 30 * time.Minute},
		{time.Hour, false, 15 * time.Minute},
		{time.Second, true, time.Second},
		{3 * time.Second, false, time.Second},
	} {
		if got := renewAfter(tc.lifetime, tc.ok); got != tc.want {
			t.Errorf("renewAfter(%s, %v) = %s, want %s", tc.lifetime, tc.ok, got, tc.want)
		}
	}
}

func TestReleaseReportsFailedDelete(t *testing.T) {
	t.Run("NAT-PMP", func(t *testing.T) {
		gw := newFakeGW(t)
		gw.set(func(f *fakeGW) { f.pcpMode = serveUnsupported })
		m := newTestMapper(t, Config{AttemptTimeout: 200 * time.Millisecond}, testEnv{gw: gw})
		info, release, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapPCP, protocol.PortMapNATPMP))
		if err != nil || info.Method != protocol.PortMapNATPMP {
			t.Fatalf("Map() = %+v, %v", info, err)
		}
		gw.set(func(f *fakeGW) { f.dropDeletes = true })
		if err := release(); !errors.Is(err, errNoResponse) {
			t.Fatalf("release() = %v, want the unconfirmed delete", err)
		}
	})
	t.Run("UPnP", func(t *testing.T) {
		igd := newFakeIGD(t, svcIGD1)
		m := newTestMapper(t, Config{}, testEnv{igd: igd})
		_, release, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapUPnP))
		if err != nil {
			t.Fatal(err)
		}
		igd.set(func(f *fakeIGD) { clear(f.active) }) // the gateway lost the entry
		if err := release(); upnpCode(err) != 714 {
			t.Fatalf("release() = %v, want the NoSuchEntryInArray fault", err)
		}
	})
}

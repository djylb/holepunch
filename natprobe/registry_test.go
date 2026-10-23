package natprobe

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/probetest"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// The registry runs no goroutine of its own. The check is against the
// goroutines running at the start, not their number: one of an earlier test
// that ends meanwhile would lower the count.
func TestRegistryNoGoroutine(t *testing.T) {
	base := goleak.IgnoreCurrent()
	clk := clock.NewFake(t, time.Time{})
	reg := NewRegistry(RegistryConfig{Clock: clk})
	for i := range 10000 {
		var route protocol.RouteID
		route[0], route[1], route[2] = byte(i), byte(i>>8), 0xAA
		if _, err := reg.register(nat.Registration{SessionID: fmt.Sprint("s", i), Route: route, Token: tok(1), TTL: time.Second}); err != nil {
			t.Fatal(err)
		}
	}
	if reg.Len() != 10000 {
		t.Fatalf("len %d", reg.Len())
	}
	if err := goleak.Find(base); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Second)
	removed := reg.sweep(clk.Now())
	if removed != 10000 || reg.Len() != 0 {
		t.Fatalf("removed %d len %d", removed, reg.Len())
	}
	if err := goleak.Find(base); err != nil {
		t.Fatal(err)
	}
}

// Registering the same session twice is idempotent.
func TestRegisterIdempotent(t *testing.T) {
	r := newRig(t, rigOpts{})
	h1 := register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	if out := r.deliver(0, c.probe(probetest.Probe{Obs: 0}), srcA); len(out) != 1 {
		t.Fatalf("%d replies", len(out))
	}
	r.clk.Advance(30 * time.Second)
	h2, err := r.reg.register(nat.Registration{SessionID: "s1", Route: rt(1), Token: tok(1), TTL: time.Minute})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if h2 == h1 || h2.e != h1.e {
		t.Fatalf("re-register: same handle %v, same entry %v", h2 == h1, h2.e == h1.e)
	}
	if obs := h2.Observations(protocol.RoleInitiator); len(obs) != 1 || obs[0].Observed != srcA {
		t.Fatalf("observations lost: %+v", obs)
	}
	r.clk.Advance(45 * time.Second) // past the first TTL, within the renewal
	if r.reg.lookup(rt(1)) == nil || !h1.e.alive(r.reg.mono(r.clk.Now())) {
		t.Fatal("the renewal did not extend")
	}
	if _, err := r.reg.register(nat.Registration{SessionID: "s1", Route: rt(1), Token: tok(2)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("other token: %v", err)
	}
	if _, err := r.reg.register(nat.Registration{SessionID: "s2", Route: rt(1), Token: tok(1)}); !errors.Is(err, ErrRouteInUse) {
		t.Fatalf("route in use: %v", err)
	}
	if r.reg.Len() != 1 {
		t.Fatalf("len %d", r.reg.Len())
	}
	for _, bad := range []nat.Registration{
		{Route: rt(3), Token: tok(1)},
		{SessionID: strings.Repeat("x", 65), Route: rt(3), Token: tok(1)},
		{SessionID: "x", Token: tok(1)},
		{SessionID: "x", Route: rt(3)},
	} {
		if _, err := r.reg.register(bad); err == nil {
			t.Fatalf("invalid registration accepted: %+v", bad)
		}
	}
	var nilReg *Registry
	if _, err := nilReg.register(nat.Registration{}); err == nil || nilReg.Len() != 0 {
		t.Fatal("nil registry")
	}
}

// TestHandleRegistered: the registration time is read from the
// Registry's clock, survives an idempotent renewal and is the origin of the
// slot times (and so of PortAnchorMs).
func TestHandleRegistered(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.clk.Advance(7 * time.Second)
	at := r.clk.Now()
	h1 := register(t, r.reg, "s1", tok(1), rt(1))
	if !h1.Registered().Equal(at) {
		t.Fatalf("registered %v, want the registry clock's %v", h1.Registered(), at)
	}
	r.clk.Advance(1500 * time.Millisecond)
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	if out := r.deliver(0, c.probe(probetest.Probe{Obs: 0}), srcA); len(out) != 1 {
		t.Fatalf("%d replies", len(out))
	}
	h2, err := r.reg.register(nat.Registration{SessionID: "s1", Route: rt(1), Token: tok(1), TTL: time.Minute})
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if !h2.Registered().Equal(at) {
		t.Fatalf("renewal: registered %v, want %v", h2.Registered(), at)
	}
	obs := h2.Observations(protocol.RoleInitiator)
	if len(obs) != 1 || obs[0].FirstAt.Sub(h2.Registered()) != 1500*time.Millisecond {
		t.Fatalf("slot times are not on the registration axis: %+v", obs)
	}
	var nilH *handle
	if !nilH.Registered().IsZero() {
		t.Fatal("nil handle")
	}
}

func TestRegistryFull(t *testing.T) {
	clk := clock.NewFake(t, time.Time{})
	reg := NewRegistry(RegistryConfig{MaxEntries: 3, Clock: clk})
	for i := range 3 {
		register(t, reg, fmt.Sprint("s", i), tok(1), rt(byte(i)))
	}
	if _, err := reg.register(nat.Registration{SessionID: "s3", Route: rt(3), Token: tok(1)}); !errors.Is(err, ErrRegistryFull) {
		t.Fatalf("got %v", err)
	}
	// Register itself drops the expired entries of the target shard
	clk.Advance(2 * time.Minute)
	for i := range 3 {
		if _, err := reg.register(nat.Registration{SessionID: fmt.Sprint("n", i), Route: rt(byte(i)), Token: tok(9), TTL: time.Minute}); err != nil {
			t.Fatalf("after expiry: %v", err)
		}
	}
	if reg.Len() != 3 {
		t.Fatalf("len %d", reg.Len())
	}
	// the default TTL is the library's 60 s fallback
	reg = NewRegistry(RegistryConfig{Clock: clk})
	h, err := reg.register(nat.Registration{SessionID: "d", Route: rt(1), Token: tok(1)})
	if err != nil || h.e.expiresAt.Load() != reg.mono(clk.Now())+int64(defaultTTL) {
		t.Fatalf("default TTL: %v", err)
	}
}

func TestRegistryExpiryExtendClose(t *testing.T) {
	r := newRig(t, rigOpts{})
	h := register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	r.clk.Advance(50 * time.Second)
	h.Extend(time.Minute)
	h.Extend(time.Second) // never shortens
	r.clk.Advance(50 * time.Second)
	if out := r.deliver(0, c.probe(probetest.Probe{}), srcA); len(out) != 1 {
		t.Fatal("the extended entry is not served")
	}
	r.clk.Advance(20 * time.Second)
	if out := r.deliver(0, c.probe(probetest.Probe{}), srcA); len(out) != 0 || r.stats.unknownRoute.Load() != 1 {
		t.Fatal("an expired entry is served")
	}
	if r.reg.sweep(r.clk.Now()) != 1 || r.reg.Len() != 0 {
		t.Fatal("sweep")
	}
	h.Close() // already swept: no double removal
	h.Extend(time.Hour)
	if r.reg.Len() != 0 {
		t.Fatal("len after close")
	}

	h = register(t, r.reg, "s2", tok(2), rt(2))
	c2 := newClient(t, tok(2), rt(2), udpwire.RoleResponder)
	h.Close()
	h.Close()
	if out := r.deliver(0, c2.probe(probetest.Probe{}), srcA); len(out) != 0 || r.reg.Len() != 0 {
		t.Fatal("a closed entry is served")
	}
	if _, err := r.reg.register(nat.Registration{SessionID: "s3", Route: rt(2), Token: tok(3)}); err != nil {
		t.Fatalf("the route of a closed session is not reusable: %v", err)
	}
	var nilH *handle
	nilH.Close()
	nilH.Extend(time.Second)
	if nilH.Observations(protocol.RoleInitiator) != nil || h.Observations(protocol.RoleServer) != nil {
		t.Fatal("observations of a nil handle or of the server role")
	}
}

// Concurrent Handle.Close calls are idempotent.
func TestHandleCloseIdempotentRace(t *testing.T) {
	clk := clock.NewFake(t, time.Time{})
	reg := NewRegistry(RegistryConfig{Clock: clk})
	var hs []*handle
	for i := range 50 {
		hs = append(hs, register(t, reg, fmt.Sprint("s", i), tok(1), rt(byte(i))))
	}
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Go(func() {
			for _, h := range hs {
				h.Close()
			}
			if i%10 == 0 {
				reg.sweep(clk.Now())
			}
		})
	}
	wg.Wait()
	if reg.Len() != 0 {
		t.Fatalf("len %d", reg.Len())
	}
}

// Two registries never share state.
func TestRegistriesIndependent(t *testing.T) {
	a, b := newRig(t, rigOpts{}), newRig(t, rigOpts{})
	register(t, a.reg, "s1", tok(1), rt(1))
	register(t, b.reg, "s1", tok(2), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	if len(a.deliver(0, c.probe(probetest.Probe{}), srcA)) != 1 || len(b.deliver(0, c.probe(probetest.Probe{}), srcA)) != 0 {
		t.Fatal("the registries leak into each other")
	}
	if b.stats.badAuth.Load() != 1 {
		t.Fatal("the other registry should fail authentication")
	}
}

// Concurrent readers with registrations and closes (-race).
func TestRegistryConcurrentReadWrite(t *testing.T) {
	clk := clock.NewFake(t, time.Time{})
	reg := NewRegistry(RegistryConfig{Clock: clk})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			var r protocol.RouteID
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				r[0], r[1] = byte(n), byte(n>>8)
				if e := reg.lookup(r); e != nil {
					_ = e.alive(reg.mono(clk.Now()))
				}
			}
		})
	}
	for i := range 2000 {
		var r protocol.RouteID
		r[0], r[1], r[2] = byte(i), byte(i>>8), 0xAA
		h, err := reg.register(nat.Registration{SessionID: fmt.Sprint("s", i), Route: r, Token: tok(1)})
		if err != nil {
			t.Fatal(err)
		}
		if i%3 == 0 {
			h.Close()
		}
	}
	close(stop)
	wg.Wait()
	if want := 2000 - 667; reg.Len() != want {
		t.Fatalf("len %d want %d", reg.Len(), want)
	}
}

// The sandwich bridge attaches through internal/nat.
func TestAttachSandwichSinkBridge(t *testing.T) {
	r := newRig(t, rigOpts{})
	h := register(t, r.reg, "s1", tok(1), rt(1))
	var got []nat.SandwichEvent
	var mu sync.Mutex
	h.AttachSandwichSink(func(ev nat.SandwichEvent) { mu.Lock(); got = append(got, ev); mu.Unlock() })
	(*handle)(nil).AttachSandwichSink(nil)
	if _, err := nat.RegisterProbe("not a registry", nat.Registration{}); err == nil {
		t.Error("RegisterProbe took a non-Registry")
	}
	c := newClient(t, tok(1), rt(1), udpwire.RoleResponder)
	r.deliver(1, c.probe(probetest.Probe{Obs: 1, Sandwich: &[2]uint8{3, nat.SandwichAfter}}), srcA)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Role != protocol.RoleResponder || got[0].Round != 3 || got[0].Phase != nat.SandwichAfter ||
		got[0].Observed != srcA || !got[0].At.Equal(r.clk.Now()) {
		t.Fatalf("events %+v", got)
	}
}

// The registry config takes its defaults and bounds.
func TestRegistryDefaults(t *testing.T) {
	reg := NewRegistry(RegistryConfig{MaxEntries: 1 << 30, SlotsPerRole: 1000, SandwichQueue: -1, SessionRate: Rate{PerSec: 5}})
	c := reg.cfg
	if c.MaxEntries != maxMaxEntries || c.SlotsPerRole != maxSlotsPerRole || c.SandwichQueue != defaultSandwichQueue ||
		c.SessionRate != (Rate{PerSec: 5, Burst: 10}) || c.ProbeBudgetPerRole != defaultProbeBudget ||
		c.ExtraQuotaPerRole != defaultExtraQuota || c.AltQuotaPerRole != defaultAltQuota {
		t.Fatalf("config %+v", c)
	}
	if NewRegistry(RegistryConfig{}).cfg.SessionRate != (Rate{PerSec: defaultSessionPerSec, Burst: defaultSessionBurst}) {
		t.Fatal("default session rate")
	}
}

// Extend never revives an expired entry, whether or not an
// unrelated writer of its shard already dropped it.
func TestExtendDoesNotReviveExpired(t *testing.T) {
	for _, otherWrite := range []bool{false, true} {
		r := newRig(t, rigOpts{})
		h, err := r.reg.register(nat.Registration{SessionID: "s1", Route: rt(1), Token: tok(1), TTL: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
		r.clk.Advance(2 * time.Second)
		if out := r.deliver(0, c.probe(probetest.Probe{}), srcA); len(out) != 0 {
			t.Fatal("expired entry served")
		}
		if otherWrite {
			other := rt(1)
			other[15] ^= 0xFF // same shard
			if _, err := r.reg.register(nat.Registration{SessionID: "other", Route: other, Token: tok(2), TTL: time.Minute}); err != nil {
				t.Fatal(err)
			}
		}
		h.Extend(time.Minute)
		if out := r.deliver(0, c.probe(probetest.Probe{}), srcA); len(out) != 0 {
			t.Fatalf("other write %v: an expired entry is served again after Extend", otherWrite)
		}
	}
}

// A huge TTL saturates the expiry instead of wrapping it into the
// past, for Register, the idempotent renewal and Extend.
func TestHugeTTLSaturates(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.clk.Advance(time.Second) // a monotonic time > 0
	reg := nat.Registration{SessionID: "s1", Route: rt(1), Token: tok(1), TTL: time.Duration(math.MaxInt64)}
	h, err := r.reg.register(reg)
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	if out := r.deliver(0, c.probe(probetest.Probe{}), srcA); len(out) != 1 {
		t.Fatalf("a registration with a huge TTL is dead on arrival (expiry %d)", h.e.expiresAt.Load())
	}
	if _, err := r.reg.register(reg); err != nil {
		t.Fatal(err)
	}
	h.Extend(time.Duration(math.MaxInt64))
	r.clk.Advance(time.Hour)
	if out := r.deliver(0, c.probe(probetest.Probe{}), srcA); len(out) != 1 || h.e.expiresAt.Load() != math.MaxInt64 {
		t.Fatalf("renewals wrapped the expiry to %d", h.e.expiresAt.Load())
	}
}

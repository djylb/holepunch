package portmapper

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// TestCloseReleasesEverything: Close deletes every mapping of every method
// within the bound, Map and Unmap counts are equal, and nothing is left
// running or open.
func TestCloseReleasesEverything(t *testing.T) {
	gw := newFakeGW(t)
	igd := newFakeIGD(t, svcIGD2)
	m := newTestMapper(t, Config{}, testEnv{gw: gw, igd: igd})
	base := goroutineBase()

	policies := []protocol.PortMappingPolicy{
		policy(0, protocol.PortMapPCP),
		policy(0, protocol.PortMapNATPMP),
		policy(0, protocol.PortMapUPnP),
	}
	for i := range 6 {
		if _, _, err := m.Map(context.Background(), listenLoopback(t), policies[i%3]); err != nil {
			t.Fatalf("Map(%d) error = %v", i, err)
		}
	}
	if got := gw.active(); got != 4 {
		t.Fatalf("active PCP and NAT-PMP mappings = %d, want 4", got)
	}

	var wg sync.WaitGroup
	errs := make([]error, 4)
	start := time.Now()
	for i := range errs {
		wg.Go(func() { errs[i] = m.Close() })
	}
	wg.Wait()
	within(t, "Close()", time.Since(start), releaseTimeout)
	for _, err := range errs {
		if err != nil {
			t.Fatalf("Close() = %v", err)
		}
	}
	c := gw.counts()
	if c.pcpCreates != c.pcpDeletes || c.natCreates != c.natDeletes || gw.active() != 0 {
		t.Fatalf("after Close: %+v, active %d; want Map and Unmap counts equal", c, gw.active())
	}
	adds, _, deletes, active := igd.counts()
	if adds != deletes || active != 0 {
		t.Fatalf("UPnP after Close: adds=%d deletes=%d active=%d", adds, deletes, active)
	}
	noLeak(t, base)
	if err := m.tn.CheckClosed(); err != nil {
		t.Fatal(err)
	}
	if s := m.g.Stats(); s.Running != 0 || s.Leaked != 0 || s.Panics != 0 {
		t.Fatalf("group stats after Close: %+v", s)
	}

	_, _, err := m.Map(context.Background(), listenLoopback(t), protocol.PortMappingPolicy{})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Map() after Close error = %v, want net.ErrClosed", err)
	}
}

// TestConcurrentMapAndClose closes the Mapper at different points of 32
// concurrent Maps. Every mapping that was created is deleted, by Close or by
// the Map that was cut short, and nothing leaks.
func TestConcurrentMapAndClose(t *testing.T) {
	for round := range 8 {
		gw := newFakeGW(t)
		m := newTestMapper(t, Config{}, testEnv{gw: gw})
		base := goroutineBase()

		var wg sync.WaitGroup
		var mapped, closedErrs atomic.Int32
		releases := make(chan func() error, 32)
		for range 32 {
			pc := listenLoopback(t)
			wg.Go(func() {
				_, release, err := m.Map(context.Background(), pc, policy(0, protocol.PortMapPCP, protocol.PortMapNATPMP))
				switch {
				case err == nil:
					mapped.Add(1)
					releases <- release
				case errors.Is(err, net.ErrClosed):
					closedErrs.Add(1)
				default:
					t.Errorf("Map() error = %v", err)
				}
			})
		}
		time.Sleep(time.Duration(round) * 250 * time.Microsecond)
		start := time.Now()
		if err := m.Close(); err != nil {
			t.Fatalf("Close() = %v", err)
		}
		within(t, "Close()", time.Since(start), releaseTimeout+boundSlack)
		wg.Wait()
		close(releases)
		for release := range releases {
			if err := release(); err != nil { // already released by Close: the first result
				t.Fatalf("release() after Close = %v", err)
			}
		}
		c := gw.counts()
		if gw.active() != 0 || c.pcpCreates != c.pcpDeletes || c.natCreates != c.natDeletes {
			t.Fatalf("round %d: %+v active=%d (mapped %d, closed %d); want every mapping deleted",
				round, c, gw.active(), mapped.Load(), closedErrs.Load())
		}
		noLeak(t, base)
		if err := m.tn.CheckClosed(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCloseBoundedWhenGatewayStopsAnswering: deletes that are never confirmed
// make Close return an error within the bound instead of waiting.
func TestCloseBoundedWhenGatewayStopsAnswering(t *testing.T) {
	gw := newFakeGW(t)
	m := newTestMapper(t, Config{}, testEnv{gw: gw})
	m.closeErrExpected = true
	base := goroutineBase()
	for range 3 {
		if _, _, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapPCP)); err != nil {
			t.Fatal(err)
		}
	}
	gw.set(func(f *fakeGW) { f.dropDeletes = true })
	start := time.Now()
	err := m.Close()
	within(t, "Close()", time.Since(start), releaseTimeout+boundSlack)
	if !errors.Is(err, errNoResponse) {
		t.Fatalf("Close() = %v, want the unconfirmed delete", err)
	}
	if err2 := m.Close(); !errors.Is(err2, err) {
		t.Fatalf("second Close() = %v, want %v", err2, err)
	}
	noLeak(t, base)
}

// TestCloseCancelsBackgroundDeletes: a background delete of an abandoned
// mapping that the gateway never confirms is cut off at Close's bound.
func TestCloseCancelsBackgroundDeletes(t *testing.T) {
	gw := newFakeGW(t)
	// PCP creates and answers nothing, so Map deletes in the background; the
	// gateway drops the delete too.
	gw.set(func(f *fakeGW) { f.pcpMode, f.dropDeletes = serveNoReply, true })
	m := newTestMapper(t, Config{AttemptTimeout: 100 * time.Millisecond}, testEnv{gw: gw})
	base := goroutineBase()
	if _, _, err := m.Map(context.Background(), listenLoopback(t), policy(0, protocol.PortMapPCP)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Map() error = %v", err)
	}
	start := time.Now()
	if err := m.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	within(t, "Close()", time.Since(start), releaseTimeout)
	noLeak(t, base)
}

// TestCleanupAfterClose: cleanup requested by a Map that returns after Close
// has joined the group runs in that Map's goroutine, with a live context.
func TestCleanupAfterClose(t *testing.T) {
	m := newTestMapper(t, Config{}, testEnv{})
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	r := &recordingRemover{}
	m.discard(r, compensateTimeout)
	if r.calls != 1 || r.ctxErr != nil {
		t.Fatalf("discard after Close: %d deletes, context error %v; want one delete with a live context", r.calls, r.ctxErr)
	}
}

// recordingRemover records the deletes asked of it.
type recordingRemover struct {
	calls  int
	ctxErr error
}

func (r *recordingRemover) remove(ctx context.Context) error {
	r.calls++
	r.ctxErr = ctx.Err()
	return nil
}

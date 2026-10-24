package e2e

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
	"go.uber.org/goleak"
)

// errUserPanic is the value user code panics with in the user-code faults.
var errUserPanic = errors.New("e2e: user code panic")

// userFault is one case of the fault matrix's user-code row: user code or a
// user implementation panics; the result must not change (the Clock, which every
// wait of the session reads, may turn it into internal) and the panic is
// counted.
type userFault struct {
	name string
	// server installs panicking server-side code; client the client's.
	// Both count the panics in n.
	server func(wc *worldConfig, n *atomic.Int32)
	client func(sides [2]*side, spec *sessionSpec, n *atomic.Int32)
	// allowInternal accepts internal instead of success.
	allowInternal bool
	// profiles are the two sides' NATs (nil: PRC).
	profiles [2]func() nattest.NATConfig
	// quiet silences the peers as in the fault matrix, so that a later
	// round runs.
	quiet silence
	// count reports the panics the library counted.
	count func(r *run, w *world) int
	// check adds an assertion.
	check func(r *run) error
}

// clientPanics is the initiator's Counters.CallbackPanics.
func clientPanics(r *run, _ *world) int { return r.out[observed].diag.Counters.CallbackPanics }

// serverPanics is the coordinator's Stats.Panics.
func serverPanics(_ *run, w *world) int { return int(w.co.Stats().Panics) }

// panicMapper is a PortMapper that panics.
type panicMapper struct{ n *atomic.Int32 }

func (m panicMapper) Map(context.Context, net.PacketConn, protocol.PortMappingPolicy) (protocol.PortMappingInfo, func() error, error) {
	m.n.Add(1)
	panic(errUserPanic)
}

// clockPanicCall is the call of Now that panics: well into the session.
const clockPanicCall = 40

// nthNowPanics returns the system clock, except that its nth call of Now
// panics once, counted in n.
func nthNowPanics(nth int32, n *atomic.Int32) clock.Clock {
	var seen atomic.Int32
	return testkit.PanicClock{Clock: clock.System{}, Panic: func(method string) any {
		if method != "Now" || seen.Add(1) != nth {
			return nil
		}
		n.Add(1)
		return errUserPanic
	}}
}

// panicPlanner panics in Classify; the coordinator replaces it with the
// built-in planner.
type panicPlanner struct {
	plan.Planner
	n *atomic.Int32
}

func (p panicPlanner) Classify(plan.ClassifyInput) plan.Classification {
	p.n.Add(1)
	panic(errUserPanic)
}

// panicMemory is a StrategyMemory that panics.
type panicMemory struct{ n *atomic.Int32 }

func (m panicMemory) Recommend(coord.StrategyKey, []plan.VariantID) []plan.VariantID {
	m.n.Add(1)
	panic(errUserPanic)
}

func (m panicMemory) Score(coord.StrategyKey, plan.VariantID) int {
	m.n.Add(1)
	panic(errUserPanic)
}

func (m panicMemory) Report(coord.StrategyKey, plan.VariantID, coord.MemoryResult) {
	m.n.Add(1)
	panic(errUserPanic)
}

// panicTraits is a TraitsMemory that panics.
type panicTraits struct{ n *atomic.Int32 }

func (m panicTraits) Apply(natprobe.TraitsKey, protocol.Traits) protocol.Traits {
	m.n.Add(1)
	panic(errUserPanic)
}

func (m panicTraits) Observe(natprobe.TraitsKey, protocol.Traits, bool) {
	m.n.Add(1)
	panic(errUserPanic)
}

func (m panicTraits) Recall(natprobe.TraitsKey) (protocol.Traits, bool) {
	m.n.Add(1)
	panic(errUserPanic)
}

func userFaults() []userFault {
	return []userFault{
		{name: "client_on_progress", count: clientPanics, client: func(_ [2]*side, spec *sessionSpec, n *atomic.Int32) {
			spec.onProgress[observed] = func(protocol.Progress) { n.Add(1); panic(errUserPanic) }
		}},
		{name: "client_network", count: clientPanics, profiles: [2]func() nattest.NATConfig{profSYMSEQ, profFC},
			client: func(sides [2]*side, _ *sessionSpec, n *atomic.Int32) {
				// The second socket of the session, which a client behind an
				// endpoint-dependent NAT opens while probing: that bind fails,
				// the session goes on.
				calls := new(atomic.Int32)
				f := func(string) {
					if calls.Add(1) == 2 {
						n.Add(1)
						panic(errUserPanic)
					}
				}
				sides[observed].net.listen.Store(&f)
			}},
		{name: "client_port_mapper", count: clientPanics, client: func(sides [2]*side, _ *sessionSpec, n *atomic.Int32) {
			sides[observed].pm = panicMapper{n: n}
		}},
		{name: "client_hop_limiter", quiet: silenceRound1, count: func(r *run, _ *world) int {
			return r.out[0].diag.Counters.CallbackPanics + r.out[1].diag.Counters.CallbackPanics
		}, client: func(sides [2]*side, _ *sessionSpec, n *atomic.Int32) {
			// Round 2 of the easy ladder has a low-TTL receiver; round 1 is
			// silenced so that it runs.
			f := func(hops int) {
				if hops > 0 {
					n.Add(1)
					panic(errUserPanic)
				}
			}
			for _, s := range sides {
				s.net.hop.Store(&f)
			}
		}, check: func(r *run) error {
			for i := range 2 {
				if slices.Contains(r.out[i].diag.Warn, protocol.WarnLowTTLUnsupported) {
					return nil
				}
			}
			return fmt.Errorf("no side warns %s after a HopLimiter panic", protocol.WarnLowTTLUnsupported)
		}},
		{name: "client_clock", allowInternal: true, client: func(_ [2]*side, spec *sessionSpec, n *atomic.Int32) {
			spec.clock[observed] = nthNowPanics(clockPanicCall, n)
		}},
		{name: "server_planner", count: serverPanics, server: func(wc *worldConfig, n *atomic.Int32) {
			wc.planner = panicPlanner{Planner: coord.DefaultPlanner(), n: n}
		}},
		{name: "server_strategy_memory", count: serverPanics, server: func(wc *worldConfig, n *atomic.Int32) {
			wc.memory = panicMemory{n: n}
		}},
		{name: "server_traits_memory", server: func(wc *worldConfig, n *atomic.Int32) {
			wc.traits = panicTraits{n: n}
		}},
		{name: "server_observer", count: serverPanics, server: func(wc *worldConfig, n *atomic.Int32) {
			wc.observer = func(coord.Event) { n.Add(1); panic(errUserPanic) }
		}},
		{name: "server_on_result", count: serverPanics, server: func(wc *worldConfig, n *atomic.Int32) {
			wc.onResult = func(coord.Result) { n.Add(1); panic(errUserPanic) }
		}},
	}
}

// runUserFault runs one user-code case and returns its violations.
func runUserFault(t *testing.T, uf userFault, seed int64) []string {
	fired := new(atomic.Int32)
	wc := worldConfig{seed: seed}
	if uf.server != nil {
		uf.server(&wc, fired)
	}
	w := newWorld(t, wc)
	var sides [2]*side
	for i := range sides {
		prof := profPRC
		if uf.profiles[i] != nil {
			prof = uf.profiles[i]
		}
		sides[i] = w.behind([]nattest.NATConfig{prof()})
	}
	var spec sessionSpec
	if uf.client != nil {
		uf.client(sides, &spec, fired)
	}
	h := newCellHelpers()
	spec.prepare = func(r *run) { silencePeers(r, sides, uf.quiet, h) }
	r, err := newRun(w, sides, spec)
	if err != nil {
		return w.abandon(err)
	}
	r.execute()
	var v []string
	add := func(format string, args ...any) { v = append(v, fmt.Sprintf(format, args...)) }
	if !h.end(scaled(helperJoin)) {
		add("the cell's helper goroutines did not end within %v", scaled(helperJoin))
	}
	for _, s := range sides {
		s.net.dropFrom(nil)
	}
	if fired.Load() == 0 {
		add("the user code never ran")
	}
	internal := uf.allowInternal && r.out[observed].reason() == protocol.ReasonInternal
	for i := range 2 {
		got := r.out[i].reason()
		switch {
		case got == "", internal && i == observed:
		case internal:
			// the peer of a side that failed fails too, by the server's notice
		default:
			add("%s: outcome %q (%v), want success", roles[i], got, r.out[i].err)
		}
	}
	if uf.count != nil && fired.Load() > 0 && countedWithin(r, w, uf.count, scaled(time.Second)) == 0 {
		add("%d panics, none counted", fired.Load())
	}
	if uf.check != nil && fired.Load() > 0 && r.out[0].ok() && r.out[1].ok() {
		if err := uf.check(r); err != nil {
			add("%v", err)
		}
	}
	cr := &cellRun{c: &cell{name: "user/" + uf.name, class: classMust}, seed: seed, w: w, sides: sides, r: r}
	cr.measure()
	v = append(v, cr.checkResources()...)
	if len(v) > 0 {
		v = append(v, cr.dumpNote(t, v, "user"))
	}
	if err := w.close(); err != nil {
		add("world close: %v", err)
	}
	return v
}

// countedWithin polls a panic counter for a while: the coordinator counts
// an OnResult panic after it delivered the Result.
func countedWithin(r *run, w *world, count func(*run, *world) int, d time.Duration) int {
	deadline := time.Now().Add(d)
	for {
		if c := count(r, w); c > 0 || time.Now().After(deadline) {
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestFaultUserCode is the user-code row of the client fault matrix: a
// panicking user callback or implementation on either side leaves the
// result unchanged, is counted and leaks nothing.
func TestFaultUserCode(t *testing.T) {
	t.Run("cells", func(t *testing.T) {
		for _, uf := range userFaults() {
			name := "user/" + uf.name
			if !suite().selected("fault/" + name) {
				continue
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				release := acquireSlot()
				defer release()
				seed := cellSeed("fault/"+name, 0)
				for _, p := range runUserFault(t, uf, seed) {
					t.Errorf("seed %d: %s", seed, p)
				}
			})
		}
	})
	goleak.VerifyNone(t)
}

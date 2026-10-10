package probe

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/clock"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// drive advances the fake clock and the simulated network while the prober
// goroutine runs, until done delivers.
func drive[T any](t *testing.T, s *sim, done <-chan T) T {
	t.Helper()
	for step := 0; ; step++ {
		select {
		case r := <-done:
			return r
		default:
		}
		if step == 100000 {
			t.Fatal("the prober did not finish")
		}
		s.settle()
		next := s.nextEvent()
		if w, ok := s.fake.Next(); ok {
			if wt := w.Sub(s.start); next < 0 || wt < next {
				next = wt
			}
		}
		if next < 0 {
			continue
		}
		s.advanceTo(max(next, s.now))
	}
}

// settle waits, in real time, until the prober goroutine has consumed its
// inbox and is back in its select; the clock under test is fake.
func (s *sim) settle() {
	for range 2000 {
		if len(s.p.inbox) == 0 {
			break
		}
		time.Sleep(50 * time.Microsecond)
	}
	time.Sleep(500 * time.Microsecond)
}

func (s *sim) loopRun(ctx context.Context) Result {
	done := make(chan Result, 1)
	go func() { done <- s.p.Run(ctx) }()
	return drive(s.t, s, done)
}

// The real Run loop (timer and select) reaches what the stepped machine does.
func TestRunLoop(t *testing.T) {
	o := defaultOpts()
	o.nat.filtering = protocol.FiltPDF
	s := newSim(t, o)
	r := s.loopRun(context.Background())
	if r.Failure != "" || r.Traits.Filtering != protocol.FiltPDF || r.Traits.FilteringConf != protocol.ConfHigh || r.Traits.Mapping != protocol.MapEIM {
		t.Fatalf("result %+v", r)
	}
	if s.now < o.rtt+80*ms || s.now > o.rtt+80*ms+10*ms {
		t.Fatalf("done at %v", s.now)
	}
	if r2 := s.p.Run(context.Background()); r2.Failure != protocol.ReasonInternal || r2.Detail != "run_twice" {
		t.Fatalf("second Run: %+v", r2)
	}
	if s.p.Deliver(0, s.socks[0].local, &udpwire.Header{Type: udpwire.TProbeAck}, nil, time.Time{}) {
		t.Fatal("Deliver accepted after Run")
	}
	if s.fake.Pending() != 0 {
		t.Fatalf("%d timers left behind", s.fake.Pending())
	}

	o = defaultOpts()
	o.nat = natCfg{mapping: protocol.MapAPDM, alloc: "seq", step: 1, filtering: protocol.FiltEIF}
	o.alt, o.stun = true, true
	s = newSim(t, o)
	r = s.loopRun(context.Background())
	if r.Failure != "" || r.Traits.Mapping != protocol.MapAPDM || r.Traits.PortAlloc != protocol.AllocSequential ||
		r.Traits.Filtering != protocol.FiltEIF || r.Sent.Second != 3 || r.Sent.Alt != 1 || r.Sent.STUN != 1 {
		t.Fatalf("result %+v", r)
	}

	s = newSim(t, defaultOpts())
	s.unreachable = true
	r = s.loopRun(context.Background())
	if r.Failure != protocol.ReasonProbeTimeout || s.now != defaultTimeout {
		t.Fatalf("result %+v at %v", r, s.now)
	}

	// ICMP notes wake the loop
	s = newSim(t, defaultOpts())
	s.unreachable, s.icmp = true, true
	r = s.loopRun(context.Background())
	if r.Failure != protocol.ReasonUDPBlocked || r.Detail != "icmp_unreachable" {
		t.Fatalf("result %+v", r)
	}
}

// Ctx cancellation ends probing promptly with canceled, whatever the cause.
func TestRunCanceled(t *testing.T) {
	for _, cause := range []error{nil, errors.New("control interrupted")} {
		s := newSim(t, defaultOpts())
		s.unreachable = true
		ctx, cancel := context.WithCancelCause(context.Background())
		done := make(chan Result, 1)
		go func() { done <- s.p.Run(ctx) }()
		// Cancel once the first batch is out: Run counts each packet as it
		// sends it and checks ctx only between batches, so all three count.
		// A fixed sleep let a slow runner cancel before the batch was sent.
		for wait := time.Now(); len(s.sentTo(srvIP)) < 3; time.Sleep(50 * time.Microsecond) {
			if time.Since(wait) > 2*time.Second {
				t.Fatal("Run sent no first batch")
			}
		}
		start := time.Now()
		cancel(cause)
		var r Result
		select {
		case r = <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Run did not return after cancel")
		}
		if time.Since(start) > 50*time.Millisecond {
			t.Fatalf("Run took %v after cancel", time.Since(start))
		}
		if r.Failure != protocol.ReasonCanceled || r.Sent.Primary != 3 {
			t.Fatalf("result %+v", r)
		}
		if s.fake.Pending() != 0 {
			t.Fatalf("%d timers left behind", s.fake.Pending())
		}
	}
	// a ctx that already ended: nothing is sent
	s0 := newSim(t, defaultOpts())
	ended, cancelEnded := context.WithCancelCause(context.Background())
	cancelEnded(errors.New("control interrupted"))
	if r := s0.p.Run(ended); r.Failure != protocol.ReasonCanceled || r.Sent.Primary != 0 || len(s0.log) != 0 {
		t.Fatalf("ended ctx: %+v", r)
	}
	// a nil ctx is tolerated as the background
	var noCtx context.Context
	s := newSim(t, defaultOpts())
	done := make(chan Result, 1)
	go func() { done <- s.p.Run(noCtx) }()
	if r := drive(t, s, done); r.Failure != "" {
		t.Fatalf("nil ctx: %+v", r)
	}
}

// The hairpin self-test.
func TestHairpin(t *testing.T) {
	var noCtx context.Context
	for _, on := range []bool{true, false} {
		o := defaultOpts()
		o.nat.hairpin = on
		s := newSim(t, o)
		if s.p.Hairpin(context.Background()) != protocol.TriUnknown {
			t.Fatal("hairpin before Run")
		}
		if r := s.stepRun(); r.Failure != "" {
			t.Fatal(r.Failure)
		}
		start := s.now
		done := make(chan protocol.Tri, 1)
		go func() { done <- s.p.Hairpin(context.Background()) }()
		got := drive(t, s, done)
		want := protocol.TriFalse
		if on {
			want = protocol.TriTrue
		}
		if got != want || s.now-start > hairpinWindow {
			t.Fatalf("hairpin(on=%v) = %v after %v", on, got, s.now-start)
		}
		if tr := s.p.table.Classify(); tr.Hairpin != want {
			t.Fatalf("table hairpin %v", tr.Hairpin)
		}
		out := len(s.sentTo(pubIP))
		if (on && out < 1) || (!on && out != 2) {
			t.Fatalf("%d hairpin packets", out)
		}
		if s.fake.Pending() != 0 {
			t.Fatalf("%d timers left behind", s.fake.Pending())
		}
	}
	// canceled: unknown, nothing recorded
	s := newSim(t, defaultOpts())
	s.stepRun()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.p.Hairpin(ctx) != protocol.TriUnknown || s.p.table.Classify().Hairpin != protocol.TriUnknown {
		t.Fatal("canceled hairpin")
	}
	// no observed address: unknown
	s = newSim(t, defaultOpts())
	s.unreachable = true
	s.stepRun()
	if s.p.Hairpin(context.Background()) != protocol.TriUnknown {
		t.Fatal("hairpin without an observed address")
	}
	// every hairpin send fails: unknown; a nil ctx is the background
	s = newSim(t, defaultOpts())
	s.stepRun()
	s.writeErr = func(uint8, netip.AddrPort) error { return syscall.EPERM }
	done := make(chan protocol.Tri, 1)
	go func() { done <- s.p.Hairpin(noCtx) }()
	if got := drive(t, s, done); got != protocol.TriUnknown {
		t.Fatalf("hairpin without sends = %v", got)
	}
	// a second concurrent self-test is refused
	s = newSim(t, defaultOpts())
	s.stepRun()
	s.p.hairpin.Store(true)
	if s.p.Hairpin(context.Background()) != protocol.TriUnknown {
		t.Fatal("concurrent hairpin")
	}
}

// A ctx that already ended sends no hairpin packet, as it sends no probe
// from Run.
func TestHairpinEndedCtxSendsNothing(t *testing.T) {
	s := newSim(t, defaultOpts())
	if r := s.stepRun(); r.Failure != "" {
		t.Fatal(r.Failure)
	}
	before := len(s.sentTo(pubIP))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := s.p.Hairpin(ctx); got != protocol.TriUnknown {
		t.Fatalf("hairpin = %v", got)
	}
	if n := len(s.sentTo(pubIP)) - before; n != 0 {
		t.Fatalf("%d hairpin packet(s) sent with an ended ctx", n)
	}
}

// The hairpin self-test runs once per prober: the family's probe-class
// bound (hairpin: 2 packets) holds however often the runtime calls
// it.
func TestHairpinRunsOnce(t *testing.T) {
	s := newSim(t, defaultOpts())
	if r := s.stepRun(); r.Failure != "" {
		t.Fatal(r.Failure)
	}
	results := make([]protocol.Tri, 0, 3)
	for range 3 {
		done := make(chan protocol.Tri, 1)
		go func() { done <- s.p.Hairpin(context.Background()) }()
		results = append(results, drive(t, s, done))
	}
	if n := len(s.sentTo(pubIP)); n != 2 {
		t.Fatalf("%d hairpin packets for one family (budget 2)", n)
	}
	if results[0] != protocol.TriFalse || results[1] != protocol.TriUnknown || results[2] != protocol.TriUnknown {
		t.Fatalf("results %v, want [false unknown unknown]", results)
	}
}

// panicClock is a clock whose timers panic, standing in for any panic inside
// the probing loop.
type panicClock struct{ clock.Clock }

func (panicClock) NewTimer(time.Duration) clock.Timer { panic("timer") }

// A panic inside the prober fails the family with internal, detail
// panic:probe/<family>, and the recovered *life.PanicError comes along in
// Result.Panic, named like the detail; nothing else carries one.
func TestRunPanicCarried(t *testing.T) {
	s := newSim(t, defaultOpts())
	s.spec.Clock = panicClock{s.fake}
	s.p = New(s.spec, s.socks[0], nil, nil)
	r := s.p.Run(context.Background())
	if r.Failure != protocol.ReasonInternal || r.Detail != "panic:probe/udp4" || r.Panic == nil || "panic:"+r.Panic.Where() != r.Detail {
		t.Fatalf("result %+v", r)
	}
	if r.Table == nil || r.Traits.Family != protocol.FamilyUDP4 || !strings.Contains(r.Panic.Error(), "timer") {
		t.Fatalf("result %+v (%v)", r, r.Panic)
	}
	if r := newSim(t, defaultOpts()).loopRun(context.Background()); r.Panic != nil {
		t.Fatalf("a clean run carries %v", r.Panic)
	}
}

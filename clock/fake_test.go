package clock_test

import (
	"context"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
)

var epoch = time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)

func TestFakeFiresByDeadlineThenCreation(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	type firing struct {
		name string
		at   time.Duration
	}
	var got []firing
	add := func(name string, d time.Duration) {
		clk.AfterFunc(d, func() { got = append(got, firing{name, clk.Now().Sub(epoch)}) })
	}
	add("c3", 3*time.Second)
	add("a1", time.Second)
	add("b3", 3*time.Second)
	add("z0", 0)
	add("d2", 2*time.Second)
	add("e3", 3*time.Second)

	if n := clk.Advance(3 * time.Second); n != 6 {
		t.Fatalf("Advance fired %d timers, want 6", n)
	}
	want := []firing{{"z0", 0}, {"a1", time.Second}, {"d2", 2 * time.Second}, {"c3", 3 * time.Second}, {"b3", 3 * time.Second}, {"e3", 3 * time.Second}}
	if len(got) != len(want) {
		t.Fatalf("fired %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("firing %d = %v, want %v (all: %v)", i, got[i], want[i], got)
		}
	}
	if now := clk.Now(); !now.Equal(epoch.Add(3 * time.Second)) {
		t.Fatalf("Now = %v after Advance", now)
	}
}

func TestFakeStart(t *testing.T) {
	if got := clock.NewFake(t, time.Time{}).Now(); !got.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) || got.IsZero() {
		t.Fatalf("zero start: Now = %v", got)
	}
	wall := time.Now()
	if got := clock.NewFake(t, wall).Now(); got != wall.Round(0) {
		t.Fatalf("start kept its monotonic reading: %v", got)
	}
}

func TestFakeNextReportsEarliestDeadline(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	if _, ok := clk.Next(); ok {
		t.Fatal("Next reported a deadline with nothing pending")
	}
	clk.AfterFunc(22*time.Second, func() {})
	tm := clk.NewTimer(5 * time.Second)
	if next, ok := clk.Next(); !ok || !next.Equal(epoch.Add(5*time.Second)) {
		t.Fatalf("Next = %v, %v; want +5s", next, ok)
	}
	tm.Stop()
	if next, _ := clk.Next(); !next.Equal(epoch.Add(22 * time.Second)) {
		t.Fatalf("Next after Stop = %v, want +22s", next)
	}
	if clk.Pending() != 1 || !clk.Now().Equal(epoch) {
		t.Fatal("Next changed the clock")
	}
}

func TestFakeResetKeepsCreationOrder(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	var got []string
	first := clk.AfterFunc(time.Second, func() { got = append(got, "first") })
	clk.AfterFunc(2*time.Second, func() { got = append(got, "second") })
	first.Reset(2 * time.Second)
	clk.Advance(2 * time.Second)
	if strings.Join(got, ",") != "first,second" {
		t.Fatalf("order %v, want first,second (ties broken by creation)", got)
	}
}

func TestFakeChannelTimerDeliversDeadline(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	tm := clk.NewTimer(5 * time.Second)
	clk.Advance(4 * time.Second)
	select {
	case v := <-tm.C():
		t.Fatalf("timer fired early with %v", v)
	default:
	}
	clk.Advance(2 * time.Second)
	select {
	case v := <-tm.C():
		if !v.Equal(epoch.Add(5 * time.Second)) {
			t.Fatalf("timer delivered %v, want its deadline", v)
		}
	default:
		t.Fatal("timer did not fire")
	}
	if tm.Stop() {
		t.Fatal("Stop after the expiry was received returned true")
	}
}

func TestFakeAfterFuncTimerHasNilChannel(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	if c := clk.AfterFunc(time.Second, func() {}).C(); c != nil {
		t.Fatal("AfterFunc timer has a channel")
	}
}

func TestFakeZeroDelayFiresOnNextAdvance(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	ran := false
	clk.AfterFunc(-time.Second, func() { ran = true })
	tm := clk.NewTimer(0)
	if ran || clk.Pending() != 2 {
		t.Fatal("zero-delay timers fired before the clock was advanced")
	}
	if n := clk.Advance(0); n != 2 || !ran {
		t.Fatalf("Advance(0) fired %d timers (ran=%v), want 2", n, ran)
	}
	if v := <-tm.C(); !v.Equal(epoch) {
		t.Fatalf("zero-delay timer delivered %v, want %v", v, epoch)
	}
}

func TestFakeNeverMovesBackwards(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	clk.Advance(10 * time.Second)
	ran := false
	clk.AfterFunc(0, func() { ran = true })
	if n := clk.AdvanceTo(epoch); n != 1 || !ran {
		t.Fatalf("AdvanceTo(past) fired %d timers, want the due one", n)
	}
	if now := clk.Now(); !now.Equal(epoch.Add(10 * time.Second)) {
		t.Fatalf("clock moved backwards to %v", now)
	}
	clk.Advance(-time.Hour)
	if now := clk.Now(); !now.Equal(epoch.Add(10 * time.Second)) {
		t.Fatalf("negative Advance moved the clock to %v", now)
	}
}

func TestFakeAdvanceNext(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	if d, ok := clk.AdvanceNext(); ok || d != 0 {
		t.Fatalf("AdvanceNext with nothing pending = (%v, %v)", d, ok)
	}
	var fired []string
	clk.AfterFunc(3*time.Second, func() { fired = append(fired, "a") })
	clk.AfterFunc(3*time.Second, func() {
		fired = append(fired, "b")
		clk.AfterFunc(0, func() { fired = append(fired, "b+0") })
	})
	clk.AfterFunc(5*time.Second, func() { fired = append(fired, "c") })

	if d, ok := clk.AdvanceNext(); !ok || d != 3*time.Second {
		t.Fatalf("first AdvanceNext = (%v, %v), want (3s, true)", d, ok)
	}
	if strings.Join(fired, ",") != "a,b,b+0" {
		t.Fatalf("fired %v, want a,b,b+0", fired)
	}
	if d, ok := clk.AdvanceNext(); !ok || d != 2*time.Second {
		t.Fatalf("second AdvanceNext = (%v, %v), want (2s, true)", d, ok)
	}
	if clk.Pending() != 0 {
		t.Fatalf("%d timers still pending", clk.Pending())
	}
}

func TestFakeCallbackPanicIsReportedAndClockStaysUsable(t *testing.T) {
	rec := &recorder{}
	clk := clock.NewFake(rec, epoch)
	var order []string
	clk.AfterFunc(time.Second, func() { order = append(order, "before") })
	clk.AfterFunc(time.Second, func() { panic("boom") })
	clk.AfterFunc(time.Second, func() { order = append(order, "after") })

	if n := clk.Advance(time.Second); n != 3 {
		t.Fatalf("Advance fired %d timers, want 3", n)
	}
	msgs := rec.messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "panicked: boom") {
		t.Fatalf("reported %q, want one panic report", msgs)
	}
	if strings.Join(order, ",") != "before,after" {
		t.Fatalf("callbacks around the panic ran as %v", order)
	}

	// The lock must not be left held: every method still works.
	done := make(chan struct{})
	go func() {
		defer close(done)
		tm := clk.NewTimer(time.Second)
		clk.Advance(time.Second)
		<-tm.C()
		_ = clk.Pending()
		_ = clk.Now()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Fake is deadlocked after a callback panic")
	}
}

// TestFakeCallbackPanicInEveryAdvance: a panicking callback must not break
// the lock (which would end the test binary with "fatal error: sync: unlock
// of unlocked mutex") no matter which advance method runs it.
func TestFakeCallbackPanicInEveryAdvance(t *testing.T) {
	for name, advance := range map[string]func(*clock.Fake){
		"Advance":     func(c *clock.Fake) { c.Advance(time.Second) },
		"AdvanceTo":   func(c *clock.Fake) { c.AdvanceTo(c.Now().Add(time.Second)) },
		"AdvanceNext": func(c *clock.Fake) { c.AdvanceNext() },
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			clk := clock.NewFake(rec, epoch)
			clk.AfterFunc(time.Second, func() { panic(name) })
			after := clk.NewTimer(time.Second)
			advance(clk)
			if msgs := rec.messages(); len(msgs) != 1 || !strings.Contains(msgs[0], "panicked: "+name) {
				t.Fatalf("reported %q", msgs)
			}
			if !received(after) {
				t.Fatal("timer due with the panicking callback did not fire")
			}
			clk.AfterFunc(time.Second, func() {})
			if d, ok := clk.AdvanceNext(); !ok || d != time.Second {
				t.Fatalf("clock unusable after the panic: AdvanceNext = %v, %v", d, ok)
			}
		})
	}
}

// TestFakePanicReportNamesTheFiredDeadline: the report of a panicking
// callback names the deadline it fired for, even when another goroutine
// re-arms the timer while the panic is being reported.
func TestFakePanicReportNamesTheFiredDeadline(t *testing.T) {
	rec := &recorder{}
	clk := clock.NewFake(rec, epoch)
	entered := make(chan struct{})
	tm := clk.AfterFunc(time.Second, func() {
		close(entered)
		panic("boom")
	})
	reset := make(chan struct{})
	go func() {
		defer close(reset)
		<-entered
		tm.Reset(time.Hour)
	}()
	clk.Advance(time.Second)
	<-reset
	want := "due at " + epoch.Add(time.Second).String() + " panicked: boom"
	if msgs := rec.messages(); len(msgs) != 1 || !strings.Contains(msgs[0], want) {
		t.Fatalf("reported %q, want one report containing %q", msgs, want)
	}
	tm.Stop()
}

func TestFakeNilReporterSwallowsPanic(t *testing.T) {
	clk := clock.NewFake(nil, epoch)
	clk.AfterFunc(0, func() { panic("ignored") })
	if n := clk.Advance(0); n != 1 {
		t.Fatalf("Advance fired %d timers, want 1", n)
	}
}

func TestFakeCallbacksMayUseTheClock(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	var victim clock.Timer
	var ticks int
	var self clock.Timer
	self = clk.AfterFunc(time.Second, func() {
		ticks++
		if victim.Stop() != (ticks == 1) {
			t.Errorf("tick %d: unexpected Stop result for victim", ticks)
		}
		if ticks < 3 {
			if self.Reset(time.Second) {
				t.Error("Reset of the running timer reported it pending")
			}
		}
	})
	victim = clk.AfterFunc(2*time.Second, func() { t.Error("stopped timer fired") })
	clk.Advance(10 * time.Second)
	if ticks != 3 {
		t.Fatalf("self-resetting timer ticked %d times, want 3", ticks)
	}
}

func TestFakeZeroDelayLoopIsCutOff(t *testing.T) {
	if testing.Short() {
		t.Skip("fires a million timers")
	}
	rec := &recorder{}
	clk := clock.NewFake(rec, epoch)
	var rearm func()
	rearm = func() { clk.AfterFunc(0, rearm) }
	clk.AfterFunc(0, rearm)
	n := clk.Advance(time.Second)
	if n != 1<<20 {
		t.Fatalf("Advance fired %d timers, want the 1<<20 cap", n)
	}
	if msgs := rec.messages(); len(msgs) != 1 || !strings.Contains(msgs[0], "re-arms itself") {
		t.Fatalf("reported %q", msgs)
	}
	if clk.Pending() != 1 {
		t.Fatalf("pending %d, want the re-armed timer", clk.Pending())
	}
}

func TestFakeWaitPending(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	fired := make(chan struct{})
	go func() {
		<-clk.NewTimer(time.Minute).C()
		close(fired)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := clk.WaitPending(ctx, 1); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	<-fired

	short, cancelShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelShort()
	err := clk.WaitPending(short, 1)
	if err == nil || !strings.Contains(err.Error(), "0 timers pending, want at least 1") {
		t.Fatalf("WaitPending with nothing armed = %v", err)
	}
}

// TestFakeConcurrentUse checks under -race that concurrent creation, Stop and
// Reset never lose or duplicate a firing while another goroutine advances.
func TestFakeConcurrentUse(t *testing.T) {
	clk := clock.NewFake(t, epoch)
	const workers, perWorker = 8, 200
	var fired, stopped atomic.Int64
	var wg sync.WaitGroup
	stopAdvancing := make(chan struct{})
	var advancer sync.WaitGroup
	advancer.Add(1)
	go func() {
		defer advancer.Done()
		prev := clk.Now()
		for {
			select {
			case <-stopAdvancing:
				return
			default:
				clk.Advance(time.Millisecond)
				now := clk.Now()
				if now.Before(prev) {
					t.Error("Now went backwards")
					return
				}
				prev = now
			}
		}
	}()
	for w := range workers {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed, seed))
			for range perWorker {
				tm := clk.AfterFunc(time.Duration(rng.IntN(5))*time.Millisecond, func() { fired.Add(1) })
				switch rng.IntN(3) {
				case 0:
					if tm.Stop() {
						stopped.Add(1)
					}
				case 1:
					if !tm.Reset(time.Duration(rng.IntN(5)) * time.Millisecond) {
						// It had fired already; Reset armed it again.
						fired.Add(-1)
					}
				}
				_ = clk.Now()
			}
		}(uint64(w))
	}
	wg.Wait()
	close(stopAdvancing)
	advancer.Wait()
	clk.Advance(time.Hour)
	if got, want := fired.Load(), int64(workers*perWorker)-stopped.Load(); got != want {
		t.Fatalf("fired %d, want %d (created %d, stopped %d)", got, want, workers*perWorker, stopped.Load())
	}
	if clk.Pending() != 0 {
		t.Fatalf("%d timers left pending", clk.Pending())
	}
}

func BenchmarkFakeAfterFuncAdvance(b *testing.B) {
	clk := clock.NewFake(b, epoch)
	fn := func() {}
	for b.Loop() {
		clk.AfterFunc(time.Millisecond, fn)
		clk.Advance(time.Millisecond)
	}
}

func BenchmarkFakeTimerStop(b *testing.B) {
	clk := clock.NewFake(b, epoch)
	for b.Loop() {
		clk.NewTimer(time.Second).Stop()
	}
}

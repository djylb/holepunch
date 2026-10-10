package clock_test

import (
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/clock"
)

// driver runs the same timer scenario against System and Fake, so that the
// Fake cannot drift from the semantics of package time.
type driver struct {
	name string
	clk  clock.Clock
	// elapse lets d (plus scheduling slack for System) pass.
	elapse func(d time.Duration)
}

const unit = 5 * time.Millisecond

func drivers(t *testing.T) []driver {
	fake := clock.NewFake(t, epoch)
	return []driver{
		{name: "System", clk: clock.System{}, elapse: func(d time.Duration) { time.Sleep(d + 50*time.Millisecond) }},
		{name: "Fake", clk: fake, elapse: func(d time.Duration) { fake.Advance(d) }},
	}
}

func received(tm clock.Timer) bool {
	select {
	case <-tm.C():
		return true
	default:
		return false
	}
}

// waitRun waits for an AfterFunc callback, which System runs on its own
// goroutine and Fake runs synchronously inside elapse.
func waitRun(t *testing.T, ran <-chan struct{}) {
	t.Helper()
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("AfterFunc callback did not run")
	}
}

func TestConformance(t *testing.T) {
	for _, d := range drivers(t) {
		t.Run(d.name, func(t *testing.T) {
			t.Run("StopBeforeExpiry", func(t *testing.T) {
				tm := d.clk.NewTimer(unit)
				if !tm.Stop() {
					t.Fatal("Stop of a pending timer returned false")
				}
				d.elapse(unit)
				if received(tm) {
					t.Fatal("stopped timer delivered a value")
				}
				if tm.Stop() {
					t.Fatal("second Stop returned true")
				}
			})
			t.Run("StopAfterUnreceivedExpiry", func(t *testing.T) {
				tm := d.clk.NewTimer(unit)
				d.elapse(unit)
				if !tm.Stop() {
					t.Fatal("Stop with an unreceived expiry returned false")
				}
				if received(tm) {
					t.Fatal("stale value received after Stop")
				}
			})
			t.Run("StopAfterReceive", func(t *testing.T) {
				tm := d.clk.NewTimer(unit)
				d.elapse(unit)
				<-tm.C()
				if tm.Stop() {
					t.Fatal("Stop after the value was received returned true")
				}
			})
			t.Run("ResetAfterUnreceivedExpiry", func(t *testing.T) {
				tm := d.clk.NewTimer(unit)
				d.elapse(unit)
				if !tm.Reset(4 * unit) {
					t.Fatal("Reset with an unreceived expiry returned false")
				}
				if received(tm) {
					t.Fatal("stale value received after Reset")
				}
				d.elapse(4 * unit)
				if !received(tm) {
					t.Fatal("reset timer did not fire")
				}
			})
			t.Run("AfterFuncStop", func(t *testing.T) {
				ran := make(chan struct{}, 1)
				tm := d.clk.AfterFunc(unit, func() { ran <- struct{}{} })
				if tm.C() != nil {
					t.Fatal("AfterFunc timer has a channel")
				}
				if !tm.Stop() {
					t.Fatal("Stop of a pending AfterFunc returned false")
				}
				d.elapse(unit)
				select {
				case <-ran:
					t.Fatal("stopped AfterFunc ran")
				default:
				}
			})
			t.Run("AfterFuncResetAfterRun", func(t *testing.T) {
				ran := make(chan struct{}, 2)
				tm := d.clk.AfterFunc(unit, func() { ran <- struct{}{} })
				d.elapse(unit)
				waitRun(t, ran)
				if tm.Stop() {
					t.Fatal("Stop after the callback ran returned true")
				}
				if tm.Reset(unit) {
					t.Fatal("Reset after the callback ran returned true")
				}
				d.elapse(unit)
				waitRun(t, ran)
			})
			t.Run("AfterFuncNilIsNoOp", func(t *testing.T) {
				pending := d.clk.AfterFunc(time.Hour, nil)
				if !pending.Stop() {
					t.Fatal("Stop of a pending nil AfterFunc returned false")
				}
				tm := d.clk.AfterFunc(unit, nil)
				d.elapse(unit)
				if tm.Stop() {
					t.Fatal("nil AfterFunc did not fire")
				}
				if tm.Reset(unit) {
					t.Fatal("Reset of a fired nil AfterFunc returned true")
				}
				d.elapse(unit)
			})
		})
	}
}

func TestSystemNowIsMonotonic(t *testing.T) {
	now := clock.System{}.Now()
	if now == now.Round(0) {
		t.Fatal("System.Now has no monotonic reading")
	}
}

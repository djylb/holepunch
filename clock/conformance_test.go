package clock_test

import (
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/testkit"
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
				resetAt := d.clk.Now()
				if !tm.Reset(4 * unit) {
					t.Fatal("Reset with an unreceived expiry returned false")
				}
				// On a slow machine the new expiry may already be due; a value
				// from before the new deadline is the stale one.
				select {
				case v := <-tm.C():
					if v.Before(resetAt.Add(4 * unit)) {
						t.Fatalf("stale value %v received after Reset at %v", v, resetAt)
					}
					return
				default:
				}
				// System's timer may fire after the elapse on a slow machine.
				d.elapse(4 * unit)
				select {
				case <-tm.C():
				case <-time.After(5 * time.Second):
					t.Fatal("reset timer did not fire")
				}
			})
			t.Run("AfterFuncStop", func(t *testing.T) {
				ran := make(chan struct{}, 1)
				created := d.clk.Now()
				tm := d.clk.AfterFunc(unit, func() { ran <- struct{}{} })
				if tm.C() != nil {
					t.Fatal("AfterFunc timer has a channel")
				}
				if !tm.Stop() {
					// Legitimate only if the deadline passed before Stop, which a
					// slow machine can cause for System; then the callback runs.
					if d.clk.Now().Sub(created) < unit {
						t.Fatal("Stop of a pending AfterFunc returned false")
					}
					waitRun(t, ran)
					return
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
				// The nil callback cannot be observed, so its firing is: Reset
				// reports a pending timer, and re-arms it, until it has fired.
				// One elapse suffices unless System's timer fires late. The
				// Reset that finds it fired re-arms it, and it fires again.
				tm := d.clk.AfterFunc(unit, nil)
				deadline := time.Now().Add(testkit.WaitBound(t))
				for range 2 {
					for d.elapse(unit); tm.Reset(unit); d.elapse(unit) {
						if time.Now().After(deadline) {
							t.Fatal("nil AfterFunc did not fire")
						}
					}
				}
				tm.Stop()
			})
		})
	}
}

func TestSystemNowIsMonotonic(t *testing.T) {
	// Time.String ends in "m=±<value>" exactly when a monotonic reading is
	// present; Equal would ignore it.
	now := clock.System{}.Now()
	if !strings.Contains(now.String(), " m=") {
		t.Fatalf("System.Now has no monotonic reading: %s", now)
	}
}

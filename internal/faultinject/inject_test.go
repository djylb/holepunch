//go:build holepunch_faultinject

package faultinject_test

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
)

// documentedPoints is the full list of injection points, with
// coord.finish.<step> expanded for one step.
var documentedPoints = []string{
	"attach.read_start", "probe.bind", "probe.send", "probe.recv", "portmap.map", "portmap.renew",
	"ctl.read", "ctl.write", "wait.summary", "wait.go", "round.stage", "readloop.packet",
	"nomination.retry", "assist.handle", "handover.ack", "finalize.disown", "result.write",
	"progress.deliver",
	"coord.attach", "coord.handle.report", "coord.handle.ready", "coord.plan", "coord.memory",
	"coord.timer", "coord.callback", "coord.finish.notify", "coord.close",
	"natprobe.packet", "natprobe.extra", "natprobe.sweep",
}

// fresh resets the registry before and after a test.
func fresh(t *testing.T) {
	faultinject.Reset()
	t.Cleanup(faultinject.Reset)
}

func TestDocumentedPointsCanBeArmed(t *testing.T) {
	fresh(t)
	for _, name := range documentedPoints {
		disarm := faultinject.Arm(name, faultinject.Error(nil), 1)
		err := faultinject.Point(name)
		if !errors.Is(err, faultinject.ErrInjected) || !strings.Contains(err.Error(), name) {
			t.Errorf("Point(%q) = %v, want an injected error naming the point", name, err)
		}
		disarm()
	}
}

func TestUnarmedPointOnlyCounts(t *testing.T) {
	fresh(t)
	for range 3 {
		if err := faultinject.Point("probe.recv"); err != nil {
			t.Fatalf("unarmed Point = %v", err)
		}
	}
	if faultinject.Hits("probe.recv") != 3 || faultinject.Fired("probe.recv") != 0 {
		t.Fatalf("Hits %d Fired %d, want 3 and 0", faultinject.Hits("probe.recv"), faultinject.Fired("probe.recv"))
	}
}

func TestNthFiresOnce(t *testing.T) {
	fresh(t)
	_ = faultinject.Point("probe.bind") // hits before Arm do not count towards nth
	defer faultinject.Arm("probe.bind", faultinject.Error(nil), 3)()
	for i := 1; i <= 5; i++ {
		err := faultinject.Point("probe.bind")
		if want := i == 3; (err != nil) != want {
			t.Fatalf("call %d: Point = %v, want error %v", i, err, want)
		}
	}
	if faultinject.Hits("probe.bind") != 6 || faultinject.Fired("probe.bind") != 1 {
		t.Fatalf("Hits %d Fired %d, want 6 and 1", faultinject.Hits("probe.bind"), faultinject.Fired("probe.bind"))
	}
}

func TestNonPositiveNthFiresEveryTimeUntilDisarmed(t *testing.T) {
	fresh(t)
	disarm := faultinject.Arm("probe.bind", faultinject.Error(nil), 0)
	for i := range 4 {
		if err := faultinject.Point("probe.bind"); err == nil {
			t.Fatalf("call %d did not fire", i+1)
		}
	}
	disarm()
	disarm()
	if err := faultinject.Point("probe.bind"); err != nil {
		t.Fatalf("Point after disarm = %v", err)
	}
	if n := faultinject.Fired("probe.bind"); n != 4 {
		t.Fatalf("Fired = %d, want 4", n)
	}
}

func TestErrorReturnsGivenErrorUnchanged(t *testing.T) {
	fresh(t)
	want := errors.New("bind refused")
	defer faultinject.Arm("probe.bind", faultinject.Error(want), 1)()
	if err := faultinject.Point("probe.bind"); err != want {
		t.Fatalf("Point = %v, want the armed error itself", err)
	}
}

func TestPanicWrapsErrInjected(t *testing.T) {
	fresh(t)
	defer faultinject.Arm("coord.finish.notify", faultinject.Panic(), 1)()
	defer func() {
		err, ok := recover().(error)
		if !ok || !errors.Is(err, faultinject.ErrInjected) || !strings.Contains(err.Error(), "coord.finish.notify") {
			t.Fatalf("recovered %v, want an error wrapping ErrInjected naming the point", err)
		}
	}()
	_ = faultinject.Point("coord.finish.notify")
	t.Fatal("Point did not panic")
}

func TestPanicDoesNotPoisonRegistry(t *testing.T) {
	fresh(t)
	defer faultinject.Arm("ctl.read", faultinject.Panic(), 1)()
	func() {
		defer func() { _ = recover() }()
		_ = faultinject.Point("ctl.read")
	}()
	done := make(chan error, 1)
	go func() { done <- faultinject.Point("ctl.read") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second Point = %v, want nil (nth = 1 fired already)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("registry is locked after an injected panic")
	}
}

func TestCloseConn(t *testing.T) {
	fresh(t)
	defer faultinject.Arm("ctl.read", faultinject.CloseConn(), 1)()
	err := faultinject.Point("ctl.read")
	for _, target := range []error{faultinject.ErrCloseConn, faultinject.ErrInjected, net.ErrClosed} {
		if !errors.Is(err, target) {
			t.Fatalf("Point = %v, want it to match %v", err, target)
		}
	}
	if !errors.Is(faultinject.ErrCloseConn, faultinject.ErrInjected) {
		t.Fatal("ErrCloseConn does not match ErrInjected")
	}
}

func TestStallUntilDisarm(t *testing.T) {
	fresh(t)
	disarm := faultinject.Arm("wait.go", faultinject.Stall(0), 1)
	done := make(chan error, 1)
	go func() { done <- faultinject.Point("wait.go") }()
	select {
	case err := <-done:
		t.Fatalf("stalled point returned %v before disarm", err)
	case <-time.After(50 * time.Millisecond):
	}
	disarm()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("released point returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("disarm did not release the stalled caller")
	}
}

func TestStallForDuration(t *testing.T) {
	fresh(t)
	defer faultinject.Arm("ctl.write", faultinject.Stall(30*time.Millisecond), 1)()
	start := time.Now()
	if err := faultinject.Point("ctl.write"); err != nil {
		t.Fatalf("Point = %v", err)
	}
	if d := time.Since(start); d < 30*time.Millisecond {
		t.Fatalf("stalled for %v, want at least 30ms", d)
	}
}

func TestDisarmCutsTimedStallShort(t *testing.T) {
	fresh(t)
	disarm := faultinject.Arm("ctl.write", faultinject.Stall(time.Hour), 1)
	done := make(chan struct{})
	go func() {
		_ = faultinject.Point("ctl.write")
		close(done)
	}()
	waitFired(t, "ctl.write", 1)
	disarm()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("disarm did not release the stalled caller")
	}
}

func TestRearmReplacesAndReleases(t *testing.T) {
	fresh(t)
	first := faultinject.Arm("round.stage", faultinject.Stall(0), 1)
	done := make(chan struct{})
	go func() {
		_ = faultinject.Point("round.stage")
		close(done)
	}()
	waitFired(t, "round.stage", 1)
	second := faultinject.Arm("round.stage", faultinject.Error(nil), 0)
	defer second()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("re-arming did not release the caller stalled by the old arm")
	}
	first() // disarming the replaced arm must not remove the new one
	if err := faultinject.Point("round.stage"); !errors.Is(err, faultinject.ErrInjected) {
		t.Fatalf("Point = %v, want the new arm's error", err)
	}
}

func TestResetReleasesAndClears(t *testing.T) {
	fresh(t)
	faultinject.Arm("wait.summary", faultinject.Stall(0), 0)
	done := make(chan struct{})
	go func() {
		_ = faultinject.Point("wait.summary")
		close(done)
	}()
	waitFired(t, "wait.summary", 1)
	faultinject.Reset()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Reset did not release the stalled caller")
	}
	if faultinject.Hits("wait.summary") != 0 || faultinject.Fired("wait.summary") != 0 {
		t.Fatal("Reset kept the counters")
	}
	if err := faultinject.Point("wait.summary"); err != nil {
		t.Fatalf("Point after Reset = %v", err)
	}
}

func TestArmRejectsMistakes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		point  string
		action faultinject.Action
	}{
		{"single part", "probe", faultinject.Panic()},
		{"upper case", "Probe.bind", faultinject.Panic()},
		{"empty part", "probe..bind", faultinject.Panic()},
		{"trailing dot", "probe.", faultinject.Panic()},
		{"leading digit", "probe.1bind", faultinject.Panic()},
		{"leading underscore", "probe._bind", faultinject.Panic()},
		{"hyphen", "probe.re-bind", faultinject.Panic()},
		{"placeholder", "coord.finish.<step>", faultinject.Panic()},
		{"zero action", "probe.bind", faultinject.Action{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Arm accepted a mistake")
				}
			}()
			faultinject.Arm(tc.point, tc.action, 1)
		})
	}
}

func TestActionString(t *testing.T) {
	for want, a := range map[string]faultinject.Action{
		"panic":               faultinject.Panic(),
		"error":               faultinject.Error(nil),
		`error("eof")`:        faultinject.Error(errors.New("eof")),
		"stall(1.5s)":         faultinject.Stall(1500 * time.Millisecond),
		"stall(until disarm)": faultinject.Stall(0),
		"close-conn":          faultinject.CloseConn(),
		"invalid":             {},
	} {
		if got := a.String(); got != want {
			t.Errorf("String = %q, want %q", got, want)
		}
	}
}

// TestConcurrentHitsAreCountedExactly runs under -race: an every-call arm
// fires for each of 200 concurrent calls, a one-shot arm exactly once, and
// concurrent disarms are safe.
func TestConcurrentHitsAreCountedExactly(t *testing.T) {
	fresh(t)
	every := faultinject.Arm("readloop.packet", faultinject.Error(nil), 0)
	once := faultinject.Arm("probe.send", faultinject.Error(nil), 50)
	var everyErrs, onceErrs atomic.Int32
	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if faultinject.Point("readloop.packet") != nil {
				everyErrs.Add(1)
			}
			if faultinject.Point("probe.send") != nil {
				onceErrs.Add(1)
			}
			_ = faultinject.Point("probe.recv")
		}()
	}
	wg.Wait()
	if everyErrs.Load() != 200 || onceErrs.Load() != 1 || faultinject.Hits("probe.recv") != 200 {
		t.Fatalf("every-call fired %d, one-shot fired %d, unarmed hits %d", everyErrs.Load(), onceErrs.Load(), faultinject.Hits("probe.recv"))
	}
	for range 4 {
		wg.Add(2)
		go func() { defer wg.Done(); every() }()
		go func() { defer wg.Done(); once() }()
	}
	wg.Wait()
	if err := faultinject.Point("readloop.packet"); err != nil {
		t.Fatalf("Point after disarm = %v", err)
	}
}

func waitFired(t *testing.T, name string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for faultinject.Fired(name) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%s fired %d times, want %d", name, faultinject.Fired(name), n)
		}
		time.Sleep(time.Millisecond)
	}
}

package clock

import (
	"container/heap"
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"
)

// Reporter receives failures detected by a Fake, such as a panicking AfterFunc
// callback. *testing.T and *testing.B satisfy it. Errorf must not stop the
// calling goroutine (do not pass a Fatalf wrapper): it is called from whatever
// goroutine advances the clock.
type Reporter interface {
	Errorf(format string, args ...any)
}

// maxFiresPerAdvance bounds a single advance so that a zero-delay timer that
// keeps re-arming itself fails the test instead of hanging it.
const maxFiresPerAdvance = 1 << 20

// Fake is a manually advanced Clock for tests.
//
// Time stands still until the test calls Advance, AdvanceTo or AdvanceNext.
// Timers due at or before the new time then fire one by one in order of
// deadline and, for equal deadlines, creation; Now reports each timer's
// deadline while it fires. Timers created by callbacks during an advance fire
// in the same advance if they fall due before its target. A timer created with
// d <= 0 is due immediately and fires on the next advance, Advance(0)
// included.
type Fake struct {
	r Reporter

	mu      sync.Mutex
	now     time.Time
	seq     uint64        // creation counter, the tie-breaker for equal deadlines
	timers  timerHeap     // pending timers
	changed chan struct{} // closed when the pending set changes; nil while nobody waits
}

var _ Clock = (*Fake)(nil)

// NewFake returns a Fake whose current time is start, without its monotonic
// reading. A zero start is replaced by 2026-01-01 UTC so that Now never
// returns the zero Time, which code commonly treats as "unset". Panics
// raised by AfterFunc callbacks are reported to r as test failures; r should
// be the test's *testing.T.
func NewFake(r Reporter, start time.Time) *Fake {
	if start.IsZero() {
		start = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	}
	return &Fake{r: r, now: start.Round(0)}
}

// Now returns the fake current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// NewTimer returns a timer whose channel receives the fake time at which it
// fires.
func (f *Fake) NewTimer(d time.Duration) Timer {
	t := &fakeTimer{f: f, index: -1, ch: make(chan time.Time, 1)}
	f.start(t, d)
	return t
}

// AfterFunc returns a timer that calls fn on the advancing goroutine when it
// fires. A nil fn is a no-op, as with System.
func (f *Fake) AfterFunc(d time.Duration, fn func()) Timer {
	if fn == nil {
		fn = func() {}
	}
	t := &fakeTimer{f: f, index: -1, fn: fn}
	f.start(t, d)
	return t
}

// Advance moves the clock forward by d, firing every timer that falls due,
// and returns how many fired. A negative d is treated as zero.
func (f *Fake) Advance(d time.Duration) int {
	if d < 0 {
		d = 0
	}
	return f.AdvanceTo(f.Now().Add(d))
}

// AdvanceTo moves the clock forward to target, firing every timer due at or
// before it, and returns how many fired. The clock never moves backwards: a
// target in the past only fires the timers that are already due.
func (f *Fake) AdvanceTo(target time.Time) int {
	fired := 0
	for {
		if fired == maxFiresPerAdvance {
			f.report("clock: %d timers fired in one advance; a zero-delay timer probably re-arms itself", fired)
			break
		}
		t, ok := f.popDue(target)
		if !ok {
			break
		}
		fired++
		if t.fn != nil {
			f.run(t)
		}
	}
	f.moveTo(target)
	return fired
}

// AdvanceNext moves the clock to the earliest pending deadline and fires the
// timers due then. It returns how far the clock moved and false if no timer
// was pending, in which case the clock is unchanged.
func (f *Fake) AdvanceNext() (time.Duration, bool) {
	now, next, ok := f.peek()
	if !ok {
		return 0, false
	}
	f.AdvanceTo(next)
	if next.Before(now) {
		return 0, true
	}
	return next.Sub(now), true
}

// Next returns the earliest pending deadline, and false when no timer is
// pending. Tests use it to assert which timeout the code under test armed.
func (f *Fake) Next() (time.Time, bool) {
	_, next, ok := f.peek()
	return next, ok
}

// Pending returns the number of timers that have not fired and have not been
// stopped.
func (f *Fake) Pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.timers)
}

// WaitPending blocks until at least n timers are pending or ctx ends. Tests
// use it to wait, in real time, until the code under test has armed the
// timers it is about to block on, before advancing the clock past them.
func (f *Fake) WaitPending(ctx context.Context, n int) error {
	for {
		got, changed := f.pendingOrWatch(n)
		if changed == nil {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("clock: %d timers pending, want at least %d: %w", got, n, context.Cause(ctx))
		}
	}
}

func (f *Fake) start(t *fakeTimer, d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	t.seq = f.seq
	f.scheduleLocked(t, d)
}

func (f *Fake) scheduleLocked(t *fakeTimer, d time.Duration) {
	if d < 0 {
		d = 0
	}
	t.when = f.now.Add(d)
	heap.Push(&f.timers, t)
	f.notifyLocked()
}

// unscheduleLocked removes t from the pending set and discards an expiry that
// was delivered but not received, reporting whether either was present.
func (f *Fake) unscheduleLocked(t *fakeTimer) bool {
	pending := false
	if t.index >= 0 {
		heap.Remove(&f.timers, t.index)
		f.notifyLocked()
		pending = true
	}
	if t.ch != nil {
		select {
		case <-t.ch:
			pending = true
		default:
		}
	}
	return pending
}

// popDue removes the earliest timer if it is due at target (or at the current
// time, whichever is later), moves the clock to its deadline and, for a
// channel timer, delivers the expiry. Delivery happens under the lock so that
// Stop and Reset observe "pending" or "delivered" atomically.
func (f *Fake) popDue(target time.Time) (*fakeTimer, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.now.After(target) {
		target = f.now
	}
	if len(f.timers) == 0 || f.timers[0].when.After(target) {
		return nil, false
	}
	t := heap.Pop(&f.timers).(*fakeTimer)
	f.notifyLocked()
	if t.when.After(f.now) {
		f.now = t.when
	}
	if t.ch != nil {
		select {
		case t.ch <- f.now:
		default:
		}
	}
	return t, true
}

func (f *Fake) moveTo(target time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if target.After(f.now) {
		f.now = target
	}
}

func (f *Fake) peek() (now, next time.Time, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.timers) == 0 {
		return f.now, time.Time{}, false
	}
	return f.now, f.timers[0].when, true
}

func (f *Fake) pendingOrWatch(n int) (int, <-chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.timers) >= n {
		return len(f.timers), nil
	}
	if f.changed == nil {
		f.changed = make(chan struct{})
	}
	return len(f.timers), f.changed
}

func (f *Fake) notifyLocked() {
	if f.changed != nil {
		close(f.changed)
		f.changed = nil
	}
}

// run calls an AfterFunc callback without holding the lock. A panic is
// recovered and reported as a test failure: re-panicking would kill the test
// binary, and FailNow is not allowed off the test goroutine.
func (f *Fake) run(t *fakeTimer) {
	defer func() {
		if r := recover(); r != nil {
			f.report("clock: AfterFunc callback due at %v panicked: %v\n%s", t.when, r, debug.Stack())
		}
	}()
	t.fn()
}

func (f *Fake) report(format string, args ...any) {
	if f.r != nil {
		f.r.Errorf(format, args...)
	}
}

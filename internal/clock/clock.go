package clock

import "time"

// Clock is the time source of the library. Every timeout and deadline in the
// client runtime and in coord is measured with it, so that a Fake can drive
// all of them in tests.
//
// Now must carry a monotonic reading when durations are derived from it;
// System does.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// NewTimer returns a timer that delivers its expiry time on C after d.
	NewTimer(d time.Duration) Timer
	// AfterFunc returns a timer that calls f in its own goroutine (System) or
	// on the advancing goroutine (Fake) after d. A nil f is a no-op.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a single-shot timer created by a Clock.
type Timer interface {
	// C returns the channel on which the expiry time is delivered. It is nil
	// for timers created by AfterFunc.
	C() <-chan time.Time
	// Stop prevents the timer from firing. It returns true if the call
	// stopped the timer, including the case where a channel timer had expired
	// but its value had not been received yet; that value is discarded.
	Stop() bool
	// Reset reschedules the timer to fire after d, discarding an expiry that
	// has not been received yet. It returns true if the timer was pending.
	Reset(d time.Duration) bool
}

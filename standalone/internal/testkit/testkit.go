// Package testkit holds the polling waits the module's tests share, bounded
// by the test binary's deadline instead of a fixed timeout. It is test
// support only, never linked by a program, and depends on the standard
// library only.
package testkit

import (
	"testing"
	"time"
)

// maxPoll is the longest pause between two polls of WaitFor.
const maxPoll = 16 * time.Millisecond

// WaitBound is how long a test waits for something that must happen in real
// time: until shortly before the test binary's deadline, so that a loaded
// machine — every package's tests in parallel under the race detector —
// slows the test down instead of failing it. Without a deadline (go test
// -timeout 0, a benchmark or a fuzz target) it is a minute.
func WaitBound(tb testing.TB) time.Duration {
	if t, ok := tb.(interface{ Deadline() (time.Time, bool) }); ok {
		if d, ok := t.Deadline(); ok {
			return max(time.Until(d)*9/10, time.Second)
		}
	}
	return time.Minute
}

// WaitFor polls cond until it holds and fails tb, naming what it waited
// for, when it still does not after WaitBound. The pause between polls
// starts at a millisecond and doubles up to maxPoll. It must be called from
// the test's goroutine, like tb.Fatal.
func WaitFor(tb testing.TB, what string, cond func() bool) {
	tb.Helper()
	bound := WaitBound(tb)
	deadline := time.Now().Add(bound)
	pause := time.Millisecond
	for !cond() {
		if time.Now().After(deadline) {
			tb.Fatalf("timed out after %v waiting for %s", bound, what)
		}
		tm := time.NewTimer(pause)
		<-tm.C
		pause = min(2*pause, maxPoll)
	}
}

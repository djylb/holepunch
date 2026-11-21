package testkit

import (
	"sync/atomic"
	"time"

	"github.com/djylb/timeshim"
)

// PanicClock is Clock with panics injected: before each call of Now or
// AfterFunc (which timeshim.NewTimer calls too), Panic is called with the
// method's name, and a non-nil result is panicked with instead of making the call. A nil Panic
// injects nothing. It stands in for a user clock with a bug, or for any
// panic at the point the code under test reads the time.
type PanicClock struct {
	timeshim.Clock
	Panic func(method string) any
}

func (c PanicClock) inject(method string) {
	if c.Panic == nil {
		return
	}
	if v := c.Panic(method); v != nil {
		panic(v)
	}
}

// Now implements timeshim.Clock.
func (c PanicClock) Now() time.Time {
	c.inject("Now")
	return c.Clock.Now()
}

// AfterFunc implements timeshim.Clock.
func (c PanicClock) AfterFunc(d time.Duration, f func()) timeshim.Timer {
	c.inject("AfterFunc")
	return c.Clock.AfterFunc(d, f)
}

// StepClock is a timeshim.Fake whose reading can also step backwards, as a
// wall clock does when it is set back, which a Fake never does: Now is the
// Fake's time shifted by the sum of the Steps. A Step moves no timer and
// fires none; timers keep the Fake's time.
type StepClock struct {
	*timeshim.Fake
	offset atomic.Int64
}

// NewStepClock returns a StepClock over timeshim.NewFake(start).
func NewStepClock(start time.Time) *StepClock {
	return &StepClock{Fake: timeshim.NewFake(start)}
}

// Now implements timeshim.Clock.
func (c *StepClock) Now() time.Time { return c.Fake.Now().Add(time.Duration(c.offset.Load())) }

// Step shifts the reading by d, which may be negative.
func (c *StepClock) Step(d time.Duration) { c.offset.Add(int64(d)) }

package clock

import "time"

// System is the real clock backed by package time. The zero value is ready to
// use.
type System struct{}

var _ Clock = System{}

// Now returns time.Now(), which carries a monotonic reading.
func (System) Now() time.Time { return time.Now() }

// NewTimer wraps time.NewTimer.
func (System) NewTimer(d time.Duration) Timer {
	t := time.NewTimer(d)
	return &systemTimer{t: t, c: t.C}
}

// AfterFunc wraps time.AfterFunc. A nil f is replaced by a no-op: package time
// would otherwise call the nil function on a fresh goroutine when the timer
// fires and crash the process.
func (System) AfterFunc(d time.Duration, f func()) Timer {
	if f == nil {
		f = func() {}
	}
	return &systemTimer{t: time.AfterFunc(d, f)}
}

type systemTimer struct {
	t *time.Timer
	c <-chan time.Time // nil for AfterFunc timers
}

func (s *systemTimer) C() <-chan time.Time        { return s.c }
func (s *systemTimer) Stop() bool                 { return s.t.Stop() }
func (s *systemTimer) Reset(d time.Duration) bool { return s.t.Reset(d) }

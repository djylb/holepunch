package life

import (
	"context"
	"sync"
	"time"
)

// Deadliner is the part of a connection InterruptRead needs.
type Deadliner interface {
	SetReadDeadline(t time.Time) error
}

// InterruptRead arranges for a blocked read on c to be interrupted when ctx
// ends, by moving c's read deadline into the past. It is the only place in
// the module that interrupts reads on a connection owned by someone else, and
// a session registers it once.
//
// The returned restore function:
//
//  1. waits for an interrupt that has started to finish, and only then clears
//     the read deadline, so the clearing is strictly ordered after the
//     interrupt and is never overwritten by it;
//  2. is idempotent and safe for concurrent use: later calls return the result
//     of the first without blocking on the interrupt again;
//  3. leaves c with a zero read deadline when it returns nil.
//
// It returns the error (or recovered panic) from clearing the deadline.
// Panics raised by c inside the interrupt are recovered.
func InterruptRead(ctx context.Context, c Deadliner) (restore func() error) {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		// time.Unix(1, 0) is in the past regardless of the wall clock and
		// cannot become "not yet reached" through clock adjustments.
		_ = Safe("interrupt-read", func() { _ = c.SetReadDeadline(time.Unix(1, 0)) })
	})
	var (
		once sync.Once
		err  error
	)
	return func() error {
		once.Do(func() {
			// stop reports false only when the callback has started: it is
			// called exactly once here, so "already stopped" cannot occur.
			if !stop() {
				<-done
			}
			if perr := Safe("restore-read", func() { err = c.SetReadDeadline(time.Time{}) }); perr != nil {
				err = perr
			}
		})
		return err
	}
}

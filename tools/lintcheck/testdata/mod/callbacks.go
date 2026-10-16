package mod

import (
	"context"
	"fmt"
	"sync"

	"example.com/mod/internal/life"
)

// Options holds user callbacks.
type Options struct {
	//holepunch:callback
	OnProgress func(string)
	OnDone     func() //holepunch:callback // a trailing comment is allowed
	Name       string
	//holepunch:callback // want "directive"
	Label string
	//holepunch:netimpl // want "directive"
	Bad func()
}

// Planner is implemented by users.
type Planner interface {
	//holepunch:callback
	Classify(x int) int
	Describe() string
}

type session struct {
	mu   sync.Mutex
	rw   sync.RWMutex
	opts Options
	pl   Planner
	//holepunch:callback
	onTick func()
}

// notify calls user code.
//
//holepunch:callback
func (s *session) notify(msg string) { s.opts.OnProgress(msg) }

func run(fn func()) { fn() }

func (s *session) underLock() {
	s.mu.Lock()
	s.opts.OnProgress("x") // want "callbacklock"
	s.mu.Unlock()
	s.opts.OnProgress("y")
}

func (s *session) deferredUnlock() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pl.Classify(1) // want "callbacklock"
}

func (s *session) readLock() {
	s.rw.RLock()
	s.opts.OnDone() // want "callbacklock"
	s.rw.RUnlock()
}

func (s *session) annotatedMembers() {
	s.mu.Lock()
	s.notify("x") // want "callbacklock"
	s.onTick()    // want "callbacklock"
	s.mu.Unlock()
}

func (s *session) closureRunsNow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	run(func() { s.opts.OnProgress("x") }) // want "callbacklock"
	_ = life.Safe("cb", func() {})         // want "callbacklock"
	_ = fmt.Errorf("not a callback")
	_ = s.pl.Describe()
}

func (s *session) lockInsideClosure() {
	_ = life.Safe("cb", func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.notify("x") // want "callbacklock"
	})
}

func (s *session) branchMayKeepLock(ok bool) {
	s.mu.Lock()
	if ok {
		s.mu.Unlock()
	}
	s.notify("maybe locked") // want "callbacklock"
}

func (s *session) loop(items []string) {
	for _, it := range items {
		s.mu.Lock()
		s.notify(it) // want "callbacklock"
		s.mu.Unlock()
	}
}

func (s *session) switchCase(k int) {
	switch k {
	case 1:
		s.mu.Lock()
	default:
		return
	}
	s.notify("locked in case 1") // want "callbacklock"
}

func (s *session) breakKeepsLock(items []string) {
	for range items {
		s.mu.Lock()
		if len(items) > 1 {
			break
		}
		s.mu.Unlock()
	}
	s.notify("left the loop holding the lock") // want "callbacklock"
}

func (s *session) labeledBreak(rows [][]int) {
outer:
	for _, row := range rows {
		for range row {
			s.mu.Lock()
			if len(row) > 1 {
				break outer
			}
			s.mu.Unlock()
		}
	}
	s.notify("left both loops holding the lock") // want "callbacklock"
}

func (s *session) snapshotThenCall() {
	s.mu.Lock()
	name := s.opts.Name
	s.mu.Unlock()
	s.opts.OnProgress(name)
}

func (s *session) earlyReturn(ok bool) {
	s.mu.Lock()
	if !ok {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.notify("ok")
}

func (s *session) bothBranchesUnlock(ok bool) {
	s.mu.Lock()
	if ok {
		s.mu.Unlock()
	} else {
		s.mu.Unlock()
	}
	s.notify("unlocked on both paths")
}

func (s *session) panicPath(ok bool) {
	s.mu.Lock()
	if !ok {
		panic("bad")
	}
	s.mu.Unlock()
	s.notify("unlocked")
}

func (s *session) continueUnlocks(items []string) {
	for range items {
		s.mu.Lock()
		if len(items) > 1 {
			s.mu.Unlock()
			continue
		}
		s.mu.Unlock()
	}
	s.notify("every path unlocked")
}

func (s *session) later(g *life.Group, clk interface{ AfterFunc(int, func()) }) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g.Go("progress", func(context.Context) { s.opts.OnProgress("later") })
	clk.AfterFunc(1, func() { s.notify("later") })
	defer func() { s.notify("deferred") }() // want "callbacklock"
	stored := func() { s.notify("stored") }
	_ = stored
}

func (s *session) deferredCallbacks() {
	defer s.notify("runs after the deferred unlock")
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.notify("runs before the deferred unlock") // want "callbacklock"
	defer s.opts.OnDone()                             // want "callbacklock"
}

func (s *session) deferredUnlocker() {
	s.mu.Lock()
	defer func() {
		s.notify("before the unlock in the literal") // want "callbacklock"
		s.mu.Unlock()
		s.notify("after it")
	}()
	defer s.notify("runs before the literal") // want "callbacklock"
}

func (s *session) explicitUnlockAfterDefer() {
	s.mu.Lock()
	defer s.notify("runs at return, after the explicit unlock")
	s.mu.Unlock()
}

func (s *session) deferredRelock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	func() {
		s.mu.Unlock()
		defer s.mu.Lock()
		defer s.notify("runs before the relock, with the lock released")
	}()
	defer s.notify("runs before the deferred unlock") // want "callbacklock"
}

func (s *session) literalUnderCallerLock() {
	s.mu.Lock()
	func() {
		defer s.notify("runs as the literal returns, the lock still held") // want "callbacklock"
	}()
	s.mu.Unlock()
	func() {
		defer s.notify("runs with the lock released")
	}()
}

func (s *session) releasedAroundLiteral() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mu.Unlock()
	func() {
		defer s.notify("the literal runs with the lock released")
	}()
	s.mu.Lock()
}

func (s *session) deferInDeferredLiteral() {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		defer s.notify("the literal runs before the deferred unlock") // want "callbacklock"
	}()
}

func (s *session) deferredLockBeforeUnlock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.mu.Lock()
	s.mu.Unlock()
	defer s.notify("runs before the relock, with the lock released")
}

func (s *session) deferredRunner(g *life.Group) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer run(func() { s.notify("run calls it before the deferred unlock") }) // want "callbacklock"
	defer g.Go("progress", func(context.Context) { s.notify("later") })
}

func (s *session) otherLock() {
	var other sync.Mutex
	other.Lock()
	other.Unlock()
	s.notify("released")
}

//go:build holepunch_faultinject

package faultinject

import (
	"fmt"
	"strings"
	"sync"
)

// arm is one armed point. seen and done are guarded by registry.mu.
type arm struct {
	action   Action
	nth      int
	seen     int
	released chan struct{}
	done     bool
}

// release wakes every caller stalled by a. Callers hold registry.mu.
func (a *arm) release() {
	if !a.done {
		a.done = true
		close(a.released)
	}
}

type registry struct {
	mu    sync.Mutex
	arms  map[string]*arm
	hits  map[string]int
	fired map[string]int
}

// reg is the process-wide set of armed points and counters. It exists only
// in the tagged test build; see the package documentation.
var reg = registry{arms: map[string]*arm{}, hits: map[string]int{}, fired: map[string]int{}}

// Arm makes the point name perform a. With nth >= 1 the action fires once, on
// the nth call of Point(name) counted from this Arm; with nth <= 0 it fires
// on every call. Arming a name that is already armed replaces the previous
// arm and releases the callers it stalled. disarm is idempotent, removes this
// arm only if it is still the current one, and releases the callers it
// stalled.
//
// Arm panics if name is not a well-formed point name or a is the zero Action:
// both are mistakes in the test, and an arm that cannot fire would make the
// test pass without injecting anything.
func Arm(name string, a Action, nth int) (disarm func()) {
	if !validName(name) {
		panic(fmt.Sprintf("faultinject: malformed point name %q, want <component>.<action>", name))
	}
	if a.kind == 0 {
		panic("faultinject: Arm with the zero Action")
	}
	ar := &arm{action: a, nth: nth, released: make(chan struct{})}
	reg.install(name, ar)
	return func() { reg.remove(name, ar) }
}

// Point marks a fault injection point. It counts the call and, when name is
// armed and due, performs the armed Action.
func Point(name string) error {
	a, released, ok := reg.hit(name)
	if !ok {
		return nil
	}
	return a.apply(name, released)
}

// Hits reports how many times Point(name) was called since the last Reset,
// armed or not. Tests use it to show that a point is reachable.
func Hits(name string) int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.hits[name]
}

// Fired reports how many times an armed action fired at name since the last
// Reset. Tests use it to prove that the fault was really injected.
func Fired(name string) int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.fired[name]
}

// Reset disarms every point, releasing stalled callers, and clears the
// counters. Tests register it with t.Cleanup.
func Reset() {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	for _, a := range reg.arms {
		a.release()
	}
	reg.arms = map[string]*arm{}
	reg.hits = map[string]int{}
	reg.fired = map[string]int{}
}

func (r *registry) install(name string, a *arm) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.arms[name]; old != nil {
		old.release()
	}
	r.arms[name] = a
}

func (r *registry) remove(name string, a *arm) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.arms[name] == a {
		delete(r.arms, name)
	}
	a.release()
}

// hit counts a call of Point and reports whether an arm fires. The action is
// applied by the caller after the lock is released, since it may panic or
// block.
func (r *registry) hit(name string) (Action, <-chan struct{}, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits[name]++
	a := r.arms[name]
	if a == nil {
		return Action{}, nil, false
	}
	a.seen++
	if a.nth > 0 && a.seen != a.nth {
		return Action{}, nil, false
	}
	r.fired[name]++
	return a.action, a.released, true
}

// validName reports whether name is two or more dot-separated parts, each a
// lower-case letter followed by lower-case letters, digits or underscores.
func validName(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || p[0] < 'a' || p[0] > 'z' {
			return false
		}
		for i := 1; i < len(p); i++ {
			c := p[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
				return false
			}
		}
	}
	return true
}

package life

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"time"
)

// JoinTimeout is the join bound Close uses when it is given a non-positive
// duration.
const JoinTimeout = 2 * time.Second

// ErrClosed is the cancellation cause of a group that was closed without an
// earlier Fail. It marks an orderly shutdown, not a failure.
var ErrClosed = errors.New("life: group closed")

// Stats is a snapshot of a group's bookkeeping.
type Stats struct {
	Running int // managed goroutines currently running
	Owned   int // resources currently owned
	Panics  int // panics recovered in managed goroutines and in Close of owned resources
	Leaked  int // goroutines still running when the bounded join of Close gave up
}

type owned struct {
	name string
	c    io.Closer
}

// Group owns resources and managed goroutines that share one lifetime.
// Create it with New; the zero value is not usable.
type Group struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	mu      sync.Mutex
	closed  bool
	running int
	idle    chan struct{} // set by Close while goroutines run; closed by the last one to exit
	owned   []owned
	panics  int
	leaked  int

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

// New creates a group whose context is derived from parent with a cancellation
// cause. A nil parent means context.Background().
func New(parent context.Context) *Group {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancelCause(parent)
	return &Group{ctx: ctx, cancel: cancel, closeDone: make(chan struct{})}
}

// Context returns the group's context. It is canceled by Fail, by Close and
// by the parent; context.Cause reports the first cause.
func (g *Group) Context() context.Context { return g.ctx }

// Go starts fn in a managed goroutine named name and reports whether it was
// started; it is not started once Close has begun, or when fn is nil. A panic
// in fn is recovered, counted and turned into Fail(*PanicError); it never
// propagates.
func (g *Group) Go(name string, fn func(ctx context.Context)) bool {
	if fn == nil {
		return false
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return false
	}
	g.running++
	g.mu.Unlock()
	go g.run(name, fn) // the module's only go statement (lintcheck nobarego)
	return true
}

func (g *Group) run(name string, fn func(ctx context.Context)) {
	defer g.exited()
	defer func() {
		if r := recover(); r != nil {
			g.countPanic()
			g.Fail(newPanicError(name, r))
		}
	}()
	fn(g.ctx)
}

func (g *Group) exited() {
	g.mu.Lock()
	g.running--
	if g.running == 0 && g.idle != nil {
		close(g.idle)
		g.idle = nil
	}
	g.mu.Unlock()
}

// Fail records cause as the group's failure and cancels the group. Only the
// first cause is kept, whether it came from Fail, Close or the parent.
func (g *Group) Fail(cause error) { g.cancel(cause) }

// Own registers c to be closed by Close. It returns false, without
// registering, when c is nil or a typed nil. Once Close has begun, Own closes
// c immediately and returns false, so a resource created during shutdown
// cannot leak. Owning the same resource twice registers it once.
func (g *Group) Own(name string, c io.Closer) bool {
	if IsNil(c) {
		return false
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		if perr := Safe("own-after-close:"+name, func() { _ = c.Close() }); perr != nil {
			g.countPanic()
		}
		return false
	}
	for _, o := range g.owned {
		if sameCloser(o.c, c) {
			g.mu.Unlock()
			return true
		}
	}
	g.owned = append(g.owned, owned{name: name, c: c})
	g.mu.Unlock()
	return true
}

// Disown removes c from the group so that Close no longer closes it, and
// reports whether c was owned. c must be the same comparable value that was
// passed to Own (normally a pointer).
func (g *Group) Disown(c io.Closer) bool {
	if IsNil(c) {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, o := range g.owned {
		if sameCloser(o.c, c) {
			g.owned = append(g.owned[:i], g.owned[i+1:]...)
			return true
		}
	}
	return false
}

// sameCloser compares two closers without panicking on dynamic types that
// are not comparable; such values can be owned but never matched.
func sameCloser(a, b io.Closer) bool {
	ta, tb := reflect.TypeOf(a), reflect.TypeOf(b)
	return ta == tb && ta.Comparable() && a == b
}

func (g *Group) countPanic() {
	g.mu.Lock()
	g.panics++
	g.mu.Unlock()
}

// Close shuts the group down: it stops accepting goroutines and resources,
// cancels the context (cause ErrClosed unless a failure came first), closes
// the owned resources in reverse order of Own, and then waits at most join
// for the managed goroutines (JoinTimeout when join <= 0). Goroutines still
// running when the bound expires are counted in Stats.Leaked; Close returns
// anyway.
//
// Close returns the first error from closing a resource, ignoring
// net.ErrClosed; a panicking Close counts as an error. It is idempotent and
// safe for concurrent use: every caller waits for the first call to finish
// and gets the same result. It must not be called from one of the group's own
// goroutines.
func (g *Group) Close(join time.Duration) error {
	g.closeOnce.Do(func() {
		defer close(g.closeDone)
		g.closeErr = g.shutdown(join)
	})
	<-g.closeDone
	return g.closeErr
}

func (g *Group) shutdown(join time.Duration) error {
	if join <= 0 {
		join = JoinTimeout
	}
	g.mu.Lock()
	g.closed = true
	list := g.owned
	g.owned = nil
	g.mu.Unlock()

	g.cancel(ErrClosed)

	var first error
	for i := len(list) - 1; i >= 0; i-- {
		o := list[i]
		var err error
		if perr := Safe("close:"+o.name, func() { err = o.c.Close() }); perr != nil {
			g.countPanic()
			err = perr
		} else if errors.Is(err, net.ErrClosed) {
			err = nil
		}
		if err != nil && first == nil {
			first = err
		}
	}

	g.mu.Lock()
	if g.running == 0 {
		g.mu.Unlock()
		return first
	}
	idle := make(chan struct{})
	g.idle = idle
	g.mu.Unlock()

	t := time.NewTimer(join)
	defer t.Stop()
	select {
	case <-idle:
	case <-t.C:
		g.mu.Lock()
		g.leaked = g.running
		g.mu.Unlock()
	}
	return first
}

// Stats returns a snapshot of the group's counters.
func (g *Group) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Stats{Running: g.running, Owned: len(g.owned), Panics: g.panics, Leaked: g.leaked}
}

// IsNil reports whether v is nil or an interface holding a nil pointer, map,
// slice, function, channel or interface. Entry points use it to reject typed
// nils once instead of recovering from the panics they cause later.
func IsNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}

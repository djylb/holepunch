// Package life is the standalone deployment's single place for starting
// goroutines, recovering panics and interrupting blocked reads on
// connections it does not own:
//
//   - Group owns io.Closers and managed goroutines that share one lifetime.
//     Every goroutine is started with Group.Go, which recovers a panic into
//     a *PanicError and fails the group instead of crashing the process.
//     Close cancels the group, closes the owned resources in reverse order
//     and joins the goroutines with a bound.
//   - Safe is the recover boundary for callbacks and cleanup steps.
//   - InterruptRead interrupts a blocked read when a context ends.
//
// Text produced by this package never contains stack traces; the stack of
// a recovered panic is only available through PanicError.Stack, for local
// logs. IsPanic recognises the panics the holepunch library recovered as
// well. The package depends on the standard library only.
package life

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// joinTimeout is the join bound Close uses when it is given a non-positive
// duration.
const joinTimeout = 2 * time.Second

// errClosed is the cancellation cause of a group closed without an earlier
// failure: an orderly shutdown.
var errClosed = errors.New("life: group closed")

type owned struct {
	name string
	c    io.Closer
}

// Group owns resources and managed goroutines that share one lifetime.
// Create it with New; the zero value is not usable. Its methods are safe for
// concurrent use.
type Group struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	mu      sync.Mutex
	closed  bool
	running int
	idle    chan struct{} // set by Close while goroutines run; closed by the last one to exit
	owned   []owned
	leaked  int

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

// New creates a group whose context is derived from parent with a
// cancellation cause. A nil parent means context.Background().
func New(parent context.Context) *Group {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancelCause(parent)
	return &Group{ctx: ctx, cancel: cancel, closeDone: make(chan struct{})}
}

// Context returns the group's context. It is canceled by a panic in a
// managed goroutine, by Close and by the parent; context.Cause reports the
// first cause.
func (g *Group) Context() context.Context { return g.ctx }

// Go starts fn in a managed goroutine named name and reports whether it was
// started; it is not started once Close has begun, or when fn is nil. A
// panic in fn is recovered and cancels the group with a *PanicError; it
// never propagates.
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
			g.cancel(newPanicError(name, r))
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

// Own registers c to be closed by Close. It returns false, without
// registering, when c is nil or a typed nil. Once Close has begun, Own
// closes c immediately and returns false, so a resource created during
// shutdown cannot leak. Owning the same resource twice registers it once.
func (g *Group) Own(name string, c io.Closer) bool {
	if IsNil(c) {
		return false
	}
	matchable := isComparable(c)
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		_ = Safe("own-after-close:"+name, func() { _ = c.Close() })
		return false
	}
	if matchable && g.indexLocked(c) >= 0 {
		g.mu.Unlock()
		return true
	}
	g.owned = append(g.owned, owned{name: name, c: c})
	g.mu.Unlock()
	return true
}

// Disown removes c from the group so that Close no longer closes it, and
// reports whether c was owned. c must be the same comparable value that was
// passed to Own (normally a pointer).
func (g *Group) Disown(c io.Closer) bool {
	if IsNil(c) || !isComparable(c) {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	i := g.indexLocked(c)
	if i < 0 {
		return false
	}
	g.owned = slices.Delete(g.owned, i, i+1)
	return true
}

// isComparable reports whether c can be compared with == without
// panicking, dynamic values inside it included.
func isComparable(c io.Closer) bool { return reflect.ValueOf(c).Comparable() }

// indexLocked returns the position of c in g.owned, or -1. c must be
// comparable.
func (g *Group) indexLocked(c io.Closer) int {
	for i, o := range g.owned {
		if o.c == c {
			return i
		}
	}
	return -1
}

// Close shuts the group down: it stops accepting goroutines and resources,
// cancels the context, closes the owned resources in reverse order of Own,
// and then waits at most join for the managed goroutines (2 s when join <=
// 0). Goroutines still running when the bound expires are counted in
// Leaked; Close returns anyway.
//
// Close returns the first error from closing a resource, ignoring
// net.ErrClosed; a panicking Close counts as an error. It is idempotent:
// every caller waits for the first call to finish and gets the same result.
// It must not be called from one of the group's own goroutines, nor from
// the Close method of an owned resource.
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
		join = joinTimeout
	}
	g.mu.Lock()
	g.closed = true
	list := g.owned
	g.owned = nil
	g.mu.Unlock()

	g.cancel(errClosed)

	var first error
	for i := len(list) - 1; i >= 0; i-- {
		o := list[i]
		var err error
		// errors.Is runs the resource's own Is and Unwrap methods: both stay
		// inside the recover boundary.
		if perr := Safe("close:"+o.name, func() {
			if err = o.c.Close(); errors.Is(err, net.ErrClosed) {
				err = nil
			}
		}); perr != nil {
			err = perr
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

// Leaked is how many goroutines were still running when the bounded join of
// Close gave up.
func (g *Group) Leaked() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.leaked
}

// IsNil reports whether v is nil or an interface holding a nil pointer, map,
// slice, function, channel or interface.
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

// Limits on what a PanicError retains: the summary travels in error
// strings, the stack is for local logs only.
const (
	maxPanicText  = 200
	maxPanicStack = 4 << 10
)

// PanicError is a panic recovered by Group.Go or Safe. Every textual form
// of it — Error, any fmt verb, encoding/json — contains only the location
// and a short summary of the panic value; the stack is reachable only
// through Stack.
type PanicError struct {
	where string
	value any
	text  string
	stack []byte
}

func newPanicError(where string, r any) *PanicError {
	stack := debug.Stack()
	if len(stack) > maxPanicStack {
		stack = stack[:maxPanicStack]
	}
	return &PanicError{where: where, value: r, text: summarize(r), stack: stack}
}

// Error reports the location and a summary of the panic value.
func (e PanicError) Error() string { return "panic in " + e.where + ": " + e.text }

// MarshalText makes encoding/json and similar encoders emit the Error text.
func (e PanicError) MarshalText() ([]byte, error) { return []byte(e.Error()), nil }

// Where names the goroutine or callback that panicked, as given to Go or
// Safe.
func (e PanicError) Where() string { return e.where }

// Stack returns a copy of the stack captured when the panic was recovered,
// truncated to 4 KiB.
func (e PanicError) Stack() []byte { return append([]byte(nil), e.stack...) }

// Unwrap returns the panic value when it is an error, so errors.Is and
// errors.As see through a panic(err): code that maps errors to codes tests
// IsPanic first.
func (e PanicError) Unwrap() error {
	err, _ := e.value.(error)
	return err
}

// GoString keeps %#v free of the stack.
func (e PanicError) GoString() string {
	return "&life.PanicError{where:" + strconv.Quote(e.where) + ", value:" + strconv.Quote(e.text) + "}"
}

// Format keeps every verb free of the struct fields, and so of the stack.
func (e PanicError) Format(f fmt.State, verb rune) {
	switch {
	case verb == 'v' && f.Flag('#'):
		_, _ = f.Write([]byte(e.GoString()))
	case verb == 'q':
		_, _ = f.Write([]byte(strconv.Quote(e.Error())))
	default:
		_, _ = f.Write([]byte(e.Error()))
	}
}

// recovered is what a recovered panic offers: this package's PanicError and
// the holepunch library's.
type recovered interface {
	error
	Where() string
	Stack() []byte
}

// IsPanic reports whether err is or wraps a recovered panic: a *PanicError
// of this package, or one of the holepunch library (holepunch.PanicError).
func IsPanic(err error) bool {
	var p recovered
	return errors.As(err, &p)
}

// Safe calls fn and converts a panic into a *PanicError named where. It
// never re-panics. Since fn may run foreign code, Safe must not be called
// with a mutex held.
//
//holepunch:callback
func Safe(where string, fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = newPanicError(where, r)
		}
	}()
	fn()
	return nil
}

// summarize renders the first line of the panic value, at most maxPanicText
// bytes of valid UTF-8, with "..." when something was cut.
func summarize(r any) (s string) {
	defer func() {
		// A value whose String or Error method panics must not escape the
		// boundary that is describing it.
		if recover() != nil {
			s = fmt.Sprintf("%T (unprintable)", r)
		}
	}()
	s = fmt.Sprint(r)
	cut := false
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s, cut = s[:i], true
	}
	s = strings.ToValidUTF8(s, "�")
	if len(s) > maxPanicText {
		n := maxPanicText
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s, cut = s[:n], true
	}
	if cut {
		s += "..."
	}
	return s
}

// InterruptRead arranges for a blocked read on c to be interrupted when ctx
// ends, by moving c's read deadline into the past. The returned restore
// function waits for an interrupt that has started, then clears the read
// deadline; it is idempotent, and returns the error (or recovered panic)
// from clearing the deadline.
func InterruptRead(ctx context.Context, c interface{ SetReadDeadline(t time.Time) error }) (restore func() error) {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		// time.Unix(1, 0) is in the past whatever the wall clock says.
		_ = Safe("interrupt-read", func() { _ = c.SetReadDeadline(time.Unix(1, 0)) })
	})
	var (
		once sync.Once
		err  error
	)
	return func() error {
		once.Do(func() {
			// stop reports false only when the callback has started.
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

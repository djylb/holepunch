package life

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/testkit"
)

// closer records the order of Close calls and what the group context looked
// like at that moment.
type closer struct {
	name   string
	err    error
	panics bool
	log    *closeLog
	g      *Group
	done   chan struct{} // closed by Close when not nil
}

type closeLog struct {
	mu       sync.Mutex
	order    []string
	canceled []bool
}

func (c *closer) Close() error {
	c.log.mu.Lock()
	c.log.order = append(c.log.order, c.name)
	c.log.canceled = append(c.log.canceled, c.g != nil && c.g.Context().Err() != nil)
	c.log.mu.Unlock()
	if c.done != nil {
		close(c.done)
	}
	if c.panics {
		panic("close " + c.name)
	}
	return c.err
}

func TestGoRecoversPanicAndFailsGroup(t *testing.T) {
	g := New(context.Background())
	started := g.Go("worker[1]", func(context.Context) { panic("boom") })
	if !started {
		t.Fatal("Go returned false on an open group")
	}
	<-g.Context().Done()
	var perr *PanicError
	if !errors.As(context.Cause(g.Context()), &perr) {
		t.Fatalf("cause = %v, want *PanicError", context.Cause(g.Context()))
	}
	if perr.Where() != "worker[1]" {
		t.Fatalf("Where = %q", perr.Where())
	}
	if len(perr.Stack()) == 0 {
		t.Fatal("stack not captured")
	}
	if err := g.Close(time.Second); err != nil {
		t.Fatal(err)
	}
	if s := g.Stats(); s.Panics != 1 || s.Running != 0 || s.Leaked != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestFirstCauseWins(t *testing.T) {
	g := New(context.Background())
	first := errors.New("first")
	g.Fail(first)
	g.Fail(errors.New("second"))
	_ = g.Close(time.Second)
	if got := context.Cause(g.Context()); !errors.Is(got, first) {
		t.Fatalf("cause = %v", got)
	}
}

func TestCloseCauseIsErrClosedWithoutFailure(t *testing.T) {
	g := New(context.Background())
	_ = g.Close(time.Second)
	if got := context.Cause(g.Context()); !errors.Is(got, ErrClosed) {
		t.Fatalf("cause = %v", got)
	}
}

func TestParentCancellationPropagates(t *testing.T) {
	parent, cancel := context.WithCancelCause(context.Background())
	g := New(parent)
	want := errors.New("parent gone")
	cancel(want)
	<-g.Context().Done()
	if got := context.Cause(g.Context()); !errors.Is(got, want) {
		t.Fatalf("cause = %v", got)
	}
	_ = g.Close(time.Second)
}

func TestGoAfterCloseIsRefused(t *testing.T) {
	g := New(context.Background())
	_ = g.Close(time.Second)
	if g.Go("late", func(context.Context) { t.Error("must not run") }) {
		t.Fatal("Go after Close returned true")
	}
}

func TestOwnAfterCloseClosesImmediately(t *testing.T) {
	g := New(context.Background())
	_ = g.Close(time.Second)
	log := &closeLog{}
	if g.Own("late", &closer{name: "late", log: log}) {
		t.Fatal("Own after Close returned true")
	}
	if len(log.order) != 1 {
		t.Fatalf("late resource closed %d times", len(log.order))
	}
	// A panicking Close during Own-after-Close is contained.
	if g.Own("late-panic", &closer{name: "p", panics: true, log: log}) {
		t.Fatal("Own after Close returned true")
	}
}

func TestOwnDuringCloseClosesImmediately(t *testing.T) {
	g := New(context.Background())
	release := make(chan struct{})
	g.Go("blocker", func(context.Context) { <-release })
	closeDone := make(chan struct{})
	go func() { _ = g.Close(time.Second); close(closeDone) }()
	// Wait until Close has started (the context is canceled first thing).
	<-g.Context().Done()
	log := &closeLog{}
	if g.Own("mid", &closer{name: "mid", log: log}) {
		t.Fatal("Own while closing returned true")
	}
	if len(log.order) != 1 {
		t.Fatal("resource registered during Close was not closed")
	}
	close(release)
	<-closeDone
}

func TestOwnRejectsNilAndTypedNil(t *testing.T) {
	g := New(context.Background())
	defer func() { _ = g.Close(time.Second) }()
	var typed *closer
	var conn net.Conn
	if g.Own("nil", nil) || g.Own("typed", typed) || g.Own("iface", conn) {
		t.Fatal("Own accepted a nil resource")
	}
	if s := g.Stats(); s.Owned != 0 {
		t.Fatalf("owned = %d", s.Owned)
	}
}

func TestCloseOrderCancelThenReverseCloseThenJoin(t *testing.T) {
	g := New(context.Background())
	log := &closeLog{}
	lastClosed := make(chan struct{})
	for _, n := range []string{"a", "b", "c"} {
		c := &closer{name: n, log: log, g: g}
		if n == "a" {
			c.done = lastClosed // closed last, in reverse order of Own
		}
		if !g.Own(n, c) {
			t.Fatal("Own failed")
		}
	}
	var sawCanceled atomic.Bool
	var closedBeforeExit atomic.Int64
	g.Go("waiter", func(ctx context.Context) {
		<-ctx.Done()
		sawCanceled.Store(true)
		// The join must follow closing, so the last resource is closed while
		// this goroutine still runs. Were the join first, the wait would end
		// only at the timeout, with nothing closed yet.
		select {
		case <-lastClosed:
		case <-time.After(5 * time.Second):
		}
		log.mu.Lock()
		closedBeforeExit.Store(int64(len(log.order)))
		log.mu.Unlock()
	})
	if err := g.Close(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if !sawCanceled.Load() {
		t.Fatal("goroutine did not observe cancellation")
	}
	if got := log.order; len(got) != 3 || got[0] != "c" || got[1] != "b" || got[2] != "a" {
		t.Fatalf("close order = %v, want [c b a]", got)
	}
	for i, c := range log.canceled {
		if !c {
			t.Fatalf("resource %s closed before the context was canceled", log.order[i])
		}
	}
	if closedBeforeExit.Load() != 3 {
		t.Fatalf("resources closed before goroutine exit = %d, want 3 (join must follow closing)", closedBeforeExit.Load())
	}
}

func TestCloseReturnsFirstRealError(t *testing.T) {
	g := New(context.Background())
	log := &closeLog{}
	errA := errors.New("a failed")
	errB := errors.New("b failed")
	g.Own("a", &closer{name: "a", err: errA, log: log})
	g.Own("b", &closer{name: "b", err: errB, log: log})
	g.Own("c", &closer{name: "c", err: net.ErrClosed, log: log})
	if err := g.Close(time.Second); !errors.Is(err, errB) {
		t.Fatalf("Close = %v, want %v (first in LIFO order, net.ErrClosed ignored)", err, errB)
	}
}

func TestClosePanicIsAnErrorAndDoesNotStopCleanup(t *testing.T) {
	g := New(context.Background())
	log := &closeLog{}
	g.Own("a", &closer{name: "a", log: log})
	g.Own("b", &closer{name: "b", panics: true, log: log})
	err := g.Close(time.Second)
	var perr *PanicError
	if !errors.As(err, &perr) || perr.Where() != "close:b" {
		t.Fatalf("Close = %v, want PanicError at close:b", err)
	}
	if len(log.order) != 2 {
		t.Fatalf("closed %v; a panic must not skip later resources", log.order)
	}
}

func TestCloseJoinBoundCountsLeaked(t *testing.T) {
	g := New(context.Background())
	release := make(chan struct{})
	exited := make(chan struct{})
	g.Go("stuck", func(context.Context) {
		defer close(exited)
		<-release // ignores ctx on purpose
	})
	start := time.Now()
	if err := g.Close(50 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 50*time.Millisecond || d >= JoinTimeout {
		t.Fatalf("Close took %v, want about the 50ms join bound", d)
	}
	if s := g.Stats(); s.Leaked != 1 || s.Running != 1 {
		t.Fatalf("stats = %+v, want Leaked=1 Running=1", s)
	}
	close(release)
	<-exited
	testkit.WaitFor(t, "the goroutines to exit", func() bool { return g.Stats().Running == 0 })
	if s := g.Stats(); s.Leaked != 1 {
		t.Fatalf("leaked must stay recorded, stats = %+v", s)
	}
}

func TestCloseNonPositiveJoinUsesDefault(t *testing.T) {
	g := New(context.Background())
	g.Go("quick", func(ctx context.Context) { <-ctx.Done() })
	if err := g.Close(0); err != nil {
		t.Fatal(err)
	}
	if s := g.Stats(); s.Leaked != 0 || s.Running != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestCloseIdempotentAndConcurrent(t *testing.T) {
	g := New(context.Background())
	log := &closeLog{}
	want := errors.New("x")
	g.Own("x", &closer{name: "x", err: want, log: log})
	release := make(chan struct{})
	g.Go("slow", func(ctx context.Context) { <-ctx.Done(); <-release })
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = g.Close(time.Second) }()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	for i, err := range errs {
		if !errors.Is(err, want) {
			t.Fatalf("caller %d got %v, want %v", i, err, want)
		}
	}
	if len(log.order) != 1 {
		t.Fatalf("resource closed %d times", len(log.order))
	}
	if err := g.Close(time.Second); !errors.Is(err, want) {
		t.Fatalf("later Close = %v", err)
	}
}

func TestDisown(t *testing.T) {
	g := New(context.Background())
	log := &closeLog{}
	keep := &closer{name: "winner", log: log}
	other := &closer{name: "loser", log: log}
	g.Own("winner", keep)
	g.Own("loser", other)
	if !g.Disown(keep) {
		t.Fatal("Disown(owned) = false")
	}
	if g.Disown(keep) {
		t.Fatal("second Disown = true")
	}
	if g.Disown(nil) {
		t.Fatal("Disown(nil) = true")
	}
	if g.Disown(uncomparable{}) {
		t.Fatal("Disown(uncomparable) = true")
	}
	_ = g.Close(time.Second)
	if len(log.order) != 1 || log.order[0] != "loser" {
		t.Fatalf("closed %v, want only the loser", log.order)
	}
}

type uncomparable struct{ f []int }

func (uncomparable) Close() error { return nil }

func TestOwnAcceptsUncomparableAndClosesIt(t *testing.T) {
	g := New(context.Background())
	if !g.Own("u", uncomparable{f: []int{1}}) {
		t.Fatal("Own(uncomparable) = false")
	}
	if g.Disown(uncomparable{f: []int{1}}) {
		t.Fatal("Disown matched an uncomparable value")
	}
	if err := g.Close(time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestGoNilFuncAndNilParent(t *testing.T) {
	var parent context.Context // a nil parent is accepted on purpose
	g := New(parent)
	if g.Go("nil", nil) {
		t.Fatal("Go(nil) returned true")
	}
	if err := g.Close(time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestOwnTwiceRegistersOnce(t *testing.T) {
	g := New(context.Background())
	log := &closeLog{}
	c := &closer{name: "c", log: log}
	if !g.Own("c", c) {
		t.Fatal("first Own failed")
	}
	if !g.Own("c", c) {
		t.Fatal("second Own failed")
	}
	if s := g.Stats(); s.Owned != 1 {
		t.Fatalf("owned = %d, want 1", s.Owned)
	}
	_ = g.Close(time.Second)
	if len(log.order) != 1 {
		t.Fatalf("closed %d times", len(log.order))
	}
}

func TestCloserPanicIsCounted(t *testing.T) {
	g := New(context.Background())
	g.Own("p", &closer{name: "p", panics: true, log: &closeLog{}})
	_ = g.Close(time.Second)
	_ = g.Own("late", &closer{name: "late", panics: true, log: &closeLog{}})
	if s := g.Stats(); s.Panics != 2 {
		t.Fatalf("panics = %d, want 2", s.Panics)
	}
}

// ifaceCloser is a comparable struct type whose interface field may hold a
// value that is not comparable; == on two such values panics at run time.
type ifaceCloser struct{ v any }

func (ifaceCloser) Close() error { return nil }

// TestOwnNeverComparesUncomparableValues: Own compares under the group lock,
// so a panicking == would leave the lock held and wedge the group.
func TestOwnNeverComparesUncomparableValues(t *testing.T) {
	g := New(context.Background())
	a, b := ifaceCloser{v: []int{1}}, ifaceCloser{v: []int{1}}
	if !g.Own("a", a) || !g.Own("b", b) {
		t.Fatal("Own of an uncomparable value failed")
	}
	if g.Disown(a) {
		t.Fatal("Disown matched an uncomparable value")
	}
	// A comparable value of the same type is still matched.
	c := ifaceCloser{v: 1}
	if !g.Own("c", c) {
		t.Fatal("first Own failed")
	}
	if !g.Own("c", c) {
		t.Fatal("second Own failed")
	}
	if s := g.Stats(); s.Owned != 3 {
		t.Fatalf("owned = %d, want 3", s.Owned)
	}
	if !g.Disown(c) {
		t.Fatal("Disown(comparable) = false")
	}
	if err := g.Close(time.Second); err != nil {
		t.Fatal(err)
	}
}

// panickyIsError is an error whose Is method panics, as one returned by a
// caller-supplied resource may.
type panickyIsError struct{}

func (panickyIsError) Error() string   { return "close failed" }
func (panickyIsError) Is(_ error) bool { panic("Is exploded") }

// TestCloseContainsPanicsFromCloseErrors: matching a resource's Close error
// against net.ErrClosed runs the error's methods, which are caller code.
func TestCloseContainsPanicsFromCloseErrors(t *testing.T) {
	g := New(context.Background())
	log := &closeLog{}
	g.Own("a", &closer{name: "a", log: log})
	g.Own("b", &closer{name: "b", err: panickyIsError{}, log: log})
	err := g.Close(time.Second)
	var perr *PanicError
	if !errors.As(err, &perr) || perr.Where() != "close:b" {
		t.Fatalf("Close = %v, want PanicError at close:b", err)
	}
	if len(log.order) != 2 {
		t.Fatalf("closed %v; the panic must not skip later resources", log.order)
	}
	if s := g.Stats(); s.Panics != 1 {
		t.Fatalf("panics = %d, want 1", s.Panics)
	}
}

// TestConcurrentGoOwnClose races Go, Own and Close: every goroutine that was
// started is joined, and every resource is closed exactly once.
func TestConcurrentGoOwnClose(t *testing.T) {
	for range 200 {
		g := New(context.Background())
		var closes atomic.Int32
		var started atomic.Int32
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if g.Go("w", func(ctx context.Context) { <-ctx.Done() }) {
					started.Add(1)
				}
				_ = g.Own("r", countingCloser{n: &closes, id: i})
			}()
		}
		wg.Add(1)
		go func() { defer wg.Done(); _ = g.Close(time.Second) }()
		wg.Wait()
		_ = g.Close(time.Second)
		if s := g.Stats(); s.Running != 0 || s.Leaked != 0 || s.Owned != 0 {
			t.Fatalf("stats = %+v", s)
		}
		if closes.Load() != 8 {
			t.Fatalf("closed %d of 8 resources", closes.Load())
		}
	}
}

type countingCloser struct {
	n  *atomic.Int32
	id int
}

func (c countingCloser) Close() error { c.n.Add(1); return nil }

func TestStatsCounts(t *testing.T) {
	g := New(context.Background())
	release := make(chan struct{})
	for range 3 {
		g.Go("w", func(context.Context) { <-release })
	}
	g.Own("r", io.NopCloser(nil))
	if s := g.Stats(); s.Running != 3 || s.Owned != 1 {
		t.Fatalf("stats = %+v", s)
	}
	close(release)
	_ = g.Close(time.Second)
	if s := g.Stats(); s.Running != 0 || s.Owned != 0 || s.Leaked != 0 {
		t.Fatalf("stats after close = %+v", s)
	}
}

func TestGoexitIsAccounted(t *testing.T) {
	g := New(context.Background())
	g.Go("goexit", func(context.Context) { runtime.Goexit() })
	if err := g.Close(time.Second); err != nil {
		t.Fatal(err)
	}
	if s := g.Stats(); s.Running != 0 || s.Leaked != 0 || s.Panics != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestIsNil(t *testing.T) {
	var p *int
	var m map[int]int
	var f func()
	var ch chan int
	var s []int
	var e error
	cases := []struct {
		v    any
		want bool
	}{
		{nil, true}, {p, true}, {m, true}, {f, true}, {ch, true}, {s, true}, {e, true},
		{0, false}, {"", false}, {struct{}{}, false}, {new(int), false},
	}
	for i, c := range cases {
		if got := IsNil(c.v); got != c.want {
			t.Errorf("case %d (%T): IsNil = %v", i, c.v, got)
		}
	}
}

// TestCloseJoinUsesNoHelperGoroutine checks that the bounded join is done by
// the Close caller itself: a helper goroutine waiting on the stuck goroutine
// would outlive Close.
func TestCloseJoinUsesNoHelperGoroutine(t *testing.T) {
	g := New(context.Background())
	release := make(chan struct{})
	exited := make(chan struct{})
	g.Go("stuck", func(context.Context) { defer close(exited); <-release })
	before := runtime.NumGoroutine()
	_ = g.Close(30 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutines after Close = %d, before = %d: Close left a helper behind", after, before)
	}
	close(release)
	<-exited
}

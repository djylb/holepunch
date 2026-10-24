// Package goroutines checks tests for leaked goroutines: Find lists the
// goroutines still running besides the caller, the test framework's and the
// runtime's own, waiting a while for them to end first; VerifyNone fails a
// test with them and VerifyTestMain a whole test binary. It depends on the
// standard library only, so that every package's tests can use it.
package goroutines

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// settleWait bounds how long Find waits for goroutines to end: a goroutine
// that was told to stop may still be on its way out, more so under the race
// detector on a loaded machine.
const settleWait = 5 * time.Second

// Option tunes Find.
type Option func(*findOptions)

type findOptions struct {
	ignore map[uint64]bool // goroutine ids to ignore
	wait   time.Duration   // settleWait, shorter in this package's tests
}

// IgnoreCurrent ignores the goroutines running now: Find then reports only
// those started later.
func IgnoreCurrent() Option {
	ids := map[uint64]bool{}
	for _, g := range goroutines() {
		ids[g.id] = true
	}
	return func(o *findOptions) {
		for id := range ids {
			o.ignore[id] = true
		}
	}
}

// Find returns an error listing the goroutines that are still running after
// up to settleWait — besides the caller, the test framework's, the runtime's
// and those the options ignore — or nil once there are none.
func Find(opts ...Option) error {
	o := findOptions{ignore: map[uint64]bool{}, wait: settleWait}
	for _, opt := range opts {
		opt(&o)
	}
	deadline := time.Now().Add(o.wait)
	pause := time.Millisecond
	for {
		left := slices.DeleteFunc(goroutines(), func(g goroutine) bool { return o.ignore[g.id] || g.expected() })
		if len(left) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			var b strings.Builder
			fmt.Fprintf(&b, "goroutines: %d still running:", len(left))
			for _, g := range left {
				b.WriteString("\n\n")
				b.WriteString(g.stack)
			}
			return fmt.Errorf("%s", b.String())
		}
		t := time.NewTimer(pause)
		<-t.C
		pause = min(2*pause, 100*time.Millisecond)
	}
}

// VerifyNone fails t when Find reports goroutines; call it deferred at the
// end of a test.
func VerifyNone(t testing.TB, opts ...Option) {
	t.Helper()
	if err := Find(opts...); err != nil {
		t.Error(err)
	}
}

// VerifyTestMain runs the tests of m and, when they passed, fails the
// binary if goroutines are left running: call it from TestMain.
func VerifyTestMain(m *testing.M, opts ...Option) {
	code := m.Run()
	if code == 0 {
		if err := Find(opts...); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	os.Exit(code)
}

// goroutine is one goroutine of a runtime.Stack dump.
type goroutine struct {
	id    uint64
	top   string // the function running, without its arguments
	stack string // the goroutine's whole dump
}

// expected reports a goroutine that is no leak: one of the test framework
// waiting for its tests, or the runtime's signal and trace handling.
func (g goroutine) expected() bool {
	switch g.top {
	case "testing.RunTests", "testing.(*T).Run", "testing.(*T).Parallel", "testing.runFuzzTests", "testing.runFuzzing",
		"testing.(*F).Fuzz",
		"os/signal.signal_recv", "os/signal.loop", "runtime.ensureSigM", "runtime.ReadTrace":
		return true
	}
	return strings.Contains(g.stack, "runtime/trace.Start")
}

// goroutines returns every goroutine but the caller's.
func goroutines() []goroutine {
	buf := make([]byte, 64<<10)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	var out []goroutine
	for i, dump := range strings.Split(string(buf), "\n\n") {
		if i == 0 {
			continue // the first is the caller's own
		}
		if g, ok := parseGoroutine(dump); ok {
			out = append(out, g)
		}
	}
	return out
}

// parseGoroutine parses one dump: "goroutine N [state]:", then the running
// function with its arguments.
func parseGoroutine(dump string) (goroutine, bool) {
	head, rest, ok := strings.Cut(dump, "\n")
	if !ok {
		return goroutine{}, false
	}
	idText, _, ok := strings.Cut(strings.TrimPrefix(head, "goroutine "), " ")
	id, err := strconv.ParseUint(idText, 10, 64)
	if !ok || err != nil {
		return goroutine{}, false
	}
	fn, _, _ := strings.Cut(rest, "\n")
	if i := strings.LastIndexByte(fn, '('); i > 0 {
		fn = fn[:i]
	}
	return goroutine{id: id, top: fn, stack: dump}, true
}

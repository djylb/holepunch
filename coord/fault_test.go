//go:build holepunch_faultinject

package coord

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

// arm arms a point for the rest of the test; the test's end disarms every
// point and clears the counters, so that Fired counts one test only.
func arm(t *testing.T, name string, a faultinject.Action, nth int) {
	t.Helper()
	t.Cleanup(faultinject.Reset)
	faultinject.Arm(name, a, nth)
}

// TestFaultAttach: an injected failure in Attach leaves the connection with
// the caller and the role free.
func TestFaultAttach(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	arm(t, fiAttach, faultinject.Error(nil), 1)
	srv, cli := netPipe(t)
	if err := s.Attach(protocol.RoleInitiator, srv, AttachOptions{Security: protocol.ControlSecurityDeclared}); !errors.Is(err, faultinject.ErrInjected) {
		t.Fatalf("attach: %v", err)
	}
	_ = cli
	r.attach(s, protocol.RoleInitiator)
	s.Abort(protocol.ReasonCanceled, "")
	r.wait(s)
}

// TestFaultAttachPanic: a panic in Attach before the stream is wrapped
// returns the whole reservation — the claim on the role and the reference —
// and leaves the connection with the caller, untouched; the session still
// ends, so Close finds nothing stuck.
func TestFaultAttachPanic(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	arm(t, fiAttach, faultinject.Panic(), 1)
	srv, cli := netPipe(t)
	err := s.Attach(protocol.RoleInitiator, srv, AttachOptions{Security: protocol.ControlSecurityDeclared})
	var pe *life.PanicError
	if !errors.As(err, &pe) || !errors.Is(err, faultinject.ErrInjected) {
		t.Fatalf("attach: %v", err)
	}
	if n := faultinject.Fired(fiAttach); n != 1 {
		t.Fatalf("fired %d times", n)
	}
	// The caller still owns the connection: it works both ways.
	go func() { _, _ = cli.Write([]byte("x")) }()
	if _, err := srv.Read(make([]byte, 1)); err != nil {
		t.Fatalf("conn unusable: %v", err)
	}
	if snap := s.Snapshot(); snap.State != StateCreated || snap.Attached != [2]bool{} {
		t.Fatalf("state changed: %+v", snap)
	}
	// The role is free again.
	c := r.attach(s, protocol.RoleInitiator)
	expect[protocol.PunchStart](t, c)
	s.Abort(protocol.ReasonCanceled, "")
	if res := r.wait(s); res.Reason != protocol.ReasonCanceled {
		t.Fatalf("result %+v", res)
	}
	if err := r.c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if st := r.c.Stats(); st.Stuck != 0 || st.SessionsActive != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// TestFaultHandlers: a fault while handling a report or a ready ends the
// session with internal; a connection-close fault is a lost link.
func TestFaultHandlers(t *testing.T) {
	t.Run("report error", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		arm(t, fiHandleReport, faultinject.Error(nil), 1)
		p.report(0)
		if res := r.wait(p.s); res.Reason != protocol.ReasonInternal {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("report panic", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		arm(t, fiHandleReport, faultinject.Panic(), 1)
		p.report(0)
		res := r.wait(p.s)
		if res.Reason != protocol.ReasonInternal || res.Detail == "" {
			t.Fatalf("result %+v", res)
		}
		if len(r.waitEvents(EvInternalError, 1)) == 0 {
			t.Fatal("no internal error event")
		}
	})
	t.Run("ready close", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		sums := p.summaries()
		arm(t, fiHandleReady, faultinject.CloseConn(), 1)
		send(t, p.cl[0], simclient.Ready(sums[0], protocol.RoleInitiator, 1))
		if a := expectAbort(t, p.cl[1]); a.Reason != protocol.ReasonPeerOffline || a.By != protocol.RoleInitiator {
			t.Fatalf("abort %+v", a)
		}
		r.wait(p.s)
	})
}

// TestFaultTimer: a panic in the timer callback ends the session with
// internal.
func TestFaultTimer(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	arm(t, fiTimer, faultinject.Panic(), 1)
	r.clk.Advance(defBindTimeout)
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonInternal {
		t.Fatalf("result %+v", res)
	}
}

// TestFaultPlan: a planner fault falls back to the default planner for a
// custom planner and fails the session for the default one.
func TestFaultPlan(t *testing.T) {
	t.Run("default planner", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		arm(t, fiPlan, faultinject.Panic(), 0)
		p.report(0)
		p.report(1)
		if res := r.wait(p.s); res.Reason != protocol.ReasonInternal {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("round", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		arm(t, fiPlan, faultinject.Panic(), 1)
		p.endRound(1, [2]simclient.Outcome{fired(5), fired(5)})
		if res := r.wait(p.s); res.Reason != protocol.ReasonInternal {
			t.Fatalf("result %+v", res)
		}
	})
}

// TestFaultMemory: a memory fault disables the memory for the session.
func TestFaultMemory(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	arm(t, fiMemory, faultinject.Panic(), 0)
	p.punching()
	p.confirm(0, 1)
	p.confirm(1, 1)
	p.succeed(0, 1)
	p.succeed(1, 1)
	if res := r.wait(p.s); res.Outcome != OutcomeSucceeded {
		t.Fatalf("result %+v", res)
	}
}

// TestFaultFinishSteps: a step of finish that fails — its point panics
// or returns an error — skips nothing, not even its own release: the links,
// the registry entry, the quotas, the index and the context are all released,
// OnResult runs once and the failure is counted.
func TestFaultFinishSteps(t *testing.T) {
	steps := []string{fiFinishNotify, fiFinishConns, fiFinishRegistry, fiFinishQuota, fiFinishIndex,
		fiFinishParent, fiFinishCtx, fiFinishMemory, fiFinishTraits, fiFinishStats}
	actions := []struct {
		name string
		a    faultinject.Action
	}{{"panic", faultinject.Panic()}, {"error", faultinject.Error(nil)}}
	for _, step := range steps {
		for _, act := range actions {
			t.Run(step+"/"+act.name, func(t *testing.T) {
				reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
				r := newRig(t, withRegistry(reg))
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				p := r.pair(SessionOptions{ClientKeys: [2]string{"a", "b"}, Parent: parent})
				arm(t, step, act.a, 0)
				p.s.Abort(protocol.ReasonCanceled, "")
				res := r.wait(p.s)
				if res.Reason != protocol.ReasonCanceled {
					t.Fatalf("result %+v", res)
				}
				if n := faultinject.Fired(step); n != 1 {
					t.Fatalf("%s fired %d times", step, n)
				}
				if n, keys, entries := r.c.Len(), r.c.Stats().ActiveByKey, reg.Len(); n != 0 || keys != 0 || entries != 0 {
					t.Fatalf("left behind: %d sessions, %d keys, %d registry entries", n, keys, entries)
				}
				if reasonOf(context.Cause(p.s.Context())) != protocol.ReasonCanceled {
					t.Fatalf("session context: %v", context.Cause(p.s.Context()))
				}
				for i := range 2 {
					expectEOFOrAbort(t, p.cl[i])
				}
				expectOneResult(t, r)
				if st := r.c.Stats(); st.Panics == 0 {
					t.Fatal("the failed step was not counted")
				}
				evs := r.waitEvents(EvInternalError, 1)
				if evs[0].Detail != step {
					t.Fatalf("internal error event %+v", evs[0])
				}
			})
		}
	}
}

// TestFaultCallback: an injected fault fails one callback delivery, which
// counts as a panic of that callback.
func TestFaultCallback(t *testing.T) {
	r := newRig(t)
	arm(t, fiCallback, faultinject.Error(nil), 0)
	s := r.session(SessionOptions{})
	s.Abort(protocol.ReasonCanceled, "")
	r.wait(s)
	select {
	case res := <-r.results:
		t.Fatalf("OnResult ran: %+v", res)
	case <-time.After(20 * time.Millisecond):
	}
}

// TestFaultClose: an injected error in Close is returned once the shutdown
// is complete.
func TestFaultClose(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	arm(t, fiClose, faultinject.Error(nil), 1)
	if err := r.c.Close(); !errors.Is(err, faultinject.ErrInjected) {
		t.Fatalf("close: %v", err)
	}
	r.wait(s)
}

// TestFaultClosePanic: a panic inside Close never reaches a
// caller: the shutdown still ends every session and joins the coordinator's
// goroutines, the panic is counted and reported, and every caller — the
// concurrent ones and a later one, which returns at once — gets it as a
// *life.PanicError.
func TestFaultClosePanic(t *testing.T) {
	r := newRig(t)
	idle := r.session(SessionOptions{})
	p := r.pair(SessionOptions{})
	arm(t, fiClose, faultinject.Panic(), 1)
	const callers = 10
	errs := make(chan error, callers)
	for range callers {
		go func() {
			defer func() {
				if v := recover(); v != nil {
					errs <- fmt.Errorf("panic escaped Close: %v", v)
				}
			}()
			errs <- r.c.Close()
		}()
	}
	var first error
	for range callers {
		select {
		case err := <-errs:
			expectClosePanic(t, err)
			if first == nil {
				first = err
			} else if err != first {
				t.Fatalf("callers got different errors: %v, %v", first, err)
			}
		case <-time.After(testkit.WaitBound(t)):
			t.Fatal("Close blocked")
		}
	}
	if n := faultinject.Fired(fiClose); n != 1 {
		t.Fatalf("fired %d times", n)
	}
	for _, s := range []*Session{idle, p.s} {
		if res := r.wait(s); res.Reason != protocol.ReasonServerShutdown {
			t.Fatalf("result %+v", res)
		}
	}
	if st := r.c.Stats(); st.Panics != 1 || st.Stuck != 0 || r.c.Len() != 0 {
		t.Fatalf("stats %+v, len %d", st, r.c.Len())
	}
	if st := r.c.root.Stats(); st.Running != 0 || st.Leaked != 0 {
		t.Fatalf("root group %+v", st)
	}
	if evs := r.eventsOf(EvInternalError); len(evs) != 1 || evs[0].Detail != fiClose {
		t.Fatalf("internal error events %+v", evs)
	}
	done := make(chan error, 1)
	go func() { done <- r.c.Close() }()
	select {
	case err := <-done:
		if err != first {
			t.Fatalf("second close: %v, want %v", err, first)
		}
	case <-time.After(testkit.WaitBound(t)):
		t.Fatal("second Close blocked")
	}
}

// expectClosePanic checks that Close returned the injected panic, and only
// it, as a *life.PanicError.
func expectClosePanic(t *testing.T, err error) {
	t.Helper()
	pe, ok := err.(*life.PanicError)
	if !ok || pe.Where() != fiClose || !errors.Is(err, faultinject.ErrInjected) {
		t.Fatalf("close: %v (%T), want the injected panic as a *life.PanicError", err, err)
	}
}

package coord

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

// The panic paths that need no fault injection point: each test makes one
// part of a reservation, of a session's start or of finish fail and checks
// that nothing is left behind.

// TestFinishSurvivesResultPanic: a panic while finish works out the end
// leaves the session closed with a bare Result: quit is closed (its close
// is deferred as soon as the state is closed) so the session goroutine returns,
// the links, the registry entry, the quotas, the index and the context are
// released, Done closes, OnResult runs once and the panic is counted.
func TestFinishSurvivesResultPanic(t *testing.T) {
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	r := newRig(t, withRegistry(reg))
	s := r.session(SessionOptions{ClientKeys: [2]string{"a", "b"}})
	c := r.attach(s, protocol.RoleInitiator, simclient.Options{NoPong: true})
	expect[protocol.PunchStart](t, c)
	s.mu.Lock()
	s.st.rtt[0].n = -1 // the estimator's min slices out of range: building the Result panics
	s.mu.Unlock()
	s.Abort(protocol.ReasonCanceled, "stop")
	select {
	case <-s.quit:
	default:
		t.Fatal("quit is open after finish")
	}
	res := r.wait(s)
	if res.SessionID != s.ID() || res.Code != protocol.ReasonCanceled || res.Detail != "stop" ||
		res.Outcome != OutcomeAborted || res.Timings.Closed.IsZero() {
		t.Fatalf("result %+v", res)
	}
	expectEOFOrAbort(t, c)
	if n, keys, entries := r.c.Len(), r.c.Stats().ActiveByKey, reg.Len(); n != 0 || keys != 0 || entries != 0 {
		t.Fatalf("left behind: %d sessions, %d keys, %d registry entries", n, keys, entries)
	}
	if reasonOf(context.Cause(s.Context())) != protocol.ReasonCanceled {
		t.Fatalf("session context: %v", context.Cause(s.Context()))
	}
	if got := expectOneResult(t, r); got.Code != protocol.ReasonCanceled {
		t.Fatalf("OnResult %+v", got)
	}
	if st := r.c.Stats(); st.Panics != 1 {
		t.Fatalf("panics %d", st.Panics)
	}
	if ev := r.waitEvents(EvInternalError, 1)[0]; ev.Detail != "coord.finish" {
		t.Fatalf("event %+v", ev)
	}
	if err := s.Attach(protocol.RoleResponder, nil, AttachOptions{}); !errors.Is(err, ErrInvalidConn) {
		t.Fatalf("attach: %v", err)
	}
	srv, _ := netPipe(t)
	if err := s.Attach(protocol.RoleResponder, srv, AttachOptions{Security: protocol.ControlSecurityDeclared}); !errors.Is(err, ErrSessionDone) {
		t.Fatalf("attach after the end: %v", err)
	}
}

// resetPanics is a session timer whose Reset panics.
type resetPanics struct{ Timer }

func (resetPanics) Reset(time.Duration) bool { panic("reset") }

// TestAttachPanicAfterTakeover: once the stream is wrapped it is the
// session's, so a failure after that ends the session with internal and the
// stream with it; Attach returns nil and its reservation is returned.
func TestAttachPanicAfterTakeover(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{ClientKeys: [2]string{"a", "b"}})
	s.mu.Lock()
	s.timer = resetPanics{s.timer}
	s.mu.Unlock()
	srv, cli := net.Pipe()
	c, err := simclient.New(cli, protocol.RoleInitiator, simclient.Options{Now: r.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := s.Attach(protocol.RoleInitiator, srv, AttachOptions{Security: protocol.ControlSecurityInsecureForTesting}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	res := r.wait(s)
	if res.Code != protocol.ReasonInternal || !strings.HasPrefix(res.Detail, "panic:coord.attach: reset") {
		t.Fatalf("result %+v", res)
	}
	if a := expectAbort(t, c); a.Code != protocol.ReasonInternal {
		t.Fatalf("abort %+v", a)
	}
	expectEOF(t, c)
	if r.c.Len() != 0 || r.c.Stats().ActiveByKey != 0 {
		t.Fatalf("left behind: %d sessions, %d keys", r.c.Len(), r.c.Stats().ActiveByKey)
	}
}

// TestAttachWithoutSessionGoroutine: the session goroutine's reference is
// only kept when the goroutine starts; otherwise Done would wait for it
// forever.
func TestAttachWithoutSessionGoroutine(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	s.mu.Lock()
	stopWatch := s.stopWatch
	s.mu.Unlock()
	stopWatch() // the group's end must not end the session here
	if err := s.group.Close(life.JoinTimeout); err != nil {
		t.Fatal(err)
	}
	c := r.attach(s, protocol.RoleInitiator)
	expect[protocol.PunchStart](t, c)
	s.Abort(protocol.ReasonCanceled, "")
	if res := r.wait(s); res.Code != protocol.ReasonCanceled {
		t.Fatalf("result %+v", res)
	}
	expectEOFOrAbort(t, c)
}

// TestCloseLinksIsolatesFailures: a link whose close panics keeps no other
// link open; the panic is counted.
func TestCloseLinksIsolatesFailures(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	srv, cli := netPipe(t)
	cw, err := controlwire.NewConn(srv, controlwire.ConnOptions{Side: controlwire.SideServer})
	if err != nil {
		t.Fatal(err)
	}
	good := newLink(1, protocol.RoleResponder)
	good.conn = cw
	bad := newLink(0, protocol.RoleInitiator)
	bad.quit = nil // close of a nil channel panics
	var ctr Counters
	s.closeLinks([2]*link{bad, good}, &ctr)
	if _, err := cli.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("the good link is open: %v", err)
	}
	if st := r.c.Stats(); st.Panics != 1 {
		t.Fatalf("panics %d", st.Panics)
	}
	if ev := r.waitEvents(EvInternalError, 1)[0]; ev.Detail != fiFinishConns {
		t.Fatalf("event %+v", ev)
	}
	s.Abort(protocol.ReasonCanceled, "")
	r.wait(s)
}

// doneFails is a parent context whose Done panics.
type doneFails struct{ context.Context }

func (doneFails) Done() <-chan struct{} { panic("done") }

// TestNewSessionPanicAfterAdmission: a failure after the session went live
// ends it: NewSession returns the panic, and the quotas, the registry entry,
// the index, the timer and the context are released; OnResult reports
// internal.
func TestNewSessionPanicAfterAdmission(t *testing.T) {
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	r := newRig(t, withRegistry(reg))
	if err := r.clk.WaitPending(ctx(t), 1); err != nil { // the housekeeping timer
		t.Fatal(err)
	}
	_, err := r.c.NewSession(SessionOptions{ClientKeys: [2]string{"a", "b"}, Parent: doneFails{context.Background()}})
	var pe *life.PanicError
	if !errors.As(err, &pe) || pe.Where() != "coord.new_session" {
		t.Fatalf("new session: %v", err)
	}
	if res := expectOneResult(t, r); res.Code != protocol.ReasonInternal || !strings.HasPrefix(res.Detail, "panic:coord.new_session: done") {
		t.Fatalf("result %+v", res)
	}
	if n, keys, entries := r.c.Len(), r.c.Stats().ActiveByKey, reg.Len(); n != 0 || keys != 0 || entries != 0 {
		t.Fatalf("left behind: %d sessions, %d keys, %d registry entries", n, keys, entries)
	}
	if n := r.clk.Pending(); n != 1 {
		t.Fatalf("%d timers pending, want the housekeeping timer only", n)
	}
	if err := r.c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestNewSessionRefusedLeavesNothing: a session refused at admission holds
// nothing afterwards — no quota, no registry entry, no timer.
func TestNewSessionRefusedLeavesNothing(t *testing.T) {
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	r := newRig(t, withRegistry(reg))
	if err := r.clk.WaitPending(ctx(t), 1); err != nil { // the housekeeping timer
		t.Fatal(err)
	}
	s := r.session(SessionOptions{ClientKeys: [2]string{"a", "b"}})
	if _, err := r.c.NewSession(SessionOptions{SessionID: s.ID(), ClientKeys: [2]string{"c", "d"}}); !invalidArgument(err) {
		t.Fatalf("duplicate id: %v", err)
	}
	if n, keys, entries := r.c.Len(), r.c.Stats().ActiveByKey, reg.Len(); n != 1 || keys != 2 || entries != 1 {
		t.Fatalf("held: %d sessions, %d keys, %d registry entries", n, keys, entries)
	}
	if n := r.clk.Pending(); n != 2 {
		t.Fatalf("%d timers pending, want the housekeeping timer and the session's", n)
	}
	s.Abort(protocol.ReasonCanceled, "")
	r.wait(s)
}

// randPanics is a Config.Rand that panics.
type randPanics struct{}

func (randPanics) Read([]byte) (int, error) { panic("rand") }

// TestNewPanic: a panic in New is returned as an error, not handed to the
// caller, and starts nothing.
func TestNewPanic(t *testing.T) {
	c, err := New(Config{AllowUnverifiedTargets: true, Memory: NoMemory{}, Rand: randPanics{}})
	var pe *life.PanicError
	if c != nil || !errors.As(err, &pe) || pe.Where() != "coord.new" {
		t.Fatalf("new: %v, %v", c, err)
	}
}

// TestStepWorkPanic: a step of finish whose work panics is reported, and the
// next step still runs.
func TestStepWorkPanic(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	ran := false
	s.step(fiFinishStats, func() { panic("work") })
	s.step(fiFinishStats, func() { ran = true })
	if !ran || r.c.Stats().Panics != 1 {
		t.Fatalf("next step ran %v, panics %d", ran, r.c.Stats().Panics)
	}
	if ev := r.waitEvents(EvInternalError, 1)[0]; ev.Detail != fiFinishStats {
		t.Fatalf("event %+v", ev)
	}
	s.Abort(protocol.ReasonCanceled, "")
	r.wait(s)
}

// TestGuard: a panic in work a guard runs ends the session with internal.
func TestGuard(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	s.guard("coord.test", func() { panic("boom") })
	if res := r.wait(s); res.Code != protocol.ReasonInternal || res.Detail != "panic:coord.test: boom" {
		t.Fatalf("result %+v", res)
	}
}

// panicAfterCancel makes the step of Close that ends the sessions panic once
// it has ended them.
func panicAfterCancel(c *Coordinator) {
	cancel := c.cancelSessions
	c.cancelSessions = func(cause error) {
		cancel(cause)
		panic("cancel")
	}
}

// TestClosePanicIsReturned: a panic in a step of Close skips none of
// the later ones — the sessions end and the coordinator's goroutines are
// joined — and once the shutdown is complete Close returns the panic as a
// *life.PanicError, to every caller; it is counted and reported as well.
func TestClosePanicIsReturned(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{ClientKeys: [2]string{"a", "b"}})
	panicAfterCancel(r.c)
	err := r.c.Close()
	var pe *life.PanicError
	if !errors.As(err, &pe) || pe.Where() != fiClose || !strings.HasSuffix(pe.Error(), ": cancel") {
		t.Fatalf("close: %v (%T)", err, err)
	}
	if res := r.wait(p.s); res.Code != protocol.ReasonServerShutdown {
		t.Fatalf("result %+v", res)
	}
	for i := range 2 {
		expectEOFOrAbort(t, p.cl[i])
	}
	if st := r.c.Stats(); st.Panics != 1 || st.Stuck != 0 || st.SessionsActive != 0 || st.ActiveByKey != 0 {
		t.Fatalf("stats %+v", st)
	}
	if st := r.c.root.Stats(); st.Running != 0 || st.Leaked != 0 {
		t.Fatalf("root group %+v", st)
	}
	if ev := r.waitEvents(EvInternalError, 1)[0]; ev.Detail != fiClose {
		t.Fatalf("event %+v", ev)
	}
	if again := r.c.Close(); !errors.Is(again, err) {
		t.Fatalf("second close: %v, want %v", again, err)
	}
	if _, err := r.c.NewSession(SessionOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("new session after close: %v", err)
	}
}

// TestCloseErrs: Close reports nothing, its only failure as it is, or every
// failure in step order.
func TestCloseErrs(t *testing.T) {
	var none closeErrs
	none.add(nil)
	if err := none.err(); err != nil {
		t.Fatalf("no failure: %v", err)
	}
	pe := life.Safe(fiClose, func() { panic("step") })
	one := closeErrs{}
	one.add(pe)
	if err := one.err(); !errors.Is(err, pe) {
		t.Fatalf("one failure: %v", err)
	}
	one.add(ErrShutdownTimeout)
	err := one.err()
	if !errors.Is(err, pe) || !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("two failures: %v", err)
	}
	if want := pe.Error() + "\n" + ErrShutdownTimeout.Error(); err.Error() != want {
		t.Fatalf("two failures: %q, want %q", err, want)
	}
}

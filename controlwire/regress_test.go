package controlwire

// Regression tests for four concurrency defects of the teardown paths. Each
// scenario hangs, leaks or corrupts the caller's stream without the rule its
// test states.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/life"
)

// A panic in the caller's Write or SetWriteDeadline must settle the frame
// being written and wake every waiter; WriteFrame and Flush return within their
// bound even with context.Background().
func TestWritePanicWakesWaiters(t *testing.T) {
	for _, where := range []string{"Write", "SetWriteDeadline"} {
		t.Run(where, func(t *testing.T) {
			a, b := net.Pipe()
			defer func() { _ = b.Close() }()
			gate := make(chan struct{})
			rc := &recConn{Conn: a}
			var probes int
			switch where {
			case "Write":
				rc.onWrite = func([]byte) { <-gate; panic("user conn Write bug") }
			case "SetWriteDeadline":
				rc.onSetWrite = func(time.Time) {
					if probes++; probes > 1 { // the first call is NewConn's probe
						<-gate
						panic("user conn SetWriteDeadline bug")
					}
				}
			}
			c := mustConn(t, rc, ConnOptions{})
			wf := make(chan error, 1)
			go func() { wf <- c.WriteFrame(context.Background(), Frame{Type: TypePunchReady, Payload: []byte("{}")}) }()
			eventually(t, "the frame to be picked", func() bool {
				c.qmu.Lock()
				defer c.qmu.Unlock()
				return c.flight != nil
			})
			waiting := make(chan error, 1)
			go func() {
				waiting <- c.WriteFrame(context.Background(), Frame{Type: TypeRoundResult, Payload: []byte("{}")})
			}()
			eventually(t, "the second frame to queue", func() bool { return queued(c, prioP1) == 1 })
			fl := make(chan error, 1)
			flCtx := newDoneSignal(context.Background())
			go func() { fl <- c.Flush(flCtx) }()
			<-flCtx.called
			close(gate)

			var perr *life.PanicError
			for name, ch := range map[string]chan error{"in-flight WriteFrame": wf, "Flush": fl} {
				select {
				case err := <-ch:
					if !errors.As(err, &perr) {
						t.Errorf("%s = %v, want the PanicError", name, err)
					}
				case <-time.After(time.Second):
					t.Fatalf("%s still blocked after the writer panicked", name)
				}
			}
			select {
			case err := <-waiting:
				if !errors.Is(err, ErrDropped) || !errors.As(err, &perr) {
					t.Errorf("queued WriteFrame = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("queued WriteFrame still blocked")
			}
			<-c.Done()
			if !errors.As(c.Err(), &perr) {
				t.Fatalf("Err = %v", c.Err())
			}
			if err := c.Send(Frame{Type: TypePong}); !errors.As(err, &perr) {
				t.Fatalf("Send after the panic = %v", err)
			}
			err := within(t, "Release", time.Second, c.Release)
			if where == "Write" && !errors.Is(err, ErrUnreturnable) {
				t.Fatalf("Release after a Write panic = %v: how much was written is unknown", err)
			}
		})
	}
}

// A SendFunc builder slower than the release grace. The frame is
// dropped before any Write; Release returns once the builder is done and the
// caller's connection never sees a byte from the library afterwards.
func TestSlowBuilderCannotDefeatRelease(t *testing.T) {
	a, b := net.Pipe() // b does not read until the end
	defer func() { _ = b.Close() }()
	c := mustConn(t, a, ConnOptions{})
	inBuild := make(chan struct{})
	must(t, c.SendFunc(TypePong, func(time.Time) ([]byte, error) {
		close(inBuild)
		time.Sleep(3 * releaseGrace)
		return []byte(`{"seq":1}`), nil
	}))
	<-inBuild
	start := time.Now()
	must(t, within(t, "Release", time.Second, c.Release))
	if d := time.Since(start); d > releaseJoin {
		t.Fatalf("Release took %v", d)
	}
	_ = b.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _ := b.Read(make([]byte, 64)); n != 0 {
		t.Fatalf("%d bytes reached the caller's connection after Release", n)
	}
}

// The writer is preempted inside SetWriteDeadline(future) while Release
// interrupts. The interrupt must not be undone: no Write may start with the
// writer's deadline, and nothing touches the connection after Release.
func TestWriterDeadlineCannotOverrideInterrupt(t *testing.T) {
	a, b := net.Pipe() // b never reads
	defer func() { _ = b.Close() }()
	entered := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	rc := &recConn{Conn: a}
	rc.onSetWrite = func(dl time.Time) {
		if dl.After(time.Now()) {
			once.Do(func() { close(entered); <-resume })
		}
	}
	c := mustConn(t, rc, ConnOptions{})
	must(t, c.Send(Frame{Type: TypePong, Payload: []byte("{}")}))
	<-entered
	relDone := make(chan error, 1)
	start := time.Now()
	go func() { relDone <- c.Release() }()
	// Let Release run its grace and interrupt while the writer is stuck in
	// SetWriteDeadline; then let the writer continue.
	eventually(t, "Release to interrupt the write side", c.writeStopped)
	close(resume)
	var err error
	select {
	case err = <-relDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Release did not return")
	}
	if err != nil {
		t.Fatalf("Release = %v (no byte was written, the stream is clean)", err)
	}
	returned := time.Now()
	if rc.writes.Load() != 0 {
		t.Fatal("a Write started after Release interrupted the write side")
	}
	// The last deadline Release leaves is zero, set after the writer's own.
	evs := rc.eventsAfter(start)
	var lastWDL *event
	for i := range evs {
		if evs[i].op == "wdl" {
			lastWDL = &evs[i]
		}
	}
	if lastWDL == nil || !lastWDL.t.IsZero() {
		t.Fatalf("final write deadline = %+v, want cleared", lastWDL)
	}
	time.Sleep(50 * time.Millisecond)
	if late := rc.eventsAfter(returned); len(late) != 0 {
		t.Fatalf("calls on the connection after Release returned: %+v", late)
	}
}

// A connection that ignores write deadlines. Release cannot stop the
// stuck Write, so it reports ErrUnreturnable after its join bound, leaves the
// deadlines in the past (no clearing) and the stuck goroutine starts no new
// call when its Write finally returns.
func TestReleaseJoinTimeoutLeavesDeadlinesAndConnAlone(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	gate := make(chan struct{})
	rc := &recConn{Conn: deadlineIgnoring{a, gate}}
	c, err := NewConn(rc, ConnOptions{})
	must(t, err)
	must(t, c.Send(Frame{Type: TypePong, Payload: []byte("{}")}))
	eventually(t, "the stuck write", func() bool { return rc.writes.Load() == 1 })
	start := time.Now()
	err = within(t, "Release", 3*time.Second, c.Release)
	if !errors.Is(err, ErrUnreturnable) {
		t.Fatalf("Release = %v", err)
	}
	returned := time.Now()
	if d := returned.Sub(start); d < releaseJoin || d > releaseJoin+time.Second {
		t.Fatalf("Release took %v", d)
	}
	for _, e := range rc.eventsAfter(start) {
		if (e.op == "wdl" || e.op == "rdl") && e.t.IsZero() {
			t.Fatalf("a deadline was cleared although a goroutine is still running: %+v", e)
		}
	}
	close(gate)
	eventually(t, "the stuck goroutine to exit", func() bool { return c.g.Stats().Running == 0 })
	if late := rc.eventsAfter(returned); len(late) != 0 {
		t.Fatalf("calls on the connection after Release returned: %+v", late)
	}
	_ = a.Close()
}

// An Intercept callback blocked across Release. Release reports
// ErrUnreturnable after its join bound and keeps the read interrupted; when
// the callback returns, the reader issues no further Read, so the caller's
// bytes stay the caller's.
func TestBlockedInterceptDoesNotReadAfterRelease(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	unblock := make(chan struct{})
	entered := make(chan struct{}, 1)
	rc := &recConn{Conn: a}
	c, err := NewConn(rc, ConnOptions{Side: SideClient, Intercept: func(_ *Conn, f Frame) bool {
		if f.Type == TypePing {
			entered <- struct{}{}
			<-unblock
			return true
		}
		return false
	}})
	must(t, err)
	if _, err := b.Write(frameBytes(TypePing, `{"seq":1}`)); err != nil {
		t.Fatal(err)
	}
	<-entered
	start := time.Now()
	err = within(t, "Release", 3*time.Second, c.Release)
	if !errors.Is(err, ErrUnreturnable) {
		t.Fatalf("Release = %v", err)
	}
	returned := time.Now()
	for _, e := range rc.eventsAfter(start) {
		if e.op == "rdl" && e.t.IsZero() {
			t.Fatal("the read deadline was cleared while the reader was alive")
		}
	}
	close(unblock)
	eventually(t, "the reader to exit", func() bool { return c.g.Stats().Running == 0 })
	if late := rc.eventsAfter(returned); len(late) != 0 {
		t.Fatalf("calls on the connection after Release returned: %+v", late)
	}
	// The caller owns the connection again and reads its own protocol.
	go func() { _, _ = b.Write([]byte("CALLER-DATA-0123")) }()
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	if n, err := io.ReadFull(a, buf); err != nil || string(buf) != "CALLER-DATA-0123" {
		t.Fatalf("caller read %q (%d bytes, %v)", buf[:n], n, err)
	}
	_ = a.Close()
}

// Release while a frame is half received. The reader may finish that
// frame within the grace and the stream is handed back at the boundary; if
// the rest does not arrive in time, Release says the stream is unreturnable.
func TestReleaseWaitsForFrameBoundary(t *testing.T) {
	frame := frameBytes(TypePunchGo, `{"round":1,"padding":"xxxxxxxx"}`)
	t.Run("rest arrives within the grace", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() { _ = b.Close() }()
		c := mustConn(t, a, ConnOptions{Side: SideClient})
		if _, err := b.Write(frame[:HeaderSize+4]); err != nil {
			t.Fatal(err)
		}
		eventually(t, "the reader to be inside the frame", func() bool {
			c.rmu.Lock()
			defer c.rmu.Unlock()
			return c.rmid
		})
		rel := make(chan error, 1)
		go func() { rel <- c.Release() }()
		eventually(t, "Release to wait for the frame boundary", func() bool {
			c.rmu.Lock()
			defer c.rmu.Unlock()
			return c.rbound != nil
		})
		// The rest is written from a goroutine: if Release stopped the reader
		// mid-frame, nobody reads it and the deferred b.Close unblocks it.
		go func() { _, _ = b.Write(frame[HeaderSize+4:]) }()
		must(t, <-rel)
		if f, err := c.ReadFrame(context.Background()); err != nil || f.Type != TypePunchGo {
			t.Fatalf("the completed frame: %v, %v", f.Type, err)
		}
		go func() { _, _ = b.Write([]byte("hp-next")) }()
		buf := make([]byte, 7)
		if _, err := io.ReadFull(a, buf); err != nil || string(buf) != "hp-next" {
			t.Fatalf("caller stream starts with %q (%v)", buf, err)
		}
	})
	t.Run("rest arrives too late", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() { _ = b.Close() }()
		c := mustConn(t, a, ConnOptions{Side: SideClient})
		if _, err := b.Write(frame[:HeaderSize+4]); err != nil {
			t.Fatal(err)
		}
		eventually(t, "the reader to be inside the frame", func() bool {
			c.rmu.Lock()
			defer c.rmu.Unlock()
			return c.rmid
		})
		start := time.Now()
		err := c.Release()
		if !errors.Is(err, ErrUnreturnable) {
			t.Fatalf("Release = %v", err)
		}
		if d := time.Since(start); d < releaseGrace || d > releaseJoin {
			t.Fatalf("Release took %v", d)
		}
	})
}

// doneSignal is a context that reports, through called, the first time its
// Done method is used: Flush asks for it only once it has taken its target
// and is about to wait.
type doneSignal struct {
	context.Context
	once   sync.Once
	called chan struct{}
}

func newDoneSignal(ctx context.Context) *doneSignal {
	return &doneSignal{Context: ctx, called: make(chan struct{})}
}

func (d *doneSignal) Done() <-chan struct{} {
	d.once.Do(func() { close(d.called) })
	return d.Context.Done()
}

// gatedFailConn fails every Write once gate is closed.
type gatedFailConn struct {
	net.Conn
	gate chan struct{}
}

var errWriteBroken = errors.New("write broken")

func (g gatedFailConn) Write([]byte) (int, error) {
	<-g.gate
	return 0, errWriteBroken
}

// A frame lost to a failing write is reported by the Flush waiting for it:
// the frame leaves the flight only after the write side has stopped, so
// Flush never sees the loss without its cause and returns nil.
func TestFlushReportsFrameLostToWriteFailure(t *testing.T) {
	for i := range 300 {
		a, b := net.Pipe()
		gate := make(chan struct{})
		c, err := NewConn(gatedFailConn{a, gate}, ConnOptions{})
		must(t, err)
		must(t, c.Send(Frame{Type: TypePong, Payload: []byte("{}")}))
		ctx := newDoneSignal(context.Background())
		flushed := make(chan error, 1)
		go func() { flushed <- c.Flush(ctx) }()
		<-ctx.called
		close(gate)
		if err := <-flushed; !errors.Is(err, errWriteBroken) {
			t.Fatalf("iteration %d: Flush = %v, want the write error", i, err)
		}
		_ = c.Close()
		_ = b.Close()
	}
}

// lateCtx is an expired context that WriteFrame first sees alive: the
// frame is queued, and by the time WriteFrame waits, its stall bound has
// expired together with ctx — what a WriteFrame caller descheduled past its
// deadline sees when it runs again.
type lateCtx struct {
	context.Context
	checks atomic.Int32
}

func (l *lateCtx) Err() error {
	if l.checks.Add(1) == 1 {
		return nil
	}
	return l.Context.Err()
}

// WriteFrame with an ended context returns the context's cause and never
// fails the write side: not when the context had ended before the call,
// whether or not the writer is busy, and not when the frame's own stall
// bound expired together with the context.
func TestWriteFrameEndedContextLeavesLinkUsable(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	idle := mustConn(t, a, ConnOptions{})
	for i := range 32 {
		if err := idle.WriteFrame(expired, Frame{Type: TypeRoundResult, Payload: []byte("late")}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("idle writer, attempt %d: WriteFrame(ended ctx) = %v", i, err)
		}
	}
	if err := idle.Err(); err != nil {
		t.Fatalf("idle writer: Err = %v after WriteFrame calls with an ended ctx", err)
	}

	c, peer, release := stalledConn(t, SideClient)
	for i := range 32 {
		ctx := &lateCtx{Context: expired}
		if err := c.WriteFrame(ctx, Frame{Type: TypeRoundResult, Payload: []byte("late")}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("busy writer, attempt %d: WriteFrame(ended ctx) = %v", i, err)
		}
	}
	if err := c.Err(); err != nil {
		t.Fatalf("busy writer: Err = %v after WriteFrame calls with an ended ctx", err)
	}
	close(release)
	must(t, c.Send(Frame{Type: TypePong, Payload: []byte("next")}))
	if p := payloadsOf(readFrames(t, peer, 2)); fmt.Sprint(p) != "[first next]" {
		t.Fatalf("frames %v", p)
	}
}

// countConn's Write returns a count io.Writer does not allow.
type countConn struct {
	net.Conn
	count func(p []byte) int
}

func (c countConn) Write(p []byte) (int, error) { return c.count(p), nil }

// A Write that returns a count outside [0, len(p)] leaves the stream position
// unknown: the write side fails and Release does not hand the stream back
// as clean.
func TestWriteInvalidCountMakesStreamUnreturnable(t *testing.T) {
	for name, count := range map[string]func([]byte) int{
		"negative": func([]byte) int { return -1 },
		"too many": func(p []byte) int { return len(p) + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			defer func() { _ = b.Close() }()
			c := mustConn(t, countConn{a, count}, ConnOptions{})
			if err := c.WriteFrame(context.Background(), Frame{Type: TypePong, Payload: []byte("{}")}); err == nil {
				t.Fatal("WriteFrame succeeded with an invalid count")
			}
			<-c.Done()
			if err := within(t, "Release", time.Second, c.Release); !errors.Is(err, ErrUnreturnable) {
				t.Fatalf("Release = %v", err)
			}
		})
	}
}

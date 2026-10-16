package controlwire

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/life"
)

func TestNewConnRejectsNilAndDeadlineless(t *testing.T) {
	if _, err := NewConn(nil, ConnOptions{}); !errors.Is(err, ErrNilConn) {
		t.Fatalf("nil: %v", err)
	}
	var typed *net.TCPConn
	if _, err := NewConn(typed, ConnOptions{}); !errors.Is(err, ErrNilConn) {
		t.Fatalf("typed nil: %v", err)
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	rc := &recConn{Conn: a, onSetRead: func(time.Time) {}}
	rc.onSetWrite = func(time.Time) { panic("no deadlines here") }
	if _, err := NewConn(rc, ConnOptions{}); !errors.Is(err, ErrDeadlineUnsupported) {
		t.Fatalf("panicking SetWriteDeadline: %v", err)
	}
	if rc.reads.Load() != 0 || rc.writes.Load() != 0 {
		t.Fatal("NewConn read or wrote before failing")
	}
	unsupported := &recConn{Conn: deadlineless{a}}
	if _, err := NewConn(unsupported, ConnOptions{}); !errors.Is(err, ErrDeadlineUnsupported) {
		t.Fatalf("unsupported: %v", err)
	}
}

type deadlineless struct{ net.Conn }

func (deadlineless) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (deadlineless) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

// TestNoPollingWakeups: an idle link costs one blocked Read and no deadline
// calls; every frame costs at most two Reads.
func TestNoPollingWakeups(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	rc := &recConn{Conn: a}
	c := mustConn(t, rc, ConnOptions{})
	eventually(t, "the reader to block", func() bool { return rc.reads.Load() == 1 })
	time.Sleep(300 * time.Millisecond)
	if r, d := rc.reads.Load(), rc.setRead.Load(); r != 1 || d != 1 {
		t.Fatalf("idle: %d reads, %d SetReadDeadline (want 1 and the 1 probe)", r, d)
	}
	const frames = 40
	for i := range frames {
		if _, err := b.Write(frameBytes(TypePunchGo, `{"round":`+strconv.Itoa(i%8+1)+`}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ReadFrame(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if r := rc.reads.Load(); r > 2*frames+1 {
		t.Fatalf("%d reads for %d frames", r, frames)
	}
	if d := rc.setRead.Load(); d != 1 {
		t.Fatalf("%d SetReadDeadline calls while reading", d)
	}
	if w := rc.setWrite.Load(); w != 1 {
		t.Fatalf("%d SetWriteDeadline calls without writes", w)
	}
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	// Release: one interrupt, one clear on the read side; one clear on the write side.
	if d, w := rc.setRead.Load(), rc.setWrite.Load(); d != 3 || w != 2 {
		t.Fatalf("after Release: %d read and %d write deadline calls", d, w)
	}
}

func TestWritePriorityOrder(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	block := make(chan struct{})
	first := true
	rc := &recConn{Conn: a, onWrite: func([]byte) {
		if first {
			first = false
			<-block
		}
	}}
	c := mustConn(t, rc, ConnOptions{})
	// The first frame occupies the writer; the rest queue up behind it.
	must(t, c.Send(Frame{Type: TypeProgress, Payload: []byte("p0")}))
	eventually(t, "the first write", func() bool { return rc.writes.Load() == 1 })
	must(t, c.Send(Frame{Type: TypeProgress, Payload: []byte("p1")}))
	must(t, c.Send(Frame{Type: TypeAssist, Payload: []byte("a1")}))
	must(t, c.Send(Frame{Type: TypeRoundResult, Payload: []byte("r1")}))
	must(t, c.Send(Frame{Type: TypePong, Payload: []byte("g1")}))
	must(t, c.Send(Frame{Type: TypeAssist, Payload: []byte("a2")}))
	must(t, c.Send(Frame{Type: TypePunchResult, Payload: []byte("r2")}))
	must(t, c.Send(Frame{Type: TypePong, Payload: []byte("g2")}))
	close(block)
	got := payloadsOf(readFrames(t, b, 8))
	want := []string{"p0", "g1", "g2", "r1", "r2", "a1", "a2", "p1"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

// queued returns the number of frames waiting in the queue of priority p.
func queued(c *Conn, p priority) int {
	c.qmu.Lock()
	defer c.qmu.Unlock()
	return len(c.queues[p])
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// stalledConn returns a Conn whose writer is stuck in its first write until
// release is closed.
func stalledConn(t *testing.T, side Side) (c *Conn, peer net.Conn, release chan struct{}) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = b.Close() })
	release = make(chan struct{})
	var once sync.Once
	rc := &recConn{Conn: a, onWrite: func([]byte) {
		blocked := false
		once.Do(func() { blocked = true })
		if blocked {
			<-release
		}
	}}
	c = mustConn(t, rc, ConnOptions{Side: side})
	first := TypePong
	if side == SideServer {
		first = TypePing
	}
	must(t, c.Send(Frame{Type: first, Payload: []byte("first")}))
	eventually(t, "the stalled write", func() bool { return rc.writes.Load() == 1 })
	return c, b, release
}

func TestQueueBoundsAndDropPolicies(t *testing.T) {
	c, peer, release := stalledConn(t, SideClient)
	for range prioP0.queueCap() {
		must(t, c.Send(Frame{Type: TypePong}))
	}
	if err := c.Send(Frame{Type: TypePong}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("P0 full: %v", err)
	}
	for range prioP1.queueCap() {
		must(t, c.Send(Frame{Type: TypeRoundResult}))
	}
	if err := c.Send(Frame{Type: TypePunchResult}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("P1 full: %v", err)
	}
	for i := range prioP2.queueCap() {
		must(t, c.Send(Frame{Type: TypeAssist, Payload: []byte("a" + strconv.Itoa(i))}))
	}
	if err := c.Send(Frame{Type: TypeAssist, Payload: []byte("newest")}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("P2 full must refuse the newest frame: %v", err)
	}
	// P3 evicts the oldest; a WriteFrame waiting on the evicted frame learns it.
	evictedWaiter := make(chan error, 1)
	go func() {
		evictedWaiter <- c.WriteFrame(context.Background(), Frame{Type: TypeProgress, Payload: []byte("waited")})
	}()
	eventually(t, "the waited frame to queue", func() bool {
		c.qmu.Lock()
		defer c.qmu.Unlock()
		return len(c.queues[prioP3]) == 1
	})
	for i := range prioP3.queueCap() {
		must(t, c.Send(Frame{Type: TypeProgress, Payload: []byte("p" + strconv.Itoa(i))}))
	}
	if err := <-evictedWaiter; !errors.Is(err, ErrDropped) {
		t.Fatalf("evicted WriteFrame: %v", err)
	}
	if d := c.Stats().Dropped; d != 1 {
		t.Fatalf("dropped = %d", d)
	}
	close(release)
	n := 1 + prioP0.queueCap() + prioP1.queueCap() + prioP2.queueCap() + prioP3.queueCap()
	frames := readFrames(t, peer, n)
	last := frames[len(frames)-prioP3.queueCap():]
	if string(last[0].Payload) != "p0" || string(last[len(last)-1].Payload) != "p63" {
		t.Fatalf("P3 kept %q..%q", last[0].Payload, last[len(last)-1].Payload)
	}
}

func TestSendCoalesced(t *testing.T) {
	c, peer, release := stalledConn(t, SideClient)
	must(t, c.SendCoalesced(Frame{Type: TypeProgress, Payload: []byte("probe_done 1")}, "probe_done"))
	must(t, c.SendCoalesced(Frame{Type: TypeProgress, Payload: []byte("fire")}, "fire"))
	must(t, c.SendCoalesced(Frame{Type: TypeProgress, Payload: []byte("probe_done 2")}, "probe_done"))
	close(release)
	got := payloadsOf(readFrames(t, peer, 3))
	if fmt.Sprint(got) != "[first probe_done 2 fire]" {
		t.Fatalf("got %v", got)
	}
}

func TestSendChecks(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := mustConn(t, a, ConnOptions{Side: SideClient})
	for _, ty := range []Type{0, TypePunchStart, TypeAbort, TypePing, 13, 200} {
		if err := c.Send(Frame{Type: ty}); !errors.Is(err, ErrWrongDirection) {
			t.Errorf("client Send(%v) = %v", ty, err)
		}
	}
	if err := c.Send(Frame{Type: TypePong, Payload: make([]byte, 257)}); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("oversize: %v", err)
	}
	if err := c.SendFunc(TypePong, nil); err == nil {
		t.Error("SendFunc(nil) accepted")
	}
	srv := mustConn(t, b, ConnOptions{Side: SideServer})
	for _, ty := range []Type{TypeProbeReport, TypePong, TypePunchResult} {
		if err := srv.Send(Frame{Type: ty}); !errors.Is(err, ErrWrongDirection) {
			t.Errorf("server Send(%v) = %v", ty, err)
		}
	}
}

func TestWriteTimeoutFailsLink(t *testing.T) {
	a, b := net.Pipe() // b never reads
	defer func() { _ = b.Close() }()
	c := mustConn(t, a, ConnOptions{WriteTimeout: 50 * time.Millisecond})
	start := time.Now()
	err := c.WriteFrame(context.Background(), Frame{Type: TypeProbeReport, Payload: []byte("{}")})
	if !isTimeout(err) {
		t.Fatalf("WriteFrame = %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("WriteFrame took %v", d)
	}
	<-c.Done()
	if !isTimeout(c.Err()) {
		t.Fatalf("Err = %v", c.Err())
	}
	if err := c.Send(Frame{Type: TypePong}); !isTimeout(err) {
		t.Fatalf("Send after failure = %v", err)
	}
}

func TestWriteFrameAndFlush(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := mustConn(t, a, ConnOptions{})
	got := make(chan []Frame, 1)
	go func() { got <- readFrames(t, b, 3) }()
	must(t, c.Send(Frame{Type: TypeProgress, Payload: []byte("p")}))
	must(t, c.Send(Frame{Type: TypeAssist, Payload: []byte("a")}))
	must(t, c.WriteFrame(context.Background(), Frame{Type: TypePunchResult, Payload: []byte("r")}))
	must(t, c.Flush(context.Background()))
	frames := payloadsOf(<-got)
	slices.Sort(frames)
	if fmt.Sprint(frames) != "[a p r]" {
		t.Fatalf("frames %v", frames)
	}

	// A frame still queued when ctx ends is withdrawn and never written.
	c2, peer, release := stalledConn(t, SideClient)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := c2.WriteFrame(ctx, Frame{Type: TypeRoundResult, Payload: []byte("late")}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WriteFrame(expired ctx) = %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	if err := c2.Flush(ctx2); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush(expired ctx) = %v", err)
	}
	close(release)
	must(t, c2.Send(Frame{Type: TypePong, Payload: []byte("next")}))
	if p := payloadsOf(readFrames(t, peer, 2)); fmt.Sprint(p) != "[first next]" {
		t.Fatalf("withdrawn frame was written: %v", p)
	}
}

// TestFlushTargetsFramesQueuedBeforeIt: Flush does not wait for frames queued
// after it started.
func TestFlushTargetsFramesQueuedBeforeIt(t *testing.T) {
	c, peer, release := stalledConn(t, SideClient)
	done := make(chan error, 1)
	ctx := newDoneSignal(context.Background())
	go func() { done <- c.Flush(ctx) }()
	<-ctx.called // Flush has taken its target
	must(t, c.Send(Frame{Type: TypeProgress, Payload: []byte("after")}))
	close(release)
	readFrames(t, peer, 1) // "first": the only frame queued before Flush
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(time.Second):
		t.Fatal("Flush waited for a frame queued after it")
	}
	readFrames(t, peer, 1)
}

func TestFlushBoundedWithoutContextDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	gate := make(chan struct{})
	defer close(gate)
	rc := &recConn{Conn: deadlineIgnoring{a, gate}}
	c := mustConn(t, rc, ConnOptions{WriteTimeout: 60 * time.Millisecond})
	must(t, c.Send(Frame{Type: TypePong}))
	err := within(t, "Flush", time.Second, func() error { return c.Flush(context.Background()) })
	if !isTimeout(err) {
		t.Fatalf("Flush = %v", err)
	}
}

// deadlineIgnoring blocks every Write until gate is closed, whatever the
// write deadline says.
type deadlineIgnoring struct {
	net.Conn
	gate chan struct{}
}

func (d deadlineIgnoring) Write(_ []byte) (int, error) {
	<-d.gate
	return 0, net.ErrClosed
}

// TestInterceptAnswersPingAtP0 answers ping from Intercept with a pong built
// at write time, while the application's frames wait in the queue.
func TestInterceptAnswersPingAtP0(t *testing.T) {
	cli, srv := net.Pipe()
	defer func() { _ = srv.Close() }()
	answered := make(chan time.Duration, 1)
	c := mustConn(t, cli, ConnOptions{Side: SideClient, Intercept: func(c *Conn, f Frame) bool {
		if f.Type != TypePing {
			return false
		}
		_ = c.SendFunc(TypePong, func(now time.Time) ([]byte, error) {
			answered <- now.Sub(f.At)
			return append([]byte("pong:"), f.Payload...), nil
		})
		return true
	}})
	if _, err := srv.Write(frameBytes(TypePing, "1")); err != nil {
		t.Fatal(err)
	}
	if f := readFrames(t, srv, 1)[0]; f.Type != TypePong || string(f.Payload) != "pong:1" {
		t.Fatalf("got %v %q", f.Type, f.Payload)
	}
	if hold := <-answered; hold < 0 || hold > time.Second {
		t.Fatalf("hold %v", hold)
	}
	// Pings never reach ReadFrame.
	if _, err := srv.Write(frameBytes(TypePunchGo, "go")); err != nil {
		t.Fatal(err)
	}
	f, err := c.ReadFrame(context.Background())
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != TypePunchGo {
		t.Fatalf("ReadFrame = %v", f.Type)
	}
}

func TestInterceptPanicFailsReadSide(t *testing.T) {
	c := mustConn(t, newMemConn(frameBytes(TypePunchGo, "{}"), 0), ConnOptions{Intercept: func(*Conn, Frame) bool { panic("dispatcher bug") }})
	<-c.Done()
	var perr *life.PanicError
	if !errors.As(c.Err(), &perr) || perr.Where() != "ctl-read:intercept" {
		t.Fatalf("Err = %v", c.Err())
	}
}

func TestBuilderFailuresDropOnlyThatFrame(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := mustConn(t, a, ConnOptions{})
	must(t, c.SendFunc(TypePong, func(time.Time) ([]byte, error) { panic("builder bug") }))
	must(t, c.SendFunc(TypePong, func(time.Time) ([]byte, error) { return nil, errors.New("no") }))
	must(t, c.SendFunc(TypePong, func(time.Time) ([]byte, error) { return make([]byte, 257), nil }))
	must(t, c.Send(Frame{Type: TypePong, Payload: []byte("ok")}))
	if f := readFrames(t, b, 1)[0]; string(f.Payload) != "ok" {
		t.Fatalf("got %q", f.Payload)
	}
	if c.Err() != nil || c.Stats().Dropped != 3 {
		t.Fatalf("Err %v, dropped %d", c.Err(), c.Stats().Dropped)
	}
}

func TestReadDeliversBufferedFramesBeforeError(t *testing.T) {
	stream := append(frameBytes(TypePunchGo, "1"), frameBytes(TypePunchGo, "2")...)
	stream = append(stream, rawFrame(2, TypePunchGo, "3")...)
	c := mustConn(t, newMemConn(stream, 0), ConnOptions{})
	<-c.Done()
	for _, want := range []string{"1", "2"} {
		f, err := c.ReadFrame(context.Background())
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if string(f.Payload) != want {
			t.Fatalf("ReadFrame = %q, want %q", f.Payload, want)
		}
	}
	if _, err := c.ReadFrame(context.Background()); !errors.Is(err, ErrVersion) {
		t.Fatalf("final error %v", err)
	}
}

func TestReadFrameHonoursContext(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	rc := &recConn{Conn: a}
	c := mustConn(t, rc, ConnOptions{})
	cause := errors.New("phase timer")
	ctx, cancel := context.WithCancelCause(context.Background())
	time.AfterFunc(20*time.Millisecond, func() { cancel(cause) })
	if _, err := c.ReadFrame(ctx); !errors.Is(err, cause) {
		t.Fatalf("ReadFrame = %v", err)
	}
	if rc.setRead.Load() != 1 {
		t.Fatal("ReadFrame touched the read deadline")
	}
	must(t, c.Release())
	if _, err := c.ReadFrame(context.Background()); !errors.Is(err, ErrReleased) {
		t.Fatalf("after Release: %v", err)
	}
}

// TestReleaseLeavesCleanStream: whatever the timing, after Release the peer
// sees complete frames followed by exactly the caller's own bytes, and the
// caller can use the connection with cleared deadlines. A peer starved for
// longer than the release grace (a loaded machine) leaves the frame in flight
// cut; Release must then say so, and nothing follows the cut.
func TestReleaseLeavesCleanStream(t *testing.T) {
	iterations := 150
	if testing.Short() {
		iterations = 20
	}
	cut := 0
	for i := range iterations {
		a, b := net.Pipe()
		var peerBytes bytes.Buffer
		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			buf := make([]byte, 7) // small reads: frames are often cut mid-write
			for {
				n, err := b.Read(buf)
				peerBytes.Write(buf[:n])
				if err != nil {
					return
				}
			}
		}()
		c, err := NewConn(a, ConnOptions{})
		must(t, err)
		for j := range 30 {
			_ = c.Send(Frame{Type: TypeProgress, Payload: []byte(strconv.Itoa(j) + "-padding-padding")})
		}
		time.Sleep(time.Duration(i%7) * 100 * time.Microsecond)
		rerr := c.Release()
		switch {
		case rerr == nil:
			if _, err := a.Write([]byte("CALLER")); err != nil {
				t.Fatalf("iteration %d: caller write after Release: %v", i, err)
			}
		case errors.Is(rerr, ErrUnreturnable):
			cut++
		default:
			t.Fatalf("iteration %d: Release = %v", i, rerr)
		}
		_ = a.Close()
		<-peerDone
		rest := afterFrames(peerBytes.Bytes())
		if rerr == nil && string(rest) != "CALLER" {
			t.Fatalf("iteration %d: stream after the frames is %q", i, rest)
		}
		if rerr != nil && !framePrefix(rest) {
			t.Fatalf("iteration %d: Release = %v, stream after the frames is %q", i, rerr, rest)
		}
		_ = b.Close()
	}
	if cut == iterations {
		t.Fatalf("no Release of %d handed the stream back", iterations)
	}
	if cut > 0 {
		t.Logf("%d of %d releases cut a frame: the peer was starved beyond the grace", cut, iterations)
	}
}

// afterFrames skips the complete frames at the start of b and returns the
// rest.
func afterFrames(b []byte) []byte {
	for len(b) >= HeaderSize {
		_, n, err := ParseHeader([HeaderSize]byte(b), nil)
		if err != nil || len(b) < HeaderSize+n {
			break
		}
		b = b[HeaderSize+n:]
	}
	return b
}

// framePrefix reports whether b is the beginning of one frame, cut before
// its end (or empty).
func framePrefix(b []byte) bool {
	if len(b) < HeaderSize {
		hdr := []byte{'h', 'p', Version}
		return bytes.HasPrefix(hdr, b[:min(len(b), len(hdr))])
	}
	_, n, err := ParseHeader([HeaderSize]byte(b), nil)
	return err == nil && len(b) < HeaderSize+n
}

// TestReleaseWithStalledPeer: the peer stopped reading in the middle of a
// frame. Release returns within milliseconds, queued waiters learn their frame
// was dropped, and the half-written frame makes the stream unreturnable.
func TestReleaseWithStalledPeer(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := mustConn(t, a, ConnOptions{})
	must(t, c.Send(Frame{Type: TypeProbeReport, Payload: bytes.Repeat([]byte("x"), 100)}))
	if _, err := io.ReadFull(b, make([]byte, 20)); err != nil { // part of the frame, then stall
		t.Fatal(err)
	}
	waiter := make(chan error, 1)
	go func() {
		waiter <- c.WriteFrame(context.Background(), Frame{Type: TypePunchResult, Payload: []byte("r")})
	}()
	eventually(t, "the WriteFrame to queue", func() bool { return queued(c, prioP1) == 1 })
	start := time.Now()
	err := c.Release()
	if !errors.Is(err, ErrUnreturnable) {
		t.Fatalf("Release = %v", err)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("Release took %v", d)
	}
	if werr := <-waiter; !errors.Is(werr, ErrDropped) || !errors.Is(werr, ErrReleased) {
		t.Fatalf("queued WriteFrame = %v", werr)
	}
}

func TestReleaseOnIdleLinkIsCleanAndFast(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := mustConn(t, a, ConnOptions{})
	start := time.Now()
	must(t, c.Release())
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("Release took %v", d)
	}
	// Deadlines are cleared: a read that waits longer than any interrupt works.
	go func() { time.Sleep(30 * time.Millisecond); _, _ = b.Write([]byte("z")) }()
	buf := make([]byte, 1)
	if _, err := a.Read(buf); err != nil || buf[0] != 'z' {
		t.Fatalf("caller read after Release: %v", err)
	}
}

func TestShutdownIdempotentAndConcurrent(t *testing.T) {
	for round := range 40 {
		a, b := net.Pipe()
		c, err := NewConn(a, ConnOptions{})
		must(t, err)
		releaseFirst := round%2 == 0
		var wg sync.WaitGroup
		results := make([]error, 8)
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if (i%2 == 0) == releaseFirst {
					results[i] = c.Release()
				} else {
					results[i] = c.Close()
				}
			}()
		}
		wg.Wait()
		var rel, cls []error
		for i, err := range results {
			if (i%2 == 0) == releaseFirst {
				rel = append(rel, err)
			} else {
				cls = append(cls, err)
			}
		}
		// One of the two operations ran; the other reports which one did.
		ranRelease := c.term.mode == termRelease
		for _, err := range rel {
			if ranRelease && err != nil || !ranRelease && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("round %d: Release = %v (release ran: %v)", round, err, ranRelease)
			}
		}
		for _, err := range cls {
			if ranRelease && !errors.Is(err, ErrReleased) || !ranRelease && err != nil {
				t.Fatalf("round %d: Close = %v (release ran: %v)", round, err, ranRelease)
			}
		}
		_ = a.Close()
		_ = b.Close()
	}
}

func TestCloseUnblocksEverything(t *testing.T) {
	a, b := net.Pipe() // b never reads nor writes
	defer func() { _ = b.Close() }()
	c := mustConn(t, a, ConnOptions{Side: SideServer})
	readErr := make(chan error, 1)
	go func() { _, err := c.ReadFrame(context.Background()); readErr <- err }()
	writeErr := make(chan error, 1)
	go func() { writeErr <- c.WriteFrame(context.Background(), Frame{Type: TypePunchGo, Payload: []byte("x")}) }()
	time.Sleep(20 * time.Millisecond)
	must(t, within(t, "Close", time.Second, c.Close))
	if err := <-readErr; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrame after Close = %v", err)
	}
	if err := <-writeErr; err == nil {
		t.Fatal("WriteFrame after Close succeeded")
	}
	if err := c.Send(Frame{Type: TypePunchGo}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after Close = %v", err)
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("the connection is still open")
	}
}

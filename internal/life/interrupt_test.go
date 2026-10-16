package life

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInterruptReadUnblocksAndRestores(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	restore := InterruptRead(ctx, a)

	errc := make(chan error, 1)
	go func() {
		_, err := a.Read(make([]byte, 1))
		errc <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read error = %v, want deadline exceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read was not interrupted")
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	// After restore the deadline is clear: a read that waits for late data succeeds.
	go func() {
		time.Sleep(30 * time.Millisecond)
		_, _ = b.Write([]byte{7})
	}()
	buf := make([]byte, 1)
	if _, err := a.Read(buf); err != nil || buf[0] != 7 {
		t.Fatalf("read after restore = %v, %v", buf, err)
	}
}

// countingDeadliner counts SetReadDeadline calls and fails the clearing one
// with a distinct error per call.
type countingDeadliner struct {
	interrupts, clears atomic.Int32
}

func (c *countingDeadliner) SetReadDeadline(t time.Time) error {
	if !t.IsZero() {
		c.interrupts.Add(1)
		return nil
	}
	return fmt.Errorf("clear %d", c.clears.Add(1))
}

// TestRestoreTwiceRunsOnce: later restores return the first result without
// clearing again or waiting for another interrupt.
func TestRestoreTwiceRunsOnce(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		d := &countingDeadliner{}
		ctx, cancel := context.WithCancel(context.Background())
		restore := InterruptRead(ctx, d)
		if interrupted {
			cancel()
		}
		first := restore()
		if again := restore(); !errors.Is(again, first) {
			t.Fatalf("interrupted=%v: second restore = %v, want the first result %v", interrupted, again, first)
		}
		cancel()
		want := int32(0)
		if interrupted {
			want = 1
		}
		if n, m := d.interrupts.Load(), d.clears.Load(); n != want || m != 1 {
			t.Fatalf("interrupted=%v: %d interrupts and %d clears, want %d and 1", interrupted, n, m, want)
		}
	}
}

func TestRestoreConcurrentCallers(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	restore := InterruptRead(ctx, a)
	cancel()
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = restore() }()
	}
	wg.Wait()
}

// TestInterruptRestoreRace cancels and restores concurrently many times and
// checks that the deadline is always clear after restore: the interrupt can
// never land after the restore.
func TestInterruptRestoreRace(t *testing.T) {
	iterations := 2000
	if testing.Short() {
		iterations = 200
	}
	for i := range iterations {
		a, b := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		restore := InterruptRead(ctx, a)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); cancel() }()
		go func() { defer wg.Done(); _ = restore() }()
		wg.Wait()
		_ = restore()
		go func() { _, _ = b.Write([]byte{1}) }()
		buf := make([]byte, 1)
		if _, err := a.Read(buf); err != nil {
			t.Fatalf("iteration %d: read after restore failed: %v", i, err)
		}
		_ = a.Close()
		_ = b.Close()
	}
}

type panickyDeadliner struct {
	calls atomic.Int32
}

func (p *panickyDeadliner) SetReadDeadline(time.Time) error {
	p.calls.Add(1)
	panic("deadline broken")
}

func TestInterruptReadContainsPanics(t *testing.T) {
	d := &panickyDeadliner{}
	ctx, cancel := context.WithCancel(context.Background())
	restore := InterruptRead(ctx, d)
	cancel()
	err := restore()
	var perr *PanicError
	if !errors.As(err, &perr) || perr.Where() != "restore-read" {
		t.Fatalf("restore = %v, want PanicError from restore-read", err)
	}
	if d.calls.Load() != 2 {
		t.Fatalf("SetReadDeadline calls = %d, want 2 (interrupt + restore)", d.calls.Load())
	}
	if again := restore(); !errors.Is(again, err) {
		t.Fatalf("second restore = %v, want the first result", again)
	}
}

// slowDeadliner makes the interrupt slow, so that restore races with a
// callback that is still running.
type slowDeadliner struct {
	mu    sync.Mutex
	order []string
	enter chan struct{}
}

func (s *slowDeadliner) SetReadDeadline(t time.Time) error {
	if !t.IsZero() {
		close(s.enter)
		time.Sleep(30 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.IsZero() {
		s.order = append(s.order, "clear")
	} else {
		s.order = append(s.order, "interrupt")
	}
	return nil
}

func TestRestoreWaitsForRunningInterrupt(t *testing.T) {
	d := &slowDeadliner{enter: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	restore := InterruptRead(ctx, d)
	cancel()
	<-d.enter
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.order) != 2 || d.order[0] != "interrupt" || d.order[1] != "clear" {
		t.Fatalf("order = %v, want [interrupt clear]", d.order)
	}
}

func TestRestoreBeforeCancelNeverInterrupts(t *testing.T) {
	d := &slowDeadliner{enter: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	restore := InterruptRead(ctx, d)
	_ = restore()
	cancel()
	time.Sleep(10 * time.Millisecond)
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.order) != 1 || d.order[0] != "clear" {
		t.Fatalf("order = %v, want [clear]", d.order)
	}
}

func TestInterruptRegisteredOnDoneContext(t *testing.T) {
	d := &slowDeadliner{enter: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	restore := InterruptRead(ctx, d)
	_ = restore()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.order) != 2 || d.order[1] != "clear" {
		t.Fatalf("order = %v, want [interrupt clear]", d.order)
	}
}

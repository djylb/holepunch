package life

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/djylb/holepunch"
)

// IsPanic recognises a recovered panic of this package and of the library,
// wrapped or not, and nothing else.
func TestIsPanic(t *testing.T) {
	local := Safe("test", func() { panic("boom") })
	var lib holepunch.PanicError
	for _, c := range []struct {
		err  error
		want bool
	}{
		{local, true},
		{fmt.Errorf("wrapped: %w", local), true},
		{&lib, true},
		{fmt.Errorf("wrapped: %w", &lib), true},
		{errors.New("plain"), false},
		{nil, false},
	} {
		if got := IsPanic(c.err); got != c.want {
			t.Errorf("IsPanic(%v) = %v", c.err, got)
		}
	}
	if Safe("test", func() {}) != nil {
		t.Error("Safe reported a panic that did not happen")
	}
}

// Close joins the group's goroutines within its bound and counts the ones
// that ignore their context.
func TestGroupCloseBounded(t *testing.T) {
	g := New(context.Background())
	release := make(chan struct{})
	defer close(release)
	g.Go("stubborn", func(context.Context) { <-release })
	g.Go("polite", func(ctx context.Context) { <-ctx.Done() })
	start := time.Now()
	_ = g.Close(50 * time.Millisecond)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Close took %v", d)
	}
	if g.Leaked() != 1 {
		t.Fatalf("leaked %d, want 1", g.Leaked())
	}
	if g.Go("late", func(context.Context) {}) {
		t.Error("a closed group started a goroutine")
	}
}

// InterruptRead ends a blocked read when its context ends, and restore
// clears the deadline again.
func TestInterruptRead(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	restore := InterruptRead(ctx, a)
	done := make(chan error, 1)
	go func() { _, err := a.Read(make([]byte, 1)); done <- err }()
	cancel()
	select {
	case err := <-done:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("read ended with %v, want a timeout", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the read was not interrupted")
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = b.Write([]byte{1}) }()
	_ = a.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := a.Read(make([]byte, 1)); err != nil {
		t.Fatalf("read after restore: %v", err)
	}
}

package nattest

import (
	"bytes"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("read: %v", err)
	}
	return b
}

func TestPipeAsymmetricDelay(t *testing.T) {
	n, clk := fakeNet(t)
	a, b := n.Pipe(PipeConfig{DelayAB: 50 * time.Millisecond, DelayBA: 250 * time.Millisecond})
	_, _ = a.Write([]byte("ab"))
	_, _ = b.Write([]byte("ba"))
	clk.Advance(49 * time.Millisecond)
	if len(b.rx.ready) != 0 {
		t.Fatal("delivered early")
	}
	clk.Advance(time.Millisecond)
	if got := string(readN(t, b, 2)); got != "ab" {
		t.Fatal(got)
	}
	clk.Advance(199 * time.Millisecond)
	if len(a.rx.ready) != 0 {
		t.Fatal("BA delivered early")
	}
	clk.Advance(time.Millisecond)
	if got := string(readN(t, a, 2)); got != "ba" {
		t.Fatal(got)
	}
}

func TestPipeOrderWithJitter(t *testing.T) {
	n := newNet(t)
	a, b := n.Pipe(PipeConfig{DelayAB: 2 * time.Millisecond, Jitter: 2 * time.Millisecond})
	var want bytes.Buffer
	for i := range 200 {
		chunk := []byte{byte(i), byte(i >> 8)}
		want.Write(chunk)
		if _, err := a.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if got := readN(t, b, want.Len()); !bytes.Equal(got, want.Bytes()) {
		t.Fatal("the stream was reordered")
	}
}

func TestPipeBackpressure(t *testing.T) {
	n := newNet(t)
	a, b := n.Pipe(PipeConfig{BufferBytes: 1024})
	if k, err := a.Write(make([]byte, 1024)); k != 1024 || err != nil {
		t.Fatal(k, err)
	}
	_ = a.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	if k, err := a.Write(make([]byte, 10)); k != 0 || !isTimeout(err) {
		t.Fatalf("expected a write timeout, got %d %v", k, err)
	}
	_ = a.SetWriteDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, err := a.Write(make([]byte, 2000)); done <- err }()
	total := 0
	for total < 1024+2000 {
		total += len(readN(t, b, min(512, 1024+2000-total)))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if k, err := a.Write(nil); k != 0 || err != nil {
		t.Fatal("empty write", k, err)
	}
	if k, err := b.Read(nil); k != 0 || err != nil {
		t.Fatal("empty read", k, err)
	}
}

func TestPipeCloseGivesEOF(t *testing.T) {
	n := newNet(t)
	a, b := n.Pipe(PipeConfig{DelayAB: time.Millisecond, DelayBA: time.Millisecond})
	_, _ = a.Write([]byte("last words"))
	_ = a.Close()
	if got := string(readN(t, b, 10)); got != "last words" {
		t.Fatal(got)
	}
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
	if _, err := b.Write([]byte("x")); !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("write to a closed peer: %v", err)
	}
	if _, err := a.Read(make([]byte, 1)); !isClosedErr(err) {
		t.Fatalf("read on a closed end: %v", err)
	}
	if err := a.Close(); !isClosedErr(err) {
		t.Fatalf("second Close: %v", err)
	}
	if a.SetDeadline(time.Now()) == nil || a.SetWriteDeadline(time.Now()) == nil {
		t.Fatal("deadline on a closed end")
	}
}

// TestPipeReaderClosedDiscards: data arriving for an end that has closed is
// discarded and frees the sender's buffer.
func TestPipeReaderClosedDiscards(t *testing.T) {
	n, clk := fakeNet(t)
	a, b := n.Pipe(PipeConfig{DelayAB: 10 * time.Millisecond, BufferBytes: 4})
	if _, err := a.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	clk.Advance(10 * time.Millisecond)
	if a.tx.pending != 0 || len(a.tx.ready) != 0 {
		t.Fatalf("pending %d ready %d", a.tx.pending, len(a.tx.ready))
	}
}

func TestPipeCut(t *testing.T) {
	n := newNet(t)
	a, b := n.Pipe(PipeConfig{DelayAB: time.Hour})
	_, _ = a.Write([]byte("lost"))
	done := make(chan error, 1)
	go func() { _, err := b.Read(make([]byte, 4)); done <- err }()
	time.Sleep(10 * time.Millisecond)
	a.Cut()
	if err := <-done; err != io.EOF {
		t.Fatalf("blocked read after Cut: %v", err)
	}
	if _, err := a.Write([]byte("x")); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("write after Cut: %v", err)
	}
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
	a.Cut() // idempotent
}

func TestPipeBlackhole(t *testing.T) {
	n, clk := fakeNet(t)
	a, b := n.Pipe(PipeConfig{DelayAB: 10 * time.Millisecond})
	_, _ = a.Write([]byte("in flight"))
	b.Blackhole()
	if k, err := a.Write([]byte("silenced")); k != 8 || err != nil {
		t.Fatal(k, err)
	}
	_ = a.Close() // the FIN is swallowed as well
	clk.Advance(time.Second)
	_ = b.SetReadDeadline(clk.Now().Add(100 * time.Millisecond))
	done := make(chan error, 1)
	go func() { _, err := b.Read(make([]byte, 16)); done <- err }()
	clk.Advance(100 * time.Millisecond)
	if err := <-done; !isTimeout(err) {
		t.Fatalf("read on a blackholed pipe: %v", err)
	}
}

func TestPipeSetDelayAndCrash(t *testing.T) {
	n, clk := fakeNet(t)
	h := n.PublicHost()
	a, b := n.Pipe(PipeConfig{A: h})
	a.SetDelay(100*time.Millisecond, 0)
	_, _ = a.Write([]byte("x"))
	clk.Advance(99 * time.Millisecond)
	if len(b.rx.ready) != 0 {
		t.Fatal("SetDelay ignored")
	}
	clk.Advance(time.Millisecond)
	readN(t, b, 1)
	h.Crash()
	clk.Advance(100 * time.Millisecond)
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("peer of a crashed host: %v", err)
	}
	if _, err := a.Write([]byte("x")); !isClosedErr(err) {
		t.Fatalf("crashed end: %v", err)
	}
}

func TestPipeDeadlinesInterruptBlockedCalls(t *testing.T) {
	n := newNet(t)
	a, b := n.Pipe(PipeConfig{BufferBytes: 1})
	_, _ = a.Write([]byte("x"))
	done := make(chan error, 2)
	go func() { _, err := a.Write([]byte("y")); done <- err }()
	go func() { _, err := a.Read(make([]byte, 1)); done <- err }()
	time.Sleep(10 * time.Millisecond)
	_ = a.SetDeadline(time.Now())
	for range 2 {
		if err := <-done; !isTimeout(err) {
			t.Fatalf("blocked call after the deadline: %v", err)
		}
	}
	readN(t, b, 1)
}

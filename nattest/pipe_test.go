package nattest

import (
	"bytes"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
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

// TestPipeCut: the bubble's Wait makes sure that the read is blocked before
// the link is cut.
func TestPipeCut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newNet(t)
		a, b := n.Pipe(PipeConfig{DelayAB: time.Hour})
		_, _ = a.Write([]byte("lost"))
		done := make(chan error, 1)
		go func() { _, err := b.Read(make([]byte, 4)); done <- err }()
		synctest.Wait()
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
	})
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

// TestPipeDeadlinesInterruptBlockedCalls: the bubble's Wait makes sure that
// the write and the read are blocked before the deadline passes.
func TestPipeDeadlinesInterruptBlockedCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newNet(t)
		a, b := n.Pipe(PipeConfig{BufferBytes: 1})
		_, _ = a.Write([]byte("x"))
		done := make(chan error, 2)
		go func() { _, err := a.Write([]byte("y")); done <- err }()
		go func() { _, err := a.Read(make([]byte, 1)); done <- err }()
		synctest.Wait()
		_ = a.SetDeadline(time.Now())
		for range 2 {
			if err := <-done; !isTimeout(err) {
				t.Fatalf("blocked call after the deadline: %v", err)
			}
		}
		readN(t, b, 1)
	})
}

// TestPipeConcurrentWritesStayWhole: concurrent Writes through a buffer much
// smaller than each of them are delivered one after the other, never
// interleaved, as on a TCP connection.
func TestPipeConcurrentWritesStayWhole(t *testing.T) {
	n := newNet(t)
	a, b := n.Pipe(PipeConfig{DelayAB: time.Millisecond, BufferBytes: 8})
	const size = 256
	letters := []byte("abcd")
	done := make(chan error, len(letters))
	for _, l := range letters {
		go func() { _, err := a.Write(bytes.Repeat([]byte{l}, size)); done <- err }()
	}
	got := readN(t, b, size*len(letters))
	for range letters {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < len(got); i += size {
		if run := got[i : i+size]; !bytes.Equal(run, bytes.Repeat(run[:1], size)) {
			t.Fatalf("writes interleaved at offset %d: %q", i, run)
		}
	}
}

// TestPipeEveryBlockedReaderWakes: data or an EOF that one wakeup brings is
// passed on to the other blocked readers. The bubble's Wait makes sure that
// every reader is blocked before the data and the EOF arrive.
func TestPipeEveryBlockedReaderWakes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newNet(t)
		a, b := n.Pipe(PipeConfig{})
		const readers = 3
		_ = b.SetReadDeadline(time.Now().Add(10 * time.Second))
		got := make(chan error, readers)
		read := func() { _, err := b.Read(make([]byte, 1)); got <- err }
		for range readers {
			go read()
		}
		synctest.Wait()
		if _, err := a.Write([]byte("xyz")); err != nil {
			t.Fatal(err)
		}
		for range readers {
			if err := <-got; err != nil {
				t.Fatalf("a reader missed the data: %v", err)
			}
		}
		for range readers {
			go read()
		}
		synctest.Wait()
		_ = a.Close()
		for range readers {
			if err := <-got; err != io.EOF {
				t.Fatalf("a reader missed the EOF: %v", err)
			}
		}
	})
}

// TestPipeBlockedWriteEndsOnClose: a Write waiting behind another one
// returns when its end closes, like the one that holds the turn.
func TestPipeBlockedWriteEndsOnClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := newNet(t)
		a, _ := n.Pipe(PipeConfig{BufferBytes: 1})
		_, _ = a.Write([]byte("x")) // the buffer is full: every later Write blocks
		done := make(chan error, 2)
		for range 2 {
			go func() { _, err := a.Write([]byte("y")); done <- err }()
		}
		synctest.Wait()
		_ = a.Close()
		for range 2 {
			if err := <-done; !isClosedErr(err) {
				t.Fatalf("blocked Write after Close: %v", err)
			}
		}
	})
}

// TestPipeDueWriteWaitsForEarlierData: a write that is due at once, here
// because the delay dropped to zero, still arrives after the data written
// before it that is due but not yet delivered.
func TestPipeDueWriteWaitsForEarlierData(t *testing.T) {
	n, clk := fakeNet(t)
	a, b := n.Pipe(PipeConfig{DelayAB: 10 * time.Millisecond})
	// Armed before the first chunk is scheduled, this timer fires first at
	// the chunk's arrival time, while the chunk is due but undelivered.
	var werr error
	clk.AfterFunc(10*time.Millisecond, func() {
		a.SetDelay(0, 0)
		_, werr = a.Write([]byte("2"))
	})
	if _, err := a.Write([]byte("1")); err != nil {
		t.Fatal(err)
	}
	clk.Advance(10 * time.Millisecond)
	if werr != nil {
		t.Fatal(werr)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(b, got); err != nil || string(got) != "12" {
		t.Fatalf("read %q, %v; want the bytes in write order", got, err)
	}
}

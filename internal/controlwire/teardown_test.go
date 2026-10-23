package controlwire

// Regression tests for the teardown paths that close a notification channel:
// whatever panics on the way, the channel is closed, so no caller waits
// forever, and the panic reaches no caller.

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/faultconn"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/internal/wiretype"
)

// TestTerminatePanicReleasesCallers: a panic in Release's or Close's work —
// at once, or after part of the stop — is that call's result for every
// caller (for Release wrapped in ErrUnreturnable), never a panic or a clean
// nil, and the Conn still stops: Done closes, a blocked writer and the
// waiters of its queue wake up, the reader ends, both goroutines are joined
// and Close closes the connection.
func TestTerminatePanicReleasesCallers(t *testing.T) {
	type mode struct {
		name  string
		op    func(*Conn) error
		other func(*Conn) error
		mode  termMode
		cause error
	}
	modes := []mode{
		{"Release", (*Conn).Release, (*Conn).Close, termRelease, ErrReleased},
		{"Close", (*Conn).Close, (*Conn).Release, termClose, net.ErrClosed},
	}
	runs := []struct {
		name string
		run  func(c *Conn, cause error) func() error
	}{
		{"at once", func(*Conn, error) func() error { return func() error { panic("terminate bug") } }},
		{"midway", func(c *Conn, cause error) func() error {
			return func() error {
				c.fail(cause)
				c.stopQueues(cause)
				c.stopReadingAtBoundary(cause)
				panic("terminate bug")
			}
		}},
	}
	for _, m := range modes {
		for _, rn := range runs {
			t.Run(m.name+"/"+rn.name, func(t *testing.T) {
				a, b := net.Pipe()
				defer func() { _ = b.Close() }()
				rc := faultconn.Wrap(a)
				rc.Record()
				c := mustConn(t, rc, ConnOptions{})
				// The peer does not read: the first frame blocks the writer in
				// Write, the second waits in the queue.
				must(t, c.Send(Frame{Type: wiretype.Pong, Payload: []byte("1")}))
				testkit.WaitFor(t, "the writer to block", func() bool { return rc.Writes() > 0 })
				queued := make(chan error, 1)
				go func() {
					queued <- c.WriteFrame(context.Background(), Frame{Type: wiretype.Pong, Payload: []byte("2")})
				}()
				read := make(chan error, 1)
				go func() {
					_, err := c.ReadFrame(context.Background())
					read <- err
				}()

				err := within(t, "terminate", 2*time.Second, func() error { return c.terminate(m.mode, rn.run(c, m.cause)) })
				returned := time.Now()
				var pe *life.PanicError
				if !errors.As(err, &pe) || pe.Where() != "controlwire:terminate" {
					t.Fatalf("%s = %v, want the panic", m.name, err)
				}
				if unreturnable := errors.Is(err, ErrUnreturnable); unreturnable != (m.mode == termRelease) {
					t.Fatalf("%s = %v: ErrUnreturnable %v", m.name, err, unreturnable)
				}
				select {
				case <-c.Done():
				default:
					t.Fatal("Done is open")
				}
				if !errors.Is(c.Err(), m.cause) {
					t.Fatalf("Err = %v, want %v", c.Err(), m.cause)
				}
				if st := c.g.Stats(); st.Running != 0 || st.Leaked != 0 {
					t.Fatalf("goroutines after %s: %+v", m.name, st)
				}
				for what, ch := range map[string]chan error{"queued WriteFrame": queued, "ReadFrame": read} {
					select {
					case err := <-ch:
						if err == nil {
							t.Fatalf("%s returned nil", what)
						}
					case <-time.After(time.Second):
						t.Fatalf("%s still blocked", what)
					}
				}
				if again := within(t, "a second "+m.name, time.Second, func() error { return m.op(c) }); !errors.Is(again, err) {
					t.Fatalf("second %s = %v, want %v", m.name, again, err)
				}
				if other := within(t, "the other terminal call", time.Second, func() error { return m.other(c) }); !errors.Is(other, m.cause) {
					t.Fatalf("other terminal call = %v, want %v", other, m.cause)
				}
				if m.mode == termClose {
					if _, err := b.Read(make([]byte, 1)); err == nil {
						t.Fatal("the connection is open after Close")
					}
				} else if late := rc.EventsAfter(returned); len(late) > 0 {
					t.Fatalf("calls on the connection after Release returned: %+v", late)
				}
			})
		}
	}
}

// isPanics is an error whose Is method panics: matching it with errors.Is
// runs code of whoever made the error.
type isPanics struct{}

func (isPanics) Error() string   { return "is panics" }
func (isPanics) Is(_ error) bool { panic("Is") }

// TestReadEndRunsNoUserCode: the reader ends because Intercept panicked
// with an error whose Is panics. Settling the end must not call into that
// value — the old errors.Is(err, errStopped) did, outside every boundary,
// and the reader died without closing readDone or Done — so Done closes,
// Err and ReadFrame report the panic, and Release returns.
func TestReadEndRunsNoUserCode(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := mustConn(t, a, ConnOptions{Intercept: func(*Conn, Frame) bool { panic(isPanics{}) }})
	go func() { _, _ = b.Write(frameBytes(wiretype.PunchGo, "{}")) }()
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("Done is open after the reader ended")
	}
	var pe *life.PanicError
	if !errors.As(c.Err(), &pe) || pe.Where() != "ctl-read:intercept" {
		t.Fatalf("Err = %v", c.Err())
	}
	err := within(t, "ReadFrame", time.Second, func() error {
		_, err := c.ReadFrame(context.Background())
		return err
	})
	if !errors.As(err, &pe) {
		t.Fatalf("ReadFrame = %v", err)
	}
	if err := within(t, "Release", time.Second, c.Release); err != nil {
		t.Fatalf("Release = %v", err)
	}
}

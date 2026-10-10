//go:build holepunch_faultinject

package controlwire

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
)

// The ctl.read and ctl.write points fail the side they
// are on like a broken connection would, and never leave a waiter blocked.

func TestFaultReadError(t *testing.T) {
	defer faultinject.Reset()
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	disarm := faultinject.Arm("ctl.read", faultinject.Error(nil), 0)
	defer disarm()
	c := mustConn(t, a, ConnOptions{})
	<-c.Done()
	if !errors.Is(c.Err(), faultinject.ErrInjected) {
		t.Fatalf("Err = %v", c.Err())
	}
	if _, err := c.ReadFrame(context.Background()); !errors.Is(err, faultinject.ErrInjected) {
		t.Fatalf("ReadFrame = %v", err)
	}
}

func TestFaultReadPanic(t *testing.T) {
	defer faultinject.Reset()
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	disarm := faultinject.Arm("ctl.read", faultinject.Panic(), 1)
	defer disarm()
	c := mustConn(t, a, ConnOptions{})
	<-c.Done()
	var perr *life.PanicError
	if !errors.As(c.Err(), &perr) {
		t.Fatalf("Err = %v", c.Err())
	}
}

func TestFaultWritePanicAndError(t *testing.T) {
	for name, action := range map[string]faultinject.Action{"panic": faultinject.Panic(), "error": faultinject.Error(nil),
		"close": faultinject.CloseConn()} {
		t.Run(name, func(t *testing.T) {
			defer faultinject.Reset()
			a, b := net.Pipe()
			defer func() { _ = b.Close() }()
			disarm := faultinject.Arm("ctl.write", action, 1)
			defer disarm()
			c := mustConn(t, a, ConnOptions{})
			err := within(t, "WriteFrame", time.Second, func() error {
				return c.WriteFrame(context.Background(), Frame{Type: TypePong, Payload: []byte("{}")})
			})
			if !errors.Is(err, faultinject.ErrInjected) {
				t.Fatalf("WriteFrame = %v", err)
			}
			<-c.Done()
			// An error leaves the stream clean; after a panic inside the write
			// call nobody knows how much reached the wire.
			rerr := within(t, "Release", time.Second, c.Release)
			if name == "panic" && !errors.Is(rerr, ErrUnreturnable) || name != "panic" && rerr != nil {
				t.Fatalf("Release = %v", rerr)
			}
		})
	}
}

func TestFaultWriteStallIsBounded(t *testing.T) {
	defer faultinject.Reset()
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	disarm := faultinject.Arm("ctl.write", faultinject.Stall(0), 1)
	c := mustConn(t, a, ConnOptions{WriteTimeout: 50 * time.Millisecond})
	err := within(t, "WriteFrame", time.Second, func() error {
		return c.WriteFrame(context.Background(), Frame{Type: TypePong, Payload: []byte("{}")})
	})
	if !isTimeout(err) {
		t.Fatalf("WriteFrame = %v", err)
	}
	disarm()
}

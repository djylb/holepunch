//go:build holepunch_faultinject

package faultinject

import (
	"fmt"
	"net"
	"time"
)

type kind uint8

const (
	kindPanic kind = iota + 1
	kindError
	kindStall
	kindCloseConn
)

// Action is what an armed point does when it fires. Build one with Panic,
// Error, Stall or CloseConn; the zero Action is invalid.
type Action struct {
	kind  kind
	err   error
	stall time.Duration
}

// Panic makes the point panic with an error wrapping ErrInjected.
func Panic() Action { return Action{kind: kindPanic} }

// Error makes the point return err unchanged, so a test can inject the exact
// error it needs (io.EOF, syscall.EPERM, ...). A nil err injects an error
// that names the point and wraps ErrInjected.
func Error(err error) Action { return Action{kind: kindError, err: err} }

// Stall blocks the caller of the point for d and then lets it continue with a
// nil error. A d that is not positive stalls until the point is disarmed.
// Disarming always releases stalled callers early.
func Stall(d time.Duration) Action { return Action{kind: kindStall, stall: d} }

// CloseConn makes the point return an error wrapping ErrCloseConn and
// net.ErrClosed. The call site closes the connection it is working on.
func CloseConn() Action { return Action{kind: kindCloseConn} }

// String names the action for test logs.
func (a Action) String() string {
	switch a.kind {
	case kindPanic:
		return "panic"
	case kindError:
		if a.err == nil {
			return "error"
		}
		return fmt.Sprintf("error(%q)", a.err.Error())
	case kindStall:
		if a.stall <= 0 {
			return "stall(until disarm)"
		}
		return "stall(" + a.stall.String() + ")"
	case kindCloseConn:
		return "close-conn"
	}
	return "invalid"
}

// apply performs the action for point name. released is closed when the arm
// is disarmed or replaced.
func (a Action) apply(name string, released <-chan struct{}) error {
	switch a.kind {
	case kindPanic:
		panic(fmt.Errorf("faultinject: panic at %s: %w", name, ErrInjected))
	case kindError:
		if a.err != nil {
			return a.err
		}
		return fmt.Errorf("faultinject: error at %s: %w", name, ErrInjected)
	case kindStall:
		stall(a.stall, released)
		return nil
	case kindCloseConn:
		return fmt.Errorf("faultinject: %s: %w: %w", name, ErrCloseConn, net.ErrClosed)
	}
	return nil
}

func stall(d time.Duration, released <-chan struct{}) {
	if d <= 0 {
		<-released
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-released:
	}
}

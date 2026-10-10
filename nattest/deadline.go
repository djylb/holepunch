package nattest

import (
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/clock"
)

// deadline is a resettable read or write deadline in the style of net.Pipe:
// a channel that is closed once the deadline has passed, closed by one timer
// of the network clock. Blocked calls select on the channel; moving the
// deadline keeps the channel while it is open, so they see the new time
// without being woken.
type deadline struct {
	mu     sync.Mutex
	timer  clock.Timer
	cancel chan struct{}
}

func newDeadline() deadline { return deadline{cancel: make(chan struct{})} }

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// set moves the deadline to t; the zero t removes it.
func (d *deadline) set(n *Network, t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		// The timer has fired: wait until its callback has closed the
		// channel, so that the state below is not overwritten by it.
		<-d.cancel
	}
	d.timer = nil
	closed := isClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := n.until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = n.clock.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

// wait returns the channel that is closed when the current deadline passes.
func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func (d *deadline) expired() bool { return isClosed(d.wait()) }

// stop releases the timer when the conn closes.
func (d *deadline) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}

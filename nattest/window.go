package nattest

import (
	"container/list"
	"time"
)

// The sliding-window counters below are shared by HostStats (what a host
// sent) and ScanDefense (what a NAT reacts to), so that a test asserting a
// budget and a NAT enforcing it count the same way. They are not safe for
// concurrent use; their owner holds a lock.

// portWindow counts the distinct ports seen within a sliding window. It
// keeps one entry per port, ordered by when the port was last seen, so its
// memory follows the number of distinct ports, not of packets; seeing a port
// again only moves its entry to the back.
type portWindow struct {
	win    time.Duration
	byPort map[uint16]*list.Element // of *portSeen
	order  list.List                // least recently seen first
}

type portSeen struct {
	t    time.Duration
	port uint16
}

func newPortWindow(win time.Duration) *portWindow {
	return &portWindow{win: win, byPort: make(map[uint16]*list.Element)}
}

// add records port at now and returns the number of distinct ports in the
// window ending at now. Calls must come in time order.
func (w *portWindow) add(now time.Duration, port uint16) int {
	w.expire(now)
	if e := w.byPort[port]; e != nil {
		e.Value.(*portSeen).t = now
		w.order.MoveToBack(e)
	} else {
		w.byPort[port] = w.order.PushBack(&portSeen{now, port})
	}
	return len(w.byPort)
}

func (w *portWindow) expire(now time.Duration) {
	for e := w.order.Front(); e != nil; e = w.order.Front() {
		ps := e.Value.(*portSeen)
		if now-ps.t < w.win {
			return
		}
		delete(w.byPort, ps.port)
		w.order.Remove(e)
	}
}

func (w *portWindow) idle(now time.Duration) bool {
	w.expire(now)
	return len(w.byPort) == 0
}

// countWindow counts events within a sliding window.
type countWindow struct {
	win  time.Duration
	q    []time.Duration
	head int
}

// add records an event at now and returns the number of events in the
// window ending at now.
func (w *countWindow) add(now time.Duration) int {
	w.expire(now)
	w.q = append(w.q, now)
	return len(w.q) - w.head
}

func (w *countWindow) expire(now time.Duration) {
	for w.head < len(w.q) && now-w.q[w.head] >= w.win {
		w.head++
	}
	if w.head > 1024 && w.head*2 > len(w.q) {
		n := copy(w.q, w.q[w.head:])
		w.q = w.q[:n]
		w.head = 0
	}
}

func (w *countWindow) count(now time.Duration) int {
	w.expire(now)
	return len(w.q) - w.head
}

// runState measures runs of consecutive ports, ascending or descending, the
// pattern of a sequential port scan (holepunch's send guard limits it to 3).
type runState struct {
	valid bool
	last  uint16
	dir   int8
	run   int
	at    time.Duration
}

// add records port at now and returns the length of the current run. A
// repeated port neither extends nor breaks the run, and a pause of gap or
// more starts a new one.
func (r *runState) add(now time.Duration, port uint16, gap time.Duration) int {
	switch {
	case !r.valid || (gap > 0 && now-r.at >= gap):
		r.valid, r.dir, r.run = true, 0, 1
	case port == r.last:
	case int(port) == int(r.last)+1:
		if r.dir == 1 {
			r.run++
		} else {
			r.dir, r.run = 1, 2
		}
	case int(port) == int(r.last)-1:
		if r.dir == -1 {
			r.run++
		} else {
			r.dir, r.run = -1, 2
		}
	default:
		r.dir, r.run = 0, 1
	}
	r.last, r.at = port, now
	return r.run
}

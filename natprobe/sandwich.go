package natprobe

import (
	"sync"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
)

// sandwichQueue is a session's bounded queue of sandwich events. A reader
// offers an event without blocking; when no delivery is in
// progress it becomes the deliverer and hands the queued events to the sink
// one at a time, each outside the lock and inside a recover boundary, so at
// most one goroutine is in a session's sink at a time and the other readers
// only enqueue. Events offered before a sink is attached wait in the queue
// and attach delivers them.
//
// The bound counts every event the sink has not consumed: the queued ones
// and the one being delivered. When it is reached, new events are dropped.
// The deliverer takes the next event under the lock and checks closed first,
// so once close returns no new sink call starts; a call already running may
// still be returning. The ring is a fixed array of the configured capacity,
// so queueing and delivering never allocate.
type sandwichQueue struct {
	mu         sync.Mutex
	sink       func(nat.SandwichEvent)
	ring       []nat.SandwichEvent // capacity slots, allocated on first use
	head, n    int                 // first queued event and the number queued
	delivering bool                // an event is out of the ring and in the sink
	closed     bool
}

// offer queues ev and reports whether it was queued and how many sink calls
// panicked while this goroutine was the deliverer.
func (q *sandwichQueue) offer(ev nat.SandwichEvent, capacity int) (queued bool, panics int) {
	q.mu.Lock()
	inSink := 0
	if q.delivering {
		inSink = 1
	}
	if q.closed || q.n+inSink >= capacity {
		q.mu.Unlock()
		return false, 0
	}
	if q.ring == nil {
		q.ring = make([]nat.SandwichEvent, capacity)
	}
	q.ring[(q.head+q.n)%len(q.ring)] = ev
	q.n++
	return true, q.deliverLocked()
}

// attach sets the sink and delivers what is queued, on the caller's
// goroutine, and returns how many sink calls panicked.
func (q *sandwichQueue) attach(sink func(nat.SandwichEvent), capacity int) (panics int) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return 0
	}
	q.sink = sink
	if q.ring == nil {
		q.ring = make([]nat.SandwichEvent, capacity)
	}
	return q.deliverLocked()
}

// deliverLocked is called with mu held and returns with it released. Unless
// another goroutine is delivering, it drains the queue one event at a time,
// calling the sink without the lock.
func (q *sandwichQueue) deliverLocked() (panics int) {
	if q.delivering || q.sink == nil {
		q.mu.Unlock()
		return 0
	}
	q.delivering = true
	for q.n > 0 && !q.closed {
		ev, sink := q.ring[q.head], q.sink
		q.ring[q.head] = nat.SandwichEvent{}
		q.head = (q.head + 1) % len(q.ring)
		q.n--
		q.mu.Unlock()
		if life.Safe("natprobe/sandwich-sink", func() { sink(ev) }) != nil {
			panics++
		}
		q.mu.Lock()
	}
	q.delivering = false
	q.mu.Unlock()
	return panics
}

// close stops delivery: queued events are dropped and later offers refused.
func (q *sandwichQueue) close() {
	q.mu.Lock()
	q.closed, q.sink, q.ring, q.head, q.n = true, nil, nil, 0, 0
	q.mu.Unlock()
}

package nattest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/life"
)

const (
	// closeJoin bounds how long Network.Close waits for the scheduler
	// goroutine.
	closeJoin = time.Second
	// maxBatch bounds the events the scheduler takes per lock acquisition,
	// so that WriteTo on other goroutines is never held up for long.
	maxBatch = 4096
)

// event is something waiting for simulated time: a packet that finished
// crossing a link with a delay, or a chunk of pipe data.
type event struct {
	at  time.Duration // network time
	seq uint64        // tie-breaker: equal times run in push order
	p   *packet
	pc  *pipeChunk
}

// eventHeap is a binary min-heap ordered by (at, seq). It is hand-written
// rather than container/heap to keep events out of interfaces: no allocation
// per push.
type eventHeap []event

func (h *eventHeap) less(i, j int) bool {
	s := *h
	if s[i].at != s[j].at {
		return s[i].at < s[j].at
	}
	return s[i].seq < s[j].seq
}

func (h *eventHeap) push(e event) {
	*h = append(*h, e)
	s := *h
	for i := len(s) - 1; i > 0; {
		p := (i - 1) / 2
		if !s.less(i, p) {
			break
		}
		s[i], s[p] = s[p], s[i]
		i = p
	}
}

func (h *eventHeap) pop() event {
	s := *h
	e := s[0]
	last := len(s) - 1
	s[0] = s[last]
	s[last] = event{}
	s = s[:last]
	for i := 0; ; {
		l := 2*i + 1
		if l >= len(s) {
			break
		}
		m := l
		if r := l + 1; r < len(s) && s.less(r, l) {
			m = r
		}
		if !s.less(m, i) {
			break
		}
		s[i], s[m] = s[m], s[i]
		i = m
	}
	*h = s
	return e
}

// scheduler runs the events of one Network in time order. On a clock other
// than *clock.Fake it is one goroutine, started with life.Group.Go, that
// sleeps on a clock timer until the earliest event is due. On a *clock.Fake
// it starts no goroutine: a single AfterFunc timer, re-armed for the earliest
// event, runs the due events on the goroutine that advances the Fake.
type scheduler struct {
	timer     clock.Timer // manual only, created on first use
	n         *Network
	group     *life.Group   // real time only
	wake      chan struct{} // real time: a new earliest event was pushed
	heap      eventHeap
	seq       uint64
	scheduled atomic.Uint64
	mu        sync.Mutex
	manual    bool
	closed    bool
}

func newScheduler(n *Network) *scheduler {
	s := &scheduler{n: n}
	if _, ok := n.clock.(*clock.Fake); ok {
		s.manual = true
		return s
	}
	s.wake = make(chan struct{}, 1)
	s.group = life.New(context.Background())
	s.group.Go("nattest.scheduler", s.run)
	return s
}

// push queues e and reports false, without queueing, once the scheduler is
// stopped.
func (s *scheduler) push(e event) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	s.seq++
	e.seq = s.seq
	s.heap.push(e)
	head := s.heap[0].seq == e.seq
	if head && s.manual {
		s.armLocked()
	}
	s.mu.Unlock()
	s.scheduled.Add(1)
	if head && !s.manual {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	return true
}

// due moves the due events into batch. It returns how long until the next
// event, or -1 when the heap is empty.
func (s *scheduler) due(batch []event) ([]event, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.n.now()
	for len(s.heap) > 0 && s.heap[0].at <= now && len(batch) < maxBatch {
		batch = append(batch, s.heap.pop())
	}
	if len(batch) == 0 && len(s.heap) > 0 {
		return batch, s.heap[0].at - now
	}
	return batch, -1
}

// run is the scheduler goroutine of the real-time mode.
func (s *scheduler) run(ctx context.Context) {
	timer := s.n.clock.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	batch := make([]event, 0, maxBatch)
	for {
		var wait time.Duration
		batch, wait = s.due(batch[:0])
		if len(batch) > 0 {
			for i := range batch {
				s.n.handle(batch[i])
				batch[i] = event{}
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if wait > 0 {
			timer.Reset(wait)
		}
		select {
		case <-timer.C():
		case <-s.wake:
			timer.Stop()
		case <-ctx.Done():
			return
		}
	}
}

// armLocked points the manual timer at the earliest event; s.mu is held and
// the heap is not empty. The Fake runs the callback on the advancing
// goroutine and never holds its own lock while doing so, so arming under
// s.mu cannot deadlock with fire.
func (s *scheduler) armLocked() {
	d := s.heap[0].at - s.n.now()
	if s.timer == nil {
		s.timer = s.n.clock.AfterFunc(d, s.fire)
		return
	}
	s.timer.Reset(d)
}

// fire is the manual timer's callback: it runs every due event, including
// those that the events themselves make due, then re-arms for the next one.
func (s *scheduler) fire() {
	var batch []event
	for {
		var wait time.Duration
		batch, wait = s.due(batch[:0])
		if len(batch) == 0 {
			if wait > 0 {
				s.mu.Lock()
				if !s.closed && len(s.heap) > 0 {
					s.armLocked()
				}
				s.mu.Unlock()
			}
			return
		}
		for i := range batch {
			s.n.handle(batch[i])
			batch[i] = event{}
		}
	}
}

// stop stops the scheduler, joins its goroutine for at most closeJoin and
// releases the events still queued. It returns how many it dropped and the
// first error: a recovered panic of the goroutine, or a join timeout.
func (s *scheduler) stop() (int, error) {
	s.mu.Lock()
	s.closed = true
	pending := s.heap
	s.heap = nil
	if s.timer != nil {
		s.timer.Stop()
	}
	s.mu.Unlock()

	var err error
	if s.group != nil {
		_ = s.group.Close(closeJoin) // owns no resources: never fails
		var perr *life.PanicError
		switch cause := context.Cause(s.group.Context()); {
		case errors.As(cause, &perr):
			err = perr
		case s.group.Stats().Leaked > 0:
			err = fmt.Errorf("nattest: scheduler goroutine did not stop within %v", closeJoin)
		}
	}
	for _, e := range pending {
		if e.p != nil {
			e.p.release()
		}
	}
	return len(pending), err
}

func (s *scheduler) pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.heap)
}

// handle runs one due event.
func (n *Network) handle(e event) {
	switch {
	case e.p != nil:
		n.process(e.p)
	case e.pc != nil:
		e.pc.pipe.deliver(e.pc)
	}
}

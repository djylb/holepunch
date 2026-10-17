package clock

import "time"

// fakeTimer is a Timer of a Fake. when and index are guarded by f.mu; seq, ch
// and fn never change after creation.
type fakeTimer struct {
	f     *Fake
	seq   uint64
	when  time.Time
	index int            // position in f.timers, -1 when not pending
	ch    chan time.Time // capacity 1; nil for AfterFunc timers

	//holepunch:callback
	fn func() // nil for channel timers
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	return t.f.unscheduleLocked(t)
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	pending := t.f.unscheduleLocked(t)
	t.f.scheduleLocked(t, d)
	return pending
}

// timerHeap orders pending timers by deadline, then by creation.
type timerHeap []*fakeTimer

func (h *timerHeap) Len() int { return len(*h) }

func (h *timerHeap) Less(i, j int) bool {
	s := *h
	if !s[i].when.Equal(s[j].when) {
		return s[i].when.Before(s[j].when)
	}
	return s[i].seq < s[j].seq
}

func (h *timerHeap) Swap(i, j int) {
	s := *h
	s[i], s[j] = s[j], s[i]
	s[i].index = i
	s[j].index = j
}

func (h *timerHeap) Push(x any) {
	t := x.(*fakeTimer)
	t.index = len(*h)
	*h = append(*h, t)
}

func (h *timerHeap) Pop() any {
	old := *h
	n := len(old) - 1
	t := old[n]
	old[n] = nil
	t.index = -1
	*h = old[:n]
	return t
}

package coord

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// bucket is a token bucket on the coordinator's clock. A negative rate is
// unlimited.
type bucket struct {
	tokens float64
	last   time.Time
	rate   float64 // tokens per second
	burst  float64
}

func newBucket(r Rate, now time.Time) bucket {
	return bucket{tokens: float64(r.Burst), last: now, rate: float64(r.PerSec), burst: float64(r.Burst)}
}

func (b *bucket) unlimited() bool { return b.rate < 0 }

func (b *bucket) refill(now time.Time) {
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(b.burst, b.tokens+d.Seconds()*b.rate)
	}
	// A clock that steps back restarts the interval instead of stalling.
	b.last = now
}

// take removes n tokens if available; otherwise it reports how long until
// they would be.
func (b *bucket) take(now time.Time, n float64) (bool, time.Duration) {
	ok, wait := b.check(now, n)
	if ok && !b.unlimited() {
		b.tokens -= n
	}
	return ok, wait
}

// check reports whether n tokens are available, or how long until they
// would be, without taking them.
func (b *bucket) check(now time.Time, n float64) (bool, time.Duration) {
	if b.unlimited() {
		return true, 0
	}
	b.refill(now)
	if b.tokens >= n {
		return true, 0
	}
	if b.rate == 0 {
		return false, time.Hour
	}
	return false, time.Duration((n - b.tokens) / b.rate * float64(time.Second))
}

// level is the number of whole tokens available now (-1: unlimited).
func (b *bucket) level(now time.Time) int {
	if b.unlimited() {
		return -1
	}
	b.refill(now)
	return int(b.tokens)
}

func (b *bucket) full(now time.Time) bool {
	if b.unlimited() {
		return true
	}
	b.refill(now)
	return b.tokens >= b.burst
}

// Key roles of the quota tables.
const (
	keyInitiator = 0
	keyResponder = 1
)

// limiter enforces the session admission limits and the per-key packet
// quotas. One mutex guards it: it is taken a
// few times per session and round, far below the rate at which it would
// contend, and one consistent view of the key table is what bounds it.
//
// The key table holds at most Limits.MaxKeys entries of a fixed size (the
// key is stored as a digest), so its memory is bounded whatever the callers'
// keys. An entry no session holds is idle; the housekeeping drops it after 2
// minutes once its buckets are full, so that "create and close at once"
// cannot reset the new-session rate. A new key in a full table evicts the
// entry idle the longest; when every entry is held, NewSession is refused
// with ErrBusy (dimension "keys").
type limiter struct {
	lim      Limits
	idleKeep time.Duration

	mu      sync.Mutex
	active  int
	pending int
	newRate bucket
	keys    map[limitKey]*keyEntry
	idle    keyList // the entries no session holds, longest idle first
	evicted int64   // idle entries evicted for a new key
	full    int64   // NewSession calls refused: every entry held
}

// limitKey names a key's entry: its role and the first 16 bytes of the
// key's SHA-256, so that an entry's size does not depend on the key.
type limitKey struct {
	role int
	sum  [16]byte
}

func keyOf(role int, key string) limitKey {
	sum := sha256.Sum256([]byte(key))
	return limitKey{role: role, sum: [16]byte(sum[:16])}
}

type keyEntry struct {
	k       limitKey
	active  int
	newRate bucket // initiator keys only
	packets bucket
	extreme bucket
	streak  int // consecutive candidate_timeout results (initiator keys)
	idle    time.Time
	// prev and next link the entry into limiter.idle while active == 0.
	prev, next *keyEntry
}

// keyList is an intrusive list of key entries in the order they became idle.
type keyList struct {
	head, tail *keyEntry
	n          int
}

func (l *keyList) pushBack(e *keyEntry) {
	e.prev, e.next = l.tail, nil
	if l.tail != nil {
		l.tail.next = e
	} else {
		l.head = e
	}
	l.tail = e
	l.n++
}

func (l *keyList) remove(e *keyEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		l.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		l.tail = e.prev
	}
	e.prev, e.next = nil, nil
	l.n--
}

// quota is one session's reservation; it is released exactly once.
type quota struct {
	keys    [2]string
	pending bool
	held    bool
}

// keyIdleKeep is how long an unused, full key entry survives.
const keyIdleKeep = 2 * time.Minute

func newLimiter(lim Limits, now time.Time) *limiter {
	return &limiter{lim: lim, newRate: newBucket(lim.NewSessions, now), idleKeep: keyIdleKeep,
		keys: make(map[limitKey]*keyEntry)}
}

// busyError is the ErrBusy of a refused NewSession.
func busyError(dim string, wait time.Duration) error {
	return fmt.Errorf("%w: %s limit, retry after %v", ErrBusy, dim, wait.Round(time.Millisecond))
}

// reserve admits a new session: per key the initiator concurrency and rate
// and the responder concurrency (both keys are reserved before the
// provider is told), then the global count, pending count and rate. It is
// all or nothing — a refusal takes no rate token either; on refusal it
// returns the refused dimension and an ErrBusy error.
func (l *limiter) reserve(now time.Time, keys [2]string) (q quota, dim string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var held []*keyEntry
	defer func() {
		// Whatever stops the reservation, a refusal or a panic, returns the
		// key holds it took.
		if !q.held {
			for _, e := range held {
				l.releaseLocked(e, now)
			}
		}
	}()
	refuse := func(dim string, wait time.Duration) (quota, string, error) {
		return quota{}, dim, busyError(dim, wait)
	}
	var keyRate *bucket // the initiator key's rate, taken with the global one
	if k := keys[keyInitiator]; k != "" {
		e := l.entryLocked(keyOf(keyInitiator, k), now)
		switch {
		case e == nil:
			return refuse("keys", time.Second)
		case l.lim.MaxPerInitiatorKey >= 0 && e.active >= l.lim.MaxPerInitiatorKey:
			return refuse("initiator_key", time.Second)
		}
		if ok, wait := e.newRate.check(now, 1); !ok {
			return refuse("initiator_key_rate", wait)
		}
		l.holdLocked(e)
		held = append(held, e)
		keyRate = &e.newRate
	}
	if k := keys[keyResponder]; k != "" {
		e := l.entryLocked(keyOf(keyResponder, k), now)
		switch {
		case e == nil:
			return refuse("keys", time.Second)
		case l.lim.MaxPerResponderKey >= 0 && e.active >= l.lim.MaxPerResponderKey:
			return refuse("responder_key", time.Second)
		}
		l.holdLocked(e)
		held = append(held, e)
	}
	switch {
	case l.active >= l.lim.MaxSessions:
		return refuse("sessions", time.Second)
	case l.lim.MaxPending >= 0 && l.pending >= l.lim.MaxPending:
		return refuse("pending", time.Second)
	}
	if ok, wait := l.newRate.take(now, 1); !ok {
		return refuse("rate", wait)
	}
	if keyRate != nil {
		keyRate.take(now, 1) // checked above, under the same lock and instant
	}
	l.active++
	l.pending++
	return quota{keys: keys, pending: true, held: true}, "", nil
}

// entryLocked returns the key's entry, creating it idle with full buckets.
// A full table first evicts the entry idle the longest; when every entry is
// held it returns nil and counts the refusal.
func (l *limiter) entryLocked(k limitKey, now time.Time) *keyEntry {
	if e := l.keys[k]; e != nil {
		return e
	}
	if len(l.keys) >= l.lim.MaxKeys {
		old := l.idle.head
		if old == nil {
			l.full++
			return nil
		}
		l.idle.remove(old)
		delete(l.keys, old.k)
		l.evicted++
	}
	e := &keyEntry{
		k:       k,
		newRate: newBucket(l.lim.InitiatorKeyRate, now),
		packets: allowance(l.lim.PacketsPerMinute[k.role], time.Minute, now),
		extreme: allowance(l.lim.ExtremePerHour, time.Hour, now),
		idle:    now,
	}
	l.keys[k] = e
	l.idle.pushBack(e)
	return e
}

// holdLocked makes a session hold e: a held entry is never evicted.
func (l *limiter) holdLocked(e *keyEntry) {
	if e.active == 0 {
		l.idle.remove(e)
	}
	e.active++
}

// releaseLocked returns a session's hold of e; the last one makes it idle.
func (l *limiter) releaseLocked(e *keyEntry, now time.Time) {
	e.active--
	if e.active == 0 {
		e.idle = now
		l.idle.pushBack(e)
	}
}

// heldLocked returns the entry of a key a live session holds: its
// reservation keeps the entry in the table, so the per-round paths never
// create one.
func (l *limiter) heldLocked(role int, key string) *keyEntry {
	if key == "" {
		return nil
	}
	return l.keys[keyOf(role, key)]
}

// allowance is a bucket of n tokens per period, full at the start; a
// negative n is unlimited.
func allowance(n int, period time.Duration, now time.Time) bucket {
	if n < 0 {
		return bucket{rate: -1}
	}
	return bucket{tokens: float64(n), last: now, rate: float64(n) / period.Seconds(), burst: float64(n)}
}

// leavePending ends q's created/binding phase (the second Attach, or the end
// of the session).
func (l *limiter) leavePending(q *quota) {
	if !q.pending {
		return
	}
	q.pending = false
	l.mu.Lock()
	l.pending--
	l.mu.Unlock()
}

// release returns q's reservations; it is a no-op the second time.
func (l *limiter) release(now time.Time, q *quota) {
	l.leavePending(q)
	if !q.held {
		return
	}
	q.held = false
	l.mu.Lock()
	defer l.mu.Unlock()
	for role, key := range q.keys {
		if e := l.heldLocked(role, key); e != nil {
			l.releaseLocked(e, now)
		}
	}
	l.active--
}

// packetsLeft is how many packets key may still be granted as role (-1:
// unlimited, or no key).
func (l *limiter) packetsLeft(now time.Time, role int, key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.heldLocked(role, key)
	if e == nil {
		return -1
	}
	return e.packets.level(now)
}

// grant charges n granted packets to key: quotas count what was granted,
// not what the client says it sent.
func (l *limiter) grant(now time.Time, role int, key string, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.heldLocked(role, key); e != nil && n > 0 && !e.packets.unlimited() {
		e.packets.refill(now)
		e.packets.tokens = max(e.packets.tokens-float64(n), 0)
	}
}

// takeExtreme consumes one extreme round from both keys, or none when either
// has used its hourly allowance.
func (l *limiter) takeExtreme(now time.Time, keys [2]string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	var es []*keyEntry
	for role, key := range keys {
		if e := l.heldLocked(role, key); e != nil {
			if !e.extreme.unlimited() && e.extreme.level(now) < 1 {
				return false
			}
			es = append(es, e)
		}
	}
	for _, e := range es {
		e.extreme.take(now, 1)
	}
	return true
}

// noteOutcome tracks consecutive candidate_timeout results of an initiator
// key and returns the streak after this result. The session still holds
// the key: its Result is built before its reservation is released.
func (l *limiter) noteOutcome(key string, timeout bool) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.heldLocked(keyInitiator, key)
	switch {
	case e == nil:
		return 0
	case timeout:
		e.streak++
	default:
		e.streak = 0
	}
	return e.streak
}

// sweep drops the entries idle for idleKeep with full buckets and returns
// how many it dropped. The idle list is in idle order, so the walk stops at
// the first entry idle for less.
func (l *limiter) sweep(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for e := l.idle.head; e != nil && now.Sub(e.idle) >= l.idleKeep; {
		next := e.next
		if e.newRate.full(now) && e.packets.full(now) && e.extreme.full(now) {
			l.idle.remove(e)
			delete(l.keys, e.k)
			n++
		}
		e = next
	}
	return n
}

// keyStats returns the key table's size, the entries in use, and its
// eviction and refusal counts (Stats).
func (l *limiter) keyStats() (entries, active, evicted, full int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return int64(len(l.keys)), int64(len(l.keys) - l.idle.n), l.evicted, l.full
}

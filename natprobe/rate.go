package natprobe

import "time"

// Rate is a token bucket: PerSec tokens per second, at most Burst at once.
type Rate struct{ PerSec, Burst int }

// clockBackStep is how far behind a bucket's state an event's time must be
// before gcra takes it for a clock that went backwards. Readers read the
// clock before they take the lock that serializes a bucket, so an event that
// lost the race for the lock carries a slightly older time than the one
// admitted before it; resetting the bucket then would hand out a second
// burst at one instant.
const clockBackStep = int64(time.Second)

// gcra admits one event at monotonic time now (ns) for rate r, using the
// generic cell rate algorithm on the theoretical arrival time *tat: one int64
// per bucket and no refill arithmetic. A slightly stale now is judged against
// the state as it is, which only makes the bucket stricter. Only a state at
// least clockBackStep further ahead than any admitted event could leave it
// means the clock went backwards; the bucket then restarts instead of
// stalling.
func gcra(tat *int64, now int64, r Rate) bool {
	interval := max(int64(time.Second)/int64(r.PerSec), 1)
	tau := int64(r.Burst-1) * interval
	t := max(*tat, now)
	if d := t - now; d > tau {
		if d < tau+interval+clockBackStep {
			return false
		}
		t = now
	}
	*tat = t + interval
	return true
}

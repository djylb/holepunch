package coord

import "time"

// RTT sampling and start alignment.
const (
	rttKeep        = 8                       // valid samples kept per link
	rttJitterN     = 4                       // samples behind the jitter estimate
	rttMaxValid    = 5 * time.Second         // valid samples are in (0, 5 s]
	rttDefault     = 150 * time.Millisecond  // RTT of a link without samples
	jitterCap      = 200 * time.Millisecond  // jitter ceiling
	marginBase     = 20 * time.Millisecond   // margin = clamp(20 ms + 2·jitter, 150)
	marginMax      = 150 * time.Millisecond  //
	startMax       = 2000 * time.Millisecond // D ceiling
	pingEvery      = 300 * time.Millisecond  // pings while waiting for the peer
	pingsPerPhase  = 2                       // per waiting phase and link
	pingsPerLink   = 8                       // in all, ping#1 included
	clockSkewWarn  = 300 * time.Second       // |offset| above this warns clock_skew
	roundTailSlack = 500 * time.Millisecond  // round deadline slack after window + max(rtt)
)

// rttEstimator keeps a link's latest valid samples; the estimate is their
// minimum (queueing and processing only make samples larger).
type rttEstimator struct {
	samples [rttKeep]time.Duration
	n       int // samples ever added
}

// add records a sample and reports whether it was valid.
func (e *rttEstimator) add(d time.Duration) bool {
	if d <= 0 || d > rttMaxValid {
		return false
	}
	e.samples[e.n%rttKeep] = d
	e.n++
	return true
}

// min is the smallest kept sample; ok is false without samples.
func (e *rttEstimator) min() (time.Duration, bool) {
	k := min(e.n, rttKeep)
	if k == 0 {
		return 0, false
	}
	m := e.samples[0]
	for _, d := range e.samples[1:k] {
		m = min(m, d)
	}
	return m, true
}

// jitter is max − min of the latest samples, capped; zero below two samples.
func (e *rttEstimator) jitter() time.Duration {
	k := min(e.n, rttJitterN)
	if k < 2 {
		return 0
	}
	lo, hi := time.Duration(1<<62), time.Duration(0)
	for i := range k {
		d := e.samples[(e.n-1-i)%rttKeep]
		lo, hi = min(lo, d), max(hi, d)
	}
	return min(hi-lo, jitterCap)
}

// alignment is a round's start plan: both go frames leave together, and each
// client waits delay[r] after reading its go, so that both fire about D after
// the write.
type alignment struct {
	rtt   [2]time.Duration
	d     time.Duration
	delay [2]time.Duration
}

// align computes D and the per-role delays from the two links' estimates: o =
// rtt/2, margin = clamp(20 ms + 2·max jitter, 150 ms), D = min(max o +
// margin, 2 s), delay = D − o. A link without samples borrows the other's
// RTT, and 150 ms is used when neither has any. noAlign (ablation NoRTTAlign)
// sends delay 0 to both.
func align(est [2]*rttEstimator, noAlign bool) alignment {
	var a alignment
	var ok [2]bool
	for r := range est {
		a.rtt[r], ok[r] = est[r].min()
	}
	switch {
	case !ok[0] && !ok[1]:
		a.rtt = [2]time.Duration{rttDefault, rttDefault}
	case !ok[0]:
		a.rtt[0] = a.rtt[1]
	case !ok[1]:
		a.rtt[1] = a.rtt[0]
	}
	o := [2]time.Duration{a.rtt[0] / 2, a.rtt[1] / 2}
	margin := min(max(marginBase+2*max(est[0].jitter(), est[1].jitter()), marginBase), marginMax)
	a.d = min(max(o[0], o[1])+margin, startMax)
	if noAlign {
		a.d = max(o[0], o[1])
		return a
	}
	for r := range o {
		a.delay[r] = max(a.d-o[r], 0)
	}
	return a
}

// pingState schedules a link's pings: ping#1 goes with punch_start, then,
// while this side waits for the peer's report or ready, one every 300 ms, at
// most two per waiting phase and eight per link.
type pingState struct {
	due      time.Duration          // next ping, session time; 0: none
	phase    int                    // waiting phase of due
	answered [pingsPerLink + 1]bool // by seq
	inPhase  [2]uint8               // pings sent in the report and ready waiting phases
	sent     uint8                  // pings sent; the last seq
}

// Waiting phases of the ping schedule.
const (
	waitReport = 0
	waitReady  = 1
)

// schedule arms the pings of a waiting phase starting at now.
func (p *pingState) schedule(phase int, now time.Duration) {
	if p.inPhase[phase] >= pingsPerPhase || p.sent >= pingsPerLink {
		return
	}
	p.phase, p.due = phase, now+pingEvery
}

// cancel stops the pings of the current waiting phase.
func (p *pingState) cancel() { p.due = 0 }

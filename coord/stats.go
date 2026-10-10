package coord

import (
	"sync/atomic"

	"github.com/djylb/holepunch/protocol"
)

// Stats is a snapshot of the coordinator's counters.
type Stats struct {
	SessionsActive, SessionsTotal int64
	ByOutcome                     [3]int64                  // succeeded, failed, aborted
	ByCode                        map[protocol.Reason]int64 // failures by reason
	HalfConfirmed                 int64                     // successes with only one confirmation
	RoundsByClass                 [6]int64                  // indexed by RoundClass
	ConfirmAtRound                [9]int64                  // 0: never confirmed; 1..8: the confirming round
	RTTHistogramMs                [8]int64                  // <20, <50, <100, <200, <400, <800, <1600, >=1600
	TimeToConfirm                 [8]int64                  // <0.5, <1, <2, <4, <8, <12, <16, >=16 s
	MemoryEntries, MemoryHits     int64
	AssistForwarded               int64
	AssistDropped                 int64
	AssistRejected                int64
	PeerTargets                   int64
	PingsSent                     int64
	ProgressDropped               int64
	UnknownFrames                 int64
	PlanClamped                   int64
	TargetRejected                int64
	BudgetViolation               int64
	STUNConflicts                 int64 // STUN values that contradicted natprobe's records
	EventsDropped                 int64
	Panics                        int64
	RateLimited                   int64 // refused NewSession calls
	ActiveByKey                   int64 // key entries in use (leak check: 0 when idle)
	KeyEntries                    int64 // key table entries, idle ones included (≤ Limits.MaxKeys)
	KeysEvicted                   int64 // idle key entries evicted for a new key in a full table
	KeyTableFull                  int64 // NewSession calls refused because every key entry was in use
	Stuck                         int64 // sessions or goroutines Close gave up on
}

// counters are the coordinator's atomic counters.
type counters struct {
	sessionsTotal   atomic.Int64
	byOutcome       [3]atomic.Int64
	byCode          [26]atomic.Int64 // in protocol.Reasons() order
	halfConfirmed   atomic.Int64
	roundsByClass   [6]atomic.Int64
	confirmAtRound  [9]atomic.Int64
	rttHist         [8]atomic.Int64
	timeToConfirm   [8]atomic.Int64
	memoryHits      atomic.Int64
	assistForwarded atomic.Int64
	assistDropped   atomic.Int64
	assistRejected  atomic.Int64
	peerTargets     atomic.Int64
	pingsSent       atomic.Int64
	progressDropped atomic.Int64
	unknownFrames   atomic.Int64
	planClamped     atomic.Int64
	targetRejected  atomic.Int64
	budgetViolation atomic.Int64
	stunConflicts   atomic.Int64
	eventsDropped   atomic.Int64
	panics          atomic.Int64
	rateLimited     atomic.Int64
	stuck           atomic.Int64
}

func reasonIndex(r protocol.Reason) int {
	for i, x := range protocol.Reasons() {
		if x == r {
			return i
		}
	}
	return -1
}

func histIndex(v float64, bounds []float64) int {
	for i, b := range bounds {
		if v < b {
			return i
		}
	}
	return len(bounds)
}

// record adds a finished session's Result to the counters.
func (c *counters) record(res *Result) {
	c.sessionsTotal.Add(1)
	if o := int(res.Outcome) - 1; o >= 0 && o < len(c.byOutcome) {
		c.byOutcome[o].Add(1)
	}
	if i := reasonIndex(res.Code); i >= 0 {
		c.byCode[i].Add(1)
	}
	if res.Outcome == OutcomeSucceeded && res.Confirmed[0] != res.Confirmed[1] {
		c.halfConfirmed.Add(1)
	}
	for _, rr := range res.Rounds {
		if int(rr.Class) < len(c.roundsByClass) {
			c.roundsByClass[rr.Class].Add(1)
		}
	}
	confirmRound := 0
	if res.Winner != nil {
		confirmRound = min(res.Winner.Round, len(c.confirmAtRound)-1)
	}
	c.confirmAtRound[confirmRound].Add(1)
	for _, d := range res.RTT {
		if d > 0 {
			c.rttHist[histIndex(float64(d.Milliseconds()), []float64{20, 50, 100, 200, 400, 800, 1600})].Add(1)
		}
	}
	if !res.Timings.FirstConfirm.IsZero() {
		d := res.Timings.FirstConfirm.Sub(res.Timings.Created)
		c.timeToConfirm[histIndex(d.Seconds(), []float64{0.5, 1, 2, 4, 8, 12, 16})].Add(1)
	}
	if res.MemoryHit {
		c.memoryHits.Add(1)
	}
	ct := res.Counters
	c.assistForwarded.Add(int64(ct.AssistForwarded))
	c.assistDropped.Add(int64(ct.AssistDropped))
	c.assistRejected.Add(int64(ct.AssistRejected))
	c.peerTargets.Add(int64(ct.PeerTargets))
	c.pingsSent.Add(int64(ct.PingsSent))
	c.progressDropped.Add(int64(ct.ProgressDropped))
	c.unknownFrames.Add(int64(ct.UnknownFrames))
	c.planClamped.Add(int64(ct.PlanClamped))
	c.targetRejected.Add(int64(ct.TargetRejected))
	c.budgetViolation.Add(int64(ct.BudgetViolation))
	c.stunConflicts.Add(int64(ct.STUNConflicts))
}

// snapshot copies the counters.
func (c *counters) snapshot() Stats {
	s := Stats{
		SessionsTotal:   c.sessionsTotal.Load(),
		ByCode:          map[protocol.Reason]int64{},
		HalfConfirmed:   c.halfConfirmed.Load(),
		MemoryHits:      c.memoryHits.Load(),
		AssistForwarded: c.assistForwarded.Load(),
		AssistDropped:   c.assistDropped.Load(),
		AssistRejected:  c.assistRejected.Load(),
		PeerTargets:     c.peerTargets.Load(),
		PingsSent:       c.pingsSent.Load(),
		ProgressDropped: c.progressDropped.Load(),
		UnknownFrames:   c.unknownFrames.Load(),
		PlanClamped:     c.planClamped.Load(),
		TargetRejected:  c.targetRejected.Load(),
		BudgetViolation: c.budgetViolation.Load(),
		STUNConflicts:   c.stunConflicts.Load(),
		EventsDropped:   c.eventsDropped.Load(),
		Panics:          c.panics.Load(),
		RateLimited:     c.rateLimited.Load(),
		Stuck:           c.stuck.Load(),
	}
	for i := range c.byOutcome {
		s.ByOutcome[i] = c.byOutcome[i].Load()
	}
	for i, r := range protocol.Reasons() {
		if n := c.byCode[i].Load(); n > 0 {
			s.ByCode[r] = n
		}
	}
	for i := range c.roundsByClass {
		s.RoundsByClass[i] = c.roundsByClass[i].Load()
	}
	for i := range c.confirmAtRound {
		s.ConfirmAtRound[i] = c.confirmAtRound[i].Load()
	}
	for i := range c.rttHist {
		s.RTTHistogramMs[i] = c.rttHist[i].Load()
		s.TimeToConfirm[i] = c.timeToConfirm[i].Load()
	}
	return s
}

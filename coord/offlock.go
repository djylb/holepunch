package coord

import (
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	engine "github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/plan"
)

// planTicket names one planning step that runs outside the lock: the
// generation and state it began in, the round it plans (1 for the session
// plan) and whether it plans that round again after its anchor refresh.
type planTicket struct {
	gen     uint64
	state   State
	k       int
	refresh bool
}

// ticketLocked is the ticket of a step beginning now that plans round k.
func (s *Session) ticketLocked(k int, refresh bool) planTicket {
	return planTicket{gen: s.st.plan.gen, state: s.st.state, k: k, refresh: refresh}
}

// validLocked reports whether step t still applies: the session kept its
// generation — no end, confirmation or lost link since — and its state;
// punching, it still plans round t.k, the one after the current round; and
// a refresh step's anchor refresh is still the one ready.
func (s *Session) validLocked(t planTicket) bool {
	st := &s.st
	switch {
	case st.plan.gen != t.gen || st.state != t.state:
		return false
	case t.refresh && (!st.refresh.ready || st.refresh.gen != t.gen || st.refresh.k != t.k):
		return false
	case t.state == StatePunching:
		return st.plan.planning && st.rounds.cur.n+1 == t.k
	}
	return true
}

// void makes every planning step under way stale: the session ended,
// confirmed, or lost a side.
func (ps *planState) void() { ps.gen++ }

// begin asks the session goroutine for a planning step (job is its work
// flag): the planner runs outside the lock until end, and a stage deadline
// meanwhile is the planner's (planner_timeout).
func (ps *planState) begin(job *bool) {
	ps.planning = true
	*job = true
}

// end marks the planning step's result taken.
func (ps *planState) end() { ps.planning = false }

// offLock runs one planning step: take builds its input and ticket under the
// lock (false: nothing to plan), work runs without the lock — natprobe's
// merge, the planner — and apply takes the result under the lock only while
// the ticket is still valid. apply's effects are carried out once the lock
// is released. take gets the session time before it, apply the clock reading
// after work.
func offLock[In, Out any](s *Session, take func(now time.Duration) (planTicket, In, bool),
	work func(In) Out, apply func(t planTicket, in In, out Out, now time.Time) effects) {
	var (
		t  planTicket
		in In
		ok bool
	)
	now := s.since(s.c.set.clock.Now())
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		t, in, ok = take(now)
	}()
	if !ok {
		return
	}
	out := work(in)
	nowT := s.c.set.clock.Now()
	var fx effects
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.validLocked(t) {
			fx = apply(t, in, out, nowT)
		}
	}()
	s.apply(fx)
}

// roundJob is the planner input of one round, taken under the lock.
type roundJob struct {
	p   plan.Planner
	cin plan.ClassifyInput // for a fallback classification
	in  plan.RoundInput
	// keep, when set, is the decision to keep without asking the planner:
	// an anchor refresh that found nothing.
	keep *decision
}

// decideJob is j's decision: the one kept, or the planner's (decide).
func (s *Session) decideJob(j roundJob) decision {
	if j.keep != nil {
		return *j.keep
	}
	return s.decide(j.p, j.cin, j.in)
}

// callPlanner calls the planner p, which coord does not trust, through fn
// behind the planner's fault point. After a panic it calls fallback on the
// default planner, which then plans the rest of the session — unless p is
// the default planner already. A panic of the default planner is not
// reported: it fails the call. It returns the planner that answered, whether
// it is the fallback, and whether any answered.
//
//holepunch:callback
func (s *Session) callPlanner(p plan.Planner, fn func(plan.Planner), fallback func(plan.Planner)) (answered plan.Planner, fellBack, ok bool) {
	if s.callout("coord.plan", fiPlan, func() { fn(p) }) {
		return p, false, true
	}
	if _, isDefault := p.(engine.DefaultPlanner); isDefault {
		return p, false, false
	}
	def := engine.DefaultPlanner{}
	if life.Safe("coord.plan.default", func() { fallback(def) }) != nil {
		return p, false, false
	}
	return def, true, true
}

// callout runs fn, code coord does not own — a planner, a memory, a
// caller's callback or connection — in a recover boundary named where,
// behind the fault point fi (none when empty). An injected fault there is a
// failure of fn: fn does not run and the fault is reported like its panic.
// It returns the recovered panic.
//
//holepunch:callback
func callout(where, fi string, fn func()) error {
	return life.Safe(where, func() {
		if fi != "" {
			if err := faultinject.Point(fi); err != nil {
				panic(err)
			}
		}
		fn()
	})
}

// callout is the package callout for the coordinator's own work: a panic is
// counted and reported as EvInternalError of session sessionID ("" for
// none). It reports whether fn returned.
//
//holepunch:callback
func (c *Coordinator) callout(sessionID, where, fi string, fn func()) bool {
	err := callout(where, fi, fn)
	if err != nil {
		c.noteCallbackPanic(sessionID, err)
	}
	return err == nil
}

// callout is Coordinator.callout for the session's own work.
//
//holepunch:callback
func (s *Session) callout(where, fi string, fn func()) bool {
	return s.c.callout(s.id, where, fi, fn)
}

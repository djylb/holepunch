package holepunch

import (
	"sync"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Phase is a session phase: the value of Error.Phase, Diagnostics.Phase and
// the wire field punch_result.phase. It is defined in package protocol
// because it travels on the wire; the values are
// protocol.PhaseCreated … protocol.PhaseFailed.
type Phase = protocol.Phase

// scopeSession is Transition.Scope for session-level transitions; family
// transitions use the family name ("udp4", "udp6").
const scopeSession = "session"

// maxTimeline bounds Diagnostics.Timeline; the most recent transitions are
// kept, since the end of a session explains how it ended.
const maxTimeline = 64

// phaseRank orders the phases. Phases only move forward (skipping is
// allowed) and the terminal ones never change.
func phaseRank(p Phase) int {
	switch p {
	case protocol.PhaseCreated:
		return 0
	case protocol.PhaseProbing:
		return 1
	case protocol.PhaseReported:
		return 2
	case protocol.PhasePlanned:
		return 3
	case protocol.PhaseReady:
		return 4
	case protocol.PhasePunching:
		return 5
	case protocol.PhaseNegotiating:
		return 6
	case protocol.PhaseConfirmed:
		return 7
	case protocol.PhaseHandover:
		return 8
	case protocol.PhaseDone, protocol.PhaseFailed:
		return 9
	}
	return -1
}

// phaseTracker is the session-level phase aggregation over the per-family
// phases: an event of any family pushes the session forward. It also keeps
// the bounded timeline and the last event. It is safe for concurrent use.
type phaseTracker struct {
	mu       sync.Mutex
	session  Phase
	families map[protocol.Family]Phase
	timeline []Transition
	last     string
}

func newPhaseTracker() *phaseTracker {
	return &phaseTracker{session: protocol.PhaseCreated, families: map[protocol.Family]Phase{}}
}

// current returns the session phase.
func (t *phaseTracker) current() Phase {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.session
}

// lastEvent returns the last recorded event.
func (t *phaseTracker) lastEvent() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.last
}

// advance moves the session forward to `to` and reports whether it moved.
func (t *phaseTracker) advance(to Phase, event string, at time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.moveLocked(scopeSession, &t.session, to, event, at)
}

// advanceFamily moves family f forward to `to` and the session with it.
// Terminal phases are session-only.
func (t *phaseTracker) advanceFamily(f protocol.Family, to Phase, event string, at time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur, ok := t.families[f]
	if !ok {
		cur = protocol.PhaseCreated
	}
	moved := t.moveLocked(string(f), &cur, to, event, at)
	t.families[f] = cur
	if moved {
		t.moveLocked(scopeSession, &t.session, to, event, at)
	}
	return moved
}

// note records an event without a phase change (it still becomes the last
// event).
func (t *phaseTracker) note(event string) {
	t.mu.Lock()
	t.last = event
	t.mu.Unlock()
}

func (t *phaseTracker) moveLocked(scope string, cur *Phase, to Phase, event string, at time.Time) bool {
	t.last = event
	from := *cur
	if phaseRank(from) >= phaseRank(to) || phaseRank(from) == phaseRank(protocol.PhaseDone) {
		return false
	}
	*cur = to
	if len(t.timeline) == maxTimeline {
		copy(t.timeline, t.timeline[1:])
		t.timeline = t.timeline[:maxTimeline-1]
	}
	t.timeline = append(t.timeline, Transition{Scope: scope, From: from, To: to, Event: event, At: at})
	return true
}

// snapshot returns the session phase, the timeline copy and the last event.
func (t *phaseTracker) snapshot() (Phase, []Transition, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.session, append([]Transition(nil), t.timeline...), t.last
}

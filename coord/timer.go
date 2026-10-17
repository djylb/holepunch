package coord

import (
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/protocol"
)

// sendMarkedLocked queues m on link r with an RTT mark. An encoding failure
// is a defect (internal). A send error goes to the effects, examined outside
// the lock: a reliable frame that does not fit the write queue loses the link
// (stalled), any other error means the write side already stopped, which the
// link's Done reports.
func (s *Session) sendMarkedLocked(r int, m protocol.Message, mark *atomic.Int64) effects {
	f, err := msgframe.Encode(m)
	if err != nil {
		return effects{term: &terminal{code: protocol.ReasonInternal, detail: truncate("encode: "+err.Error(), maxDetail)}}
	}
	var fx effects
	fx.sendErr[r] = s.st.links[r].sendMarked(f, mark, s.epoch)
	return fx
}

// sendPingLocked writes the next ping of link r (at most 8 per link).
func (s *Session) sendPingLocked(r int) effects {
	l := s.st.links[r]
	if l.ping.sent >= pingsPerLink {
		return effects{}
	}
	l.ping.sent++
	s.st.ctr.PingsSent++
	seq := l.ping.sent
	return s.sendMarkedLocked(r, protocol.Ping{Seq: seq}, &l.markPing[seq])
}

// cancelPingsLocked ends the pings of a waiting phase on both links.
func (s *Session) cancelPingsLocked(phase int) {
	for _, l := range s.st.links {
		if l != nil && l.ping.phase == phase {
			l.ping.cancel()
		}
	}
}

// rearmLocked points the session's single timer at its nearest event: the
// stage deadline, the lifetime cap, a ping, or pending sandwich events.
func (s *Session) rearmLocked(now time.Duration) {
	st := &s.st
	if st.state == StateClosed {
		return
	}
	next := min(st.deadline, st.expireAt)
	for _, l := range st.links {
		if l != nil && !l.dead && l.ping.due != 0 {
			next = min(next, l.ping.due)
		}
	}
	if len(st.sandBox) > 0 {
		next = now
	}
	if st.refresh.pending {
		next = min(next, st.refresh.until)
	}
	s.timer.Reset(max(next-now, 0))
}

// onTimer is the session timer's callback. It never runs user code: it
// handles what fell due under the lock — sandwich windows, pings, the
// lifetime cap, the stage deadline — and wakes the session goroutine for
// planning. A callback that finds nothing due (it fired early, or the timer
// was pushed back meanwhile) only re-arms. It runs on the clock's goroutine,
// so all of its work, the effects included, is inside its recover boundary.
func (s *Session) onTimer() {
	if !s.acquire() {
		return
	}
	defer s.release()
	s.guard("coord.timer", func() {
		if err := faultinject.Point(fiTimer); err != nil {
			panic(err)
		}
		s.apply(s.timerLocked(s.since(s.c.set.clock.Now())))
	})
}

func (s *Session) timerLocked(now time.Duration) effects {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	var fx effects
	if st.state == StateClosed {
		return fx
	}
	if len(st.sandBox) > 0 {
		s.sandwichLocked(now)
	}
	if st.refresh.pending && now >= st.refresh.until {
		s.refreshDoneLocked(now) // the probes that came are all there is
	}
	for r, l := range st.links {
		if l == nil || l.dead || l.ping.due == 0 || now < l.ping.due {
			continue
		}
		fx.merge(s.sendPingLocked(r))
		l.ping.inPhase[l.ping.phase]++
		l.ping.due = 0
		l.ping.schedule(l.ping.phase, now)
	}
	switch {
	case now >= st.expireAt:
		fx.end(&terminal{code: protocol.ReasonSessionExpired})
	case now >= st.deadline:
		fx.merge(s.deadlineLocked(now))
	}
	s.rearmLocked(now)
	return fx
}

// deadlineLocked is what the stage deadline means in each state.
func (s *Session) deadlineLocked(now time.Duration) effects {
	st := &s.st
	var fx effects
	if st.deferred != nil {
		fx.end(st.deferred)
		return fx
	}
	switch st.state {
	case StateCreated, StateBinding:
		fx.end(&terminal{code: protocol.ReasonPeerOffline, detail: detailJoinTimeout, failed: missing(st.links[0] != nil, st.links[1] != nil)})
	case StateProbing:
		if st.planning {
			fx.end(&terminal{code: protocol.ReasonInternal, detail: detailPlannerTimeout})
			return fx
		}
		fx.end(&terminal{code: protocol.ReasonProbeTimeout, failed: missing(st.reports[0] != nil, st.reports[1] != nil),
			notifyFailed: true})
	case StateSummarized:
		fx.end(&terminal{code: protocol.ReasonNotSynchronized, failed: missing(st.ready[0], st.ready[1]),
			notifyFailed: true})
	case StatePunching:
		switch {
		case now >= st.punchDeadline && st.planning:
			fx.end(&terminal{code: protocol.ReasonInternal, detail: detailPlannerTimeout})
		case st.gone[0] || st.gone[1]:
			g := 0
			if st.gone[1] {
				g = 1
			}
			fx.end(goneTerm(roleOf(g)))
		case now >= st.punchDeadline:
			fx.end(s.stopTermLocked("", ""))
		case !st.cur.evaluating:
			fx.merge(s.endRoundLocked(now))
		}
	case StateConfirming:
		fx.end(&terminal{})
	}
	return fx
}

// missing names the side that has not done its part, "" when neither has.
func missing(done0, done1 bool) protocol.Role {
	switch {
	case done0 && !done1:
		return protocol.RoleResponder
	case done1 && !done0:
		return protocol.RoleInitiator
	}
	return ""
}

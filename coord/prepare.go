package coord

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	engine "github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// prepareRoundLocked turns a planner decision into the two sides' RoundPlans
// without trusting it: the budget class passes the escalation guard,
// the window is clamped, each side is clamped to the class, the session and
// key budgets, the host's capabilities and the protocol limits, and every
// target passes admission. It charges the grants and makes the plan the
// round under way; it fails with no_probe_endpoint when neither side keeps a
// stage that sends.
func (s *Session) prepareRoundLocked(k int, dec plan.RoundDecision, now time.Duration) *terminal {
	st := &s.st
	name := dec.VariantName
	if !isName(name) {
		name = fmt.Sprintf("variant_%d", dec.Variant)
		s.clampedLocked(k, "variant", 0, 0)
	}
	// One rescue round per session, and only right after a one-way round.
	rescue := dec.Rescue && !st.rounds.rescueUsed && !s.ablate.NoRounds && len(st.rounds.prev) > 0 &&
		st.rounds.prev[len(st.rounds.prev)-1].Class == plan.RoundOneWay
	if dec.Rescue && !rescue {
		s.clampedLocked(k, "rescue", 1, 0)
	}
	class := s.guardClassLocked(k, dec.Budget, now)
	lim, _ := class.Limits()

	a := align([2]*rttEstimator{&st.rtt[0], &st.rtt[1]}, s.ablate.NoRTTAlign)
	hi := max(min(s.remainingLocked(now)-a.d, time.Duration(class.MaxWindowMs())*time.Millisecond), minWindow)
	win := clampDur(dec.Window, minWindow, hi)
	if win != dec.Window {
		s.clampedLocked(k, "window_ms", dec.Window.Milliseconds(), win.Milliseconds())
	}
	nonRescue := st.rounds.nonRescue
	if !rescue {
		nonRescue++
	}
	// Final promises that no round follows: not while
	// the session's rescue round may still follow a one-way result.
	noRescueLeft := rescue || st.rounds.rescueUsed || s.ablate.NoRounds
	final := (dec.Final || nonRescue >= int(s.to.MaxRounds)) && noRescueLeft || k >= protocol.MaxRound

	seed := st.rng.Uint32()
	cur := roundState{n: k, variant: dec.Variant, name: name, class: class, rescue: rescue, final: final, window: win,
		families: slices.Clone(dec.Families)}
	usable := false
	var ports [2]int
	for r := range 2 {
		sides, active := s.clampSidesLocked(s.sideClampLocked(k, r, lim, now), dec.Sides[r])
		usable = usable || active
		rp := protocol.RoundPlan{
			Round:    uint8(k),
			Variant:  name,
			Budget:   class,
			WindowMs: uint16(win / time.Millisecond),
			Final:    final,
			Rescue:   rescue,
			Seed:     seed,
			Sides:    sides,
		}
		rp, clamped := rp.Normalize()
		if clamped {
			s.clampedLocked(k, "plan", 0, 0)
		}
		cur.plans[r] = rp
		for _, fs := range rp.Sides {
			cur.sandwich[r][fs.Family.Index()] = fs.Sandwich
			cur.granted[r] += int(fs.MaxPackets)
			ports[r] += int(fs.MaxDistinctPorts)
		}
	}
	if !usable {
		return &terminal{code: protocol.ReasonNoProbeEndpoint}
	}
	for r := range 2 {
		st.audit.granted[r] += cur.granted[r]
		s.c.limiter.grant(s.at(now), r, s.keys[r], cur.granted[r])
	}
	st.rounds.recentPorts[k] = ports
	st.rounds.cur = cur
	st.rounds.lastGranted = class
	if rescue {
		st.rounds.rescueUsed = true
	} else {
		st.rounds.nonRescue++
	}
	return nil
}

// sideClampLocked is what the clamp of side r's round k takes from the
// session besides the admission sets and the audit.
func (s *Session) sideClampLocked(k, r int, lim protocol.ClassLimits, now time.Duration) sideClamp {
	st := &s.st
	return sideClamp{
		k:          k,
		r:          r,
		now:        now,
		lim:        lim,
		families:   st.plan.cls.Families,
		caps:       st.reports[r].Caps,
		sandwich:   st.sand.negotiated && st.sand.echoed[r],
		relayOnly:  protocol.RelayOnly(st.plan.cls.Families, st.adm.pair, st.plan.views),
		budgetLeft: s.budgetLeftLocked(r, now),
	}
}

// guardClassLocked applies the escalation guard: the first round
// is at most min(class of Ladder[0], balanced) unless the memory proved the
// promoted variant (then heavy); later rounds rise at most one class above
// the last grant; heavy needs round 2 and random-EDM evidence, else round 3;
// extreme needs AllowExtreme, round 3 and the keys' hourly allowance.
func (s *Session) guardClassLocked(k int, class protocol.BudgetClass, now time.Duration) protocol.BudgetClass {
	st := &s.st
	in := class
	if !class.Valid() {
		class = protocol.BudgetLight
	}
	var ceiling protocol.BudgetClass
	if st.rounds.lastGranted == "" {
		ceiling = protocol.BudgetLight
		if len(st.plan.cls.Ladder) > 0 {
			if c, ok := engine.VariantClass(st.plan.cls.Ladder[0]); ok && c.Valid() {
				ceiling = c
			}
		}
		ceiling = ceiling.Min(protocol.BudgetBalanced)
		if st.plan.promoted {
			ceiling = protocol.BudgetHeavy
		}
	} else {
		ceiling = protocol.ClassOfRank(st.rounds.lastGranted.Rank() + 1)
	}
	// The slow birthday's class runs only in a Background session
	// of a pair found random — by natprobe, or by a one-way round, after
	// which the planner may turn the pair into PDF×RND; there it
	// escapes the escalation guard, first round included: it is wide in
	// time, not in rate, and the strategy memory may start a Background
	// session with it. Elsewhere the round is held to heavy and to the
	// guard.
	background := class == protocol.BudgetBackground && st.plan.mode == protocol.ModeBackground && (st.plan.pairRND || st.rounds.sawOneWay())
	if class == protocol.BudgetBackground && !background {
		class = protocol.BudgetHeavy
	}
	if class.Rank() > ceiling.Rank() && !background {
		class = ceiling
	}
	if class == protocol.BudgetHeavy && k < 3 && !(k >= 2 && st.plan.pairRND) && !(st.rounds.lastGranted == "" && st.plan.promoted) {
		class = protocol.BudgetBalanced
	}
	if class == protocol.BudgetExtreme &&
		(!s.c.cfg.Budget.AllowExtreme || k < 3 || !s.c.limiter.takeExtreme(s.at(now), s.keys)) {
		class = protocol.BudgetHeavy
	}
	if class != in {
		s.clampedLocked(k, "budget", int64(in.Rank()), int64(class.Rank()))
	}
	return class
}

// clampedLocked counts one plan change and reports it as an event.
func (s *Session) clampedLocked(k int, field string, from, to int64) {
	s.st.ctr.PlanClamped++
	s.c.emit(Event{Kind: EvPlanClamped, SessionID: s.id, Round: k, Labels: s.labels,
		Data: PlanClampedData{Field: field, From: from, To: to}})
}

// admitTargetLocked is admitDirectLocked for one address outside a plan.
func (s *Session) admitTargetLocked(p int, fam protocol.Family, a netip.AddrPort, now time.Duration) bool {
	return s.admitDirectLocked(p, fam, a, s.st.rounds.round, now) != admitRejected
}

// rejectedLocked counts one refused target and reports it as an event.
func (s *Session) rejectedLocked(k int, rule string, a netip.AddrPort, now time.Duration) {
	s.st.ctr.TargetRejected++
	s.c.emit(Event{Kind: EvTargetRejected, At: s.at(now), SessionID: s.id, Round: k, Labels: s.labels,
		Data: TargetRejectedData{Rule: rule, Addr: a}})
}

// sawOneWay reports whether a round of the session carried packets one way
// only.
func (rs *roundsState) sawOneWay() bool {
	return slices.ContainsFunc(rs.records, func(r RoundRecord) bool { return r.Class == plan.RoundOneWay })
}

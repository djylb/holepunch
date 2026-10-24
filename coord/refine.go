package coord

import (
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// refineIn is the input of refining the plan with a warm side's final
// report, taken under the lock.
type refineIn struct {
	r       int
	gen     uint64
	report  protocol.ProbeReport
	views   [2]protocol.PeerView // the merged views the plan stands on
	cin     plan.ClassifyInput
	planner plan.Planner
	memory  StrategyMemory
}

// refineOut is what refining computed outside the lock.
type refineOut struct {
	raw          protocol.PeerView // the final report's merge without the memory: the side's evidence
	contradicted bool              // the final report overturns a family's remembered mapping (overturns)
	views        [2]protocol.PeerView
	cin          plan.ClassifyInput
	cls          plan.Classification
	planner      plan.Planner
	po           planOut // the strategy memory's view of the new classification (recommend)
	classified   bool
}

// refine checks side r's final report against the plan the session made on
// its early report and the remembered traits (WarmHit): the final report's
// own evidence replaces the early one's for the traits memory at the end,
// a port mapping it carries is taken as punch_ready's would be
// (latePortMapLocked: the client reported it here, and punch_ready will
// not), and when it overturns a family's remembered mapping — the memory
// was wrong — the side is WarmContradicted and the rounds from the next
// one on are planned on the final report's traits, classified again.
// Otherwise the plan keeps its traits: the recalled ones stand for what
// the early sample could not show. The endpoints stay the summary's: the
// peer admits no other. Probing ends when the summary arrives, so a final
// report often measured little more than the early one; the check is a
// safety net, not a second probe.
func (s *Session) refine(r int) {
	var in refineIn
	ok := func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		st := &s.st
		if st.state == StateClosed || st.reports[r] == nil || st.plan.warm[r] != WarmHit || !st.plan.planned {
			return false
		}
		in = refineIn{r: r, gen: st.plan.gen, report: *st.reports[r], views: [2]protocol.PeerView{st.plan.views[0].Clone(), st.plan.views[1].Clone()},
			cin: st.plan.cin.Clone(), planner: st.plan.planner, memory: st.plan.memory}
		return true
	}()
	if !ok {
		return
	}
	out := s.refineWork(in)
	now := s.since(s.c.set.clock.Now()) // the Clock is the caller's: never called under the lock
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	if st.state == StateClosed || st.plan.warm[r] != WarmHit {
		return
	}
	if out.raw.Families != nil {
		for _, f := range s.unobserved {
			out.raw = withoutFamily(out.raw, f)
		}
		st.plan.rawViews[r] = out.raw
	}
	switch st.state {
	case StateProbing, StateSummarized, StatePunching:
	default:
		if out.contradicted {
			st.plan.warm[r] = WarmContradicted
		}
		return
	}
	if st.plan.gen == in.gen {
		for _, fr := range in.report.Families {
			if fr.PortMap != nil {
				s.latePortMapLocked(r, fr.Family, *fr.PortMap, now)
			}
		}
	}
	if !out.contradicted {
		return
	}
	st.plan.warm[r] = WarmContradicted
	if st.plan.gen != in.gen {
		return
	}
	adoptTraits(&st.plan.views[r], out.views[r])
	adoptTraits(&st.plan.pviews[r], out.views[r])
	st.plan.cin = out.cin
	if out.classified {
		st.plan.cls, st.plan.planner = out.cls, out.planner
		// The strategy memory keeps the session's key: round 1 ran on it.
		st.plan.order, st.plan.bgOnly = out.po.order, out.po.bgOnly
		st.plan.pairRND = pairRND(st.plan.views, st.plan.cls)
	}
}

// refineWork merges the final report and, when it contradicts the plan,
// classifies the pair again, outside the lock.
func (s *Session) refineWork(in refineIn) refineOut {
	var out refineOut
	mem := s.c.set.traits
	if s.ablate.NoMemory {
		mem = nil
	}
	m, err := s.handle.Merge(roleOf(in.r), in.report, nat.MergeOptions{Memory: mem, ClientKey: s.keys[in.r],
		VerifiedOnly: s.c.cfg.Targets == TargetsVerifiedOnly})
	if err != nil {
		return out
	}
	out.raw = m.Raw
	out.views = in.views
	for _, fv := range m.View.Families {
		old, ok := familyView(in.views[in.r], fv.Family)
		if ok && overturns(old.Traits, fv.Traits) {
			out.contradicted = true
		}
	}
	if !out.contradicted {
		return out
	}
	adoptTraits(&out.views[in.r], m.View)
	out.cin = in.cin
	if in.r == 0 {
		adoptTraits(&out.cin.Initiator, m.View)
	} else {
		adoptTraits(&out.cin.Responder, m.View)
	}
	out.cin.Measured[in.r] = m.Raw.Clone()
	cls, p, ok := s.classify(in.planner, out.cin)
	if !ok || cls.Reject != "" || len(cls.Families) == 0 {
		return out // the plan's classification stands
	}
	out.cls, out.planner, out.classified = cls, p, true
	out.po = planOut{views: out.views, cls: cls, memory: in.memory}
	s.recommend(&out.po)
	return out
}

// overturns reports whether a family's final traits overturn the warm ones
// a plan used: the warm merge planned the side endpoint independent (a
// remembered EIM), and the final report shows a dependent mapping or
// several exits. Finer differences — a filtering or allocation the early
// sample could not show — are what the final report adds, and no
// contradiction.
func overturns(warm, final protocol.Traits) bool {
	dependent := final.Mapping == protocol.MapADM || final.Mapping == protocol.MapAPDM
	return dependent && final.Mapping != warm.Mapping || final.MultiExit && !warm.MultiExit
}

// adoptTraits replaces the traits of every family of v that from merged
// too, keeping v's endpoints.
func adoptTraits(v *protocol.PeerView, from protocol.PeerView) {
	for i := range v.Families {
		if fv, ok := familyView(from, v.Families[i].Family); ok {
			v.Families[i].Traits = fv.Traits
		}
	}
}

package coord

import (
	"encoding/base64"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/netaddr"
	engine "github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/internal/trunc"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// planIn is the planning input taken under the lock.
type planIn struct {
	unobserved []protocol.Family // Session.unobserved
	reports    [2]protocol.ProbeReport
	echoed     [2]bool
	planner    plan.Planner
	memory     StrategyMemory
}

// planOut is what the planning computed outside the lock.
type planOut struct {
	views, pviews, raw [2]protocol.PeerView
	pair               protocol.PairFacts
	cls                plan.Classification
	cin                plan.ClassifyInput
	planner            plan.Planner
	memory             StrategyMemory
	mode               string
	key                StrategyKey
	hasKey             bool
	order              []plan.VariantID
	memHit, promoted   bool
	bgOnly             bool                 // engine.BackgroundOnly by the memory's scores
	sessionMode        protocol.SessionMode // background when offered and both reports accept it
	stunConflicts      int                  // STUN values contradicting natprobe (MergeDiag)
	term               *terminal
}

// planSession runs on the session goroutine when both reports are in: it
// merges each report with natprobe's records (cookie verification), lets the
// Planner classify the pair and plan round 1 — all outside the lock — and
// then, if nothing changed meanwhile, writes both summaries.
func (s *Session) planSession() {
	var (
		t      planTicket
		round1 bool
	)
	offLock(s, s.planInputLocked, s.plan, func(tk planTicket, _ planIn, out planOut, now time.Time) effects {
		var fx effects
		fx, round1 = s.takePlanLocked(out, s.since(now))
		t = tk
		return fx
	})
	if !round1 {
		return
	}
	// The sink went on with the plan's effects, before round 1 is planned:
	// its anchor refresh hands the probes over through it.
	offLock(s, func(time.Duration) (planTicket, roundJob, bool) {
		if !s.validLocked(t) {
			return t, roundJob{}, false
		}
		st := &s.st
		return t, roundJob{p: st.plan.planner, cin: st.plan.cin, in: s.roundInputLocked(1, st.updated)}, true
	}, s.decideJob, func(t planTicket, j roundJob, d decision, now time.Time) effects {
		fx := s.applyRound1Locked(d, now)
		if t.state = StateSummarized; s.validLocked(t) {
			// Round 1's anchor refresh runs while the summaries travel and
			// the readies come back; the go waits for it.
			s.beginRefreshLocked(t, d, j.cin, j.in, s.since(now))
		}
		return fx
	})
}

// planInputLocked takes the session plan's input once both reports are in.
func (s *Session) planInputLocked(time.Duration) (planTicket, planIn, bool) {
	st := &s.st
	if st.state != StateProbing || st.reports[0] == nil || st.reports[1] == nil || st.plan.planned {
		return planTicket{}, planIn{}, false
	}
	return s.ticketLocked(1, false), planIn{
		reports:    [2]protocol.ProbeReport{*st.reports[0], *st.reports[1]},
		echoed:     st.sand.echoed,
		planner:    st.plan.planner,
		memory:     st.plan.memory,
		unobserved: s.unobserved,
	}, true
}

// plan computes the session plan outside the lock.
func (s *Session) plan(in planIn) planOut {
	out := planOut{planner: in.planner, memory: in.memory}
	if !s.mergeViews(in, &out) {
		return out
	}
	out.pair = s.pairFacts(in, &out)
	// The session keeps the input for a fallback classification outside the
	// lock, so it shares nothing with what it is made of: the planner views
	// change in place, the views and pair facts become the admission sets
	// (admission.index), and raw still feeds the traits memory at the end.
	// classify hands the planner a copy of its own.
	cin := plan.ClassifyInput{
		Initiator: out.pviews[0],
		Responder: out.pviews[1],
		// natprobe's own measurements, without the traits memory: the only
		// evidence the early verdict trusts.
		Measured: out.raw,
		Pair:     out.pair,
		Policy:   *s.starts[0].Policy,
		Timeouts: s.to,
		Mode:     sessionMode(s.offer, in.reports),
	}.Clone()
	out.sessionMode = cin.Mode
	if in.echoed[0] && in.echoed[1] {
		cin.Features = []protocol.Feature{protocol.FeatureSandwich}
	}
	out.cin = cin
	var ok bool
	if out.cls, out.planner, ok = s.classify(out.planner, cin); !ok {
		out.term = &terminal{code: protocol.ReasonInternal, detail: "panic:planner"}
		return out
	}
	if out.cls.Reject == "" && len(out.cls.Families) == 0 {
		out.cls.Reject = protocol.ReasonNoCommonFamily
	}
	if !out.cls.Advice.Valid() {
		// The summary's plan carries it: an unknown advice would fail its
		// encoding.
		out.cls.Advice = ""
	}
	if out.cls.Reject != "" {
		out.term = plannerEnd(out.cls.Reject, "")
		return out
	}
	mode, ok := pickTransport(in.reports[0].Transport.Mode, in.reports[1].Transport.Mode, s.c.cfg.TransportFallback)
	if !ok {
		out.term = &terminal{code: protocol.ReasonTransportMismatch}
		return out
	}
	out.mode = mode
	s.recommend(&out)
	return out
}

// mergeViews builds both sides' views: natprobe's authoritative merge (only
// endpoints whose cookie was echoed are verified), or in NoObserver mode
// the clients' own reports, whose global endpoints the planner may aim at. The
// planner sees the views as sent.
func (s *Session) mergeViews(in planIn, out *planOut) bool {
	if s.handle == nil {
		for r := range in.reports {
			out.views[r] = selfView(in.reports[r])
			out.pviews[r] = out.views[r].Clone()
		}
		return true
	}
	mem := s.c.set.traits
	if s.ablate.NoMemory {
		mem = nil
	}
	verifiedOnly := s.c.cfg.Targets == TargetsVerifiedOnly
	for r := range in.reports {
		m, err := s.handle.Merge(roleOf(r), in.reports[r], mem, s.keys[r], verifiedOnly)
		if err != nil {
			out.term = &terminal{code: protocol.ReasonInternal, detail: trunc.String("merge: "+err.Error(), protocol.MaxDetail)}
			return false
		}
		// The memory's own conclusions must not renew it: the traits fed
		// back at the end come from this session's evidence only (Raw).
		out.views[r], out.raw[r] = m.View, m.Raw
		out.stunConflicts += m.Diag.STUNConflicts
		out.pviews[r] = out.views[r].Clone()
	}
	// A family no observer covers has nothing verified: it runs on the
	// clients' own reports in the restricted mode, or not at all. It never
	// feeds the traits memory.
	for _, f := range in.unobserved {
		for r := range in.reports {
			out.views[r] = withoutFamily(out.views[r], f)
			out.pviews[r] = withoutFamily(out.pviews[r], f)
			out.raw[r] = withoutFamily(out.raw[r], f)
			if s.c.cfg.Targets == TargetsVerifiedOnly {
				continue
			}
			for _, fr := range in.reports[r].Families {
				if fr.Family == f {
					fv := nat.SelfReportedView(fr)
					out.views[r].Families = append(out.views[r].Families, fv)
					out.pviews[r].Families = append(out.pviews[r].Families, fv.Clone())
					break
				}
			}
		}
	}
	return true
}

// selfView is a client's view built from its own report (NoObserver mode):
// every family's nat.SelfReportedView.
func selfView(rep protocol.ProbeReport) protocol.PeerView {
	var v protocol.PeerView
	for _, fr := range rep.Families {
		v.Families = append(v.Families, nat.SelfReportedView(fr))
	}
	return v
}

// withoutFamily is v without family f.
func withoutFamily(v protocol.PeerView, f protocol.Family) protocol.PeerView {
	v.Families = slices.DeleteFunc(slices.Clone(v.Families), func(fv protocol.FamilyView) bool { return fv.Family == f })
	return v
}

// pairFacts computes what only a server seeing both clients knows. A shared
// family is unverified in NoObserver mode (every family) or when no
// observer covers it; the pair is on one LAN when it shares the public
// IP and the LAN prefixes intersect, and shares an overlay when both
// sides reported overlay addresses: the server cannot tell whether
// two tunnels reach each other, and trying costs two packets a target.
func (s *Session) pairFacts(in planIn, out *planOut) protocol.PairFacts {
	var p protocol.PairFacts
	for _, f := range [2]protocol.Family{protocol.FamilyUDP6, protocol.FamilyUDP4} {
		a, okA := familyView(out.views[0], f)
		b, okB := familyView(out.views[1], f)
		if !okA || !okB {
			continue
		}
		p.SharedFamilies = append(p.SharedFamilies, f)
		if s.handle == nil || slices.Contains(in.unobserved, f) {
			if p.Unverified == nil {
				p.Unverified = map[protocol.Family]bool{}
			}
			p.Unverified[f] = true
		}
		if hasOverlay(a) && hasOverlay(b) {
			if p.SharedOverlay == nil {
				p.SharedOverlay = map[protocol.Family]bool{}
			}
			p.SharedOverlay[f] = true
		}
		if a.Traits.PublicIP.IsValid() && a.Traits.PublicIP == b.Traits.PublicIP {
			if p.SamePublicIP == nil {
				p.SamePublicIP = map[protocol.Family]bool{}
			}
			p.SamePublicIP[f] = true
			if sameLAN(a, b) {
				if p.LikelySameLAN == nil {
					p.LikelySameLAN = map[protocol.Family]bool{}
				}
				p.LikelySameLAN[f] = true
			}
		}
		// Two sides the server saw at private addresses reach it without
		// NAT; their PublicIP are their own LAN addresses, so sharing a
		// LAN prefix is what puts them on one LAN.
		if a.Traits.LANObserved && b.Traits.LANObserved && sameLAN(a, b) {
			if p.LikelySameLAN == nil {
				p.LikelySameLAN = map[protocol.Family]bool{}
			}
			p.LikelySameLAN[f] = true
		}
		// Elsewhere a LAN-observed side has no verified public address: it
		// is reached at the global addresses it reported itself, in the
		// unverified mode, unless the server allows verified targets only.
		if s.c.cfg.Targets != TargetsVerifiedOnly && !p.LikelySameLAN[f] && (selfReportedOnly(a) || selfReportedOnly(b)) {
			if p.Unverified == nil {
				p.Unverified = map[protocol.Family]bool{}
			}
			p.Unverified[f] = true
		}
	}
	for r, rep := range in.reports {
		if rep.Clock.RTTMs > 0 {
			if p.ProbeRTTMs == nil {
				p.ProbeRTTMs = map[protocol.Role]uint32{}
			}
			p.ProbeRTTMs[roleOf(r)] = rep.Clock.RTTMs
		}
	}
	s.mu.Lock()
	offsets, known := s.st.offset, [2]bool{s.st.offsetRTT[0] != 0, s.st.offsetRTT[1] != 0}
	s.mu.Unlock()
	for r := range offsets {
		if known[r] {
			if p.ClockOffsetMs == nil {
				p.ClockOffsetMs = map[protocol.Role]int64{}
			}
			p.ClockOffsetMs[roleOf(r)] = offsets[r].Milliseconds()
		}
	}
	return p
}

// lanObserved reports whether the server saw a side only at private
// addresses in some family (Traits.LANObserved).
func lanObserved(views [2]protocol.PeerView) bool {
	for _, v := range views {
		if slices.ContainsFunc(v.Families, func(fv protocol.FamilyView) bool { return fv.Traits.LANObserved }) {
			return true
		}
	}
	return false
}

func familyView(v protocol.PeerView, f protocol.Family) (protocol.FamilyView, bool) {
	for _, fv := range v.Families {
		if fv.Family == f {
			return fv, true
		}
	}
	return protocol.FamilyView{}, false
}

// selfReportedOnly reports whether a LAN-observed view carries a global
// address the side reported itself (a STUN answer, a port mapping), which
// natprobe admits as its reported fallback.
func selfReportedOnly(v protocol.FamilyView) bool {
	return v.Traits.LANObserved && slices.ContainsFunc(v.Endpoints, func(e protocol.Endpoint) bool {
		return !e.Verified && (e.Source == protocol.EndpointSTUN || e.Source == protocol.EndpointPortmap) &&
			netaddr.Public(e.Addr.Addr())
	})
}

// hasOverlay reports whether a view carries an overlay endpoint.
func hasOverlay(v protocol.FamilyView) bool {
	return slices.ContainsFunc(v.Endpoints, func(e protocol.Endpoint) bool { return e.Source == protocol.EndpointOverlay })
}

// sameLAN reports whether the two views have LAN endpoints in one /24 (IPv4)
// or /64 (IPv6): the LAN prefixes intersect.
func sameLAN(a, b protocol.FamilyView) bool {
	for _, x := range a.Endpoints {
		if x.Source != protocol.EndpointLAN {
			continue
		}
		bits := 24
		if x.Addr.Addr().Is6() {
			bits = 64
		}
		px, _ := x.Addr.Addr().Prefix(bits)
		for _, y := range b.Endpoints {
			if y.Source == protocol.EndpointLAN && px.Contains(y.Addr.Addr()) {
				return true
			}
		}
	}
	return false
}

// classify runs the planner's Classify; after a panic it falls back to the
// default planner, which then plans the rest of the session. The planner
// gets a copy: in is the session's own, kept for a later fallback.
func (s *Session) classify(p plan.Planner, in plan.ClassifyInput) (plan.Classification, plan.Planner, bool) {
	var cls plan.Classification
	p, _, ok := s.callPlanner(p, func(p plan.Planner) { cls = p.Classify(in.Clone()) }, func(def plan.Planner) { cls = def.Classify(in) })
	return cls, p, ok
}

// plannerEnd is the end a planner asked for; a planner that names no known
// reason is defective (internal).
func plannerEnd(code protocol.Reason, detail string) *terminal {
	if !code.Known() {
		return &terminal{code: protocol.ReasonInternal, detail: trunc.String("planner reason "+string(code), protocol.MaxDetail)}
	}
	// The detail goes out in punch_abort, whose encoding refuses a longer one.
	return &terminal{code: code, detail: trunc.String(detail, protocol.MaxDetail)}
}

// pickTransport settles the upper-layer transport: equal modes, or the
// one mode given; conflicting modes take the fallback, or fail.
func pickTransport(a, b, fallback string) (string, bool) {
	var mode string
	switch {
	case a == b:
		mode = a
	case a == "":
		mode = b
	case b == "":
		mode = a
	default:
		if fallback == "" {
			return "", false
		}
		mode = fallback
	}
	if mode == "" {
		mode = fallback
	}
	return mode, true
}

// recommend asks the strategy memory for the ladder order and what it knows
// of the variants (StrategyMemory). Only a variant the memory proved for
// this pair (a positive score) may lift the first round's budget cap
// (escalation guard).
func (s *Session) recommend(out *planOut) {
	cls := out.cls
	out.order = slices.Clone(cls.Ladder)
	if out.memory == nil || len(cls.Ladder) == 0 || len(cls.Families) == 0 {
		return
	}
	var sides [2]StrategySide
	a, ok := roleIndex(cls.SideA)
	if !ok {
		return
	}
	for i, r := range [2]int{a, 1 - a} {
		fv, ok := familyView(out.views[r], cls.Families[0])
		if !ok || !fv.Traits.PublicIP.IsValid() {
			return
		}
		bits := 32
		if fv.Traits.PublicIP.Is6() {
			bits = 64
		}
		pfx, _ := fv.Traits.PublicIP.Prefix(bits)
		sides[i] = StrategySide{IPPrefix: pfx, ClassBits: nat.ClassBits(fv.Traits)}
	}
	out.key, out.hasKey = DeriveStrategyKey(s.c.salt, sides[0], sides[1]), true
	var (
		order  []plan.VariantID
		first  int
		bgOnly bool
		valid  bool
	)
	if !s.callout("coord.memory", fiMemory, func() {
		// A copy: the memory may sort what it is given, and the ladder
		// stays the classification's.
		order = out.memory.Recommend(out.key, slices.Clone(cls.Ladder))
		if valid = samePermutation(order, cls.Ladder); valid {
			first = out.memory.Score(out.key, order[0])
			bgOnly = engine.BackgroundOnly(func(v plan.VariantID) int { return out.memory.Score(out.key, v) })
		}
	}) {
		out.memory = nil
		return
	}
	if !valid {
		return
	}
	out.order = order
	out.memHit = first > 0
	out.promoted = first > 0 && order[0] != cls.Ladder[0]
	out.bgOnly = bgOnly
}

func samePermutation(a, b []plan.VariantID) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// takePlanLocked stores the planning result; it reports whether round 1 is to be planned. A rejected pair or a
// transport conflict ends the session here, right after the second
// report.
func (s *Session) takePlanLocked(out planOut, now time.Duration) (effects, bool) {
	st := &s.st
	var fx effects
	st.updated = now
	st.plan.planned = true
	st.plan.views, st.plan.pviews, st.plan.rawViews = out.views, out.pviews, out.raw
	st.adm.pair, st.plan.cls, st.plan.cin, st.plan.planner, st.plan.memory = out.pair, out.cls, out.cin, out.planner, out.memory
	st.plan.transport = out.mode
	st.plan.memKey, st.plan.hasKey, st.plan.order = out.key, out.hasKey, out.order
	st.plan.memHit, st.plan.promoted, st.plan.bgOnly, st.plan.mode = out.memHit, out.promoted, out.bgOnly, out.sessionMode
	st.ctr.STUNConflicts = uint64(out.stunConflicts)
	st.adm.index(st.plan.pviews)
	if len(st.adm.pair.Unverified) > 0 {
		st.addWarn(protocol.WarnUnverifiedTargets)
	}
	if lanObserved(st.plan.views) {
		st.addWarn(protocol.WarnLANObserved)
	}
	if out.term == nil {
		st.sand.negotiated = s.handle != nil && st.sand.echoed[0] && st.sand.echoed[1]
		st.plan.pairRND = pairRND(st.plan.views, st.plan.cls)
		// natprobe hands over the anchor refresh's probes from now on, the
		// sandwich's once punching.
		fx.sink = s.handle != nil
		return fx, true
	}
	st.plan.end()
	s.c.emit(Event{Kind: EvPlanned, At: s.at(now), SessionID: s.id, Labels: s.labels,
		Data: PlannedData{PairClass: out.cls.PairClass, Rejected: out.term.code}})
	s.planEndLocked(&fx, out.term, now)
	return fx, false
}

// planEndLocked ends the session with a decision taken while planning — a
// rejection, a stop, no round left to run. The NoEarlyAbort ablation keeps
// every such end but internal for the stage deadline, and no
// further round starts meanwhile.
func (s *Session) planEndLocked(fx *effects, term *terminal, now time.Duration) {
	st := &s.st
	if !s.ablate.NoEarlyAbort || term.code == protocol.ReasonInternal {
		fx.end(term)
		return
	}
	st.deferred = term
	if st.state == StatePunching {
		st.deadline = st.rounds.punchDeadline
	}
	s.rearmLocked(now)
}

// applyRound1Locked clamps round 1, writes both summaries and moves to
// summarized.
func (s *Session) applyRound1Locked(d decision, nowT time.Time) effects {
	st := &s.st
	var fx effects
	st.plan.end()
	now := s.since(nowT)
	st.updated = now
	if !s.takeDecisionLocked(d) {
		fx.end(&terminal{code: protocol.ReasonInternal, detail: "panic:planner"})
		return fx
	}
	if d.dec.Stop != "" {
		s.planEndLocked(&fx, s.stopTermLocked(d.dec.Stop, d.dec.StopDetail), now)
		return fx
	}
	if term := s.prepareRoundLocked(1, d.dec, now); term != nil {
		s.planEndLocked(&fx, term, now)
		return fx
	}
	var planID [6]byte
	for i := range planID {
		planID[i] = byte(st.rng.Uint32())
	}
	pid := base64.RawURLEncoding.EncodeToString(planID[:])
	pairClass := st.plan.cls.PairClass
	if !isName(pairClass) {
		pairClass = ""
	}
	for r, l := range st.links {
		sum := protocol.ProbeSummary{
			SessionID: s.id,
			Self:      st.plan.views[r],
			Peer:      s.peerViewLocked(1 - r),
			Pair:      st.adm.pair,
			Transport: protocol.TransportPick{Mode: st.plan.transport, PeerData: st.reports[1-r].Transport.Data},
			Timeouts:  s.starts[r].Timeouts,
			Plan: protocol.PlanSpec{
				ID:             pid,
				PairClass:      pairClass,
				RoundsMax:      s.to.MaxRounds,
				Budget:         s.budget,
				Round1:         st.rounds.cur.plans[r],
				Mode:           st.plan.mode,
				Advice:         st.plan.cls.Advice,
				BackgroundOnly: st.plan.bgOnly,
			},
		}
		if fx.merge(s.sendMarkedLocked(r, sum, &l.markSummary)); fx.term != nil {
			return fx
		}
	}
	st.state = StateSummarized
	st.summaryAt, st.summarized = now, true
	st.deadline = now + s.ttl.ready
	if s.handle != nil {
		// The registration must outlive the punch: natprobe keeps watching
		// the primary sockets for moved mappings and, when negotiated,
		// takes the sandwich probes; the first confirmation closes it. An
		// expired entry is gone, Extend cannot revive it: renew it now,
		// while it is alive, to the latest possible punch deadline + 1 s.
		fx.sink = st.sand.negotiated
		fx.extend = s.ttl.ready + ms(s.to.HandshakeTimeoutMs) + s.ttl.punchSlack + time.Second
	}
	s.rearmLocked(now)
	s.c.emit(Event{Kind: EvPlanned, At: nowT, SessionID: s.id, Labels: s.labels, Data: PlannedData{
		PairClass: st.plan.cls.PairClass, Variant: st.rounds.cur.name, Budget: st.rounds.cur.class, MemoryHit: st.plan.memHit,
		Transport: st.plan.transport,
	}})
	return fx
}

// peerViewLocked is side p's view as its peer receives it: its private
// addresses only where the peer may aim at them — LAN endpoints
// for a peer on the same LAN, port-mapping addresses (upstream-LAN
// candidates) for a peer behind the same public IP — and its overlay
// addresses only for a peer that has some too.
func (s *Session) peerViewLocked(p int) protocol.PeerView {
	st := &s.st
	v := st.plan.views[p].Clone()
	for i := range v.Families {
		fv := &v.Families[i]
		fv.Endpoints = slices.DeleteFunc(fv.Endpoints, func(e protocol.Endpoint) bool {
			if e.Source == protocol.EndpointOverlay {
				return !st.adm.pair.SharedOverlay[fv.Family]
			}
			if !netaddr.Private(e.Addr.Addr()) {
				return false
			}
			switch e.Source {
			case protocol.EndpointLAN:
				return !st.adm.pair.LikelySameLAN[fv.Family]
			case protocol.EndpointPortmap:
				return !st.adm.pair.SamePublicIP[fv.Family]
			}
			return false
		})
	}
	return v
}

// prependPlannerEndpointLocked puts an admitted endpoint of side r first in
// the planner's view of its family, where it supersedes the endpoints after
// it: the planner aims Direct and spray stages at the first verified IP and
// takes one server endpoint on it. A full view loses its last
// endpoint.
func (s *Session) prependPlannerEndpointLocked(r int, fam protocol.Family, e protocol.Endpoint) {
	v := &s.st.plan.pviews[r]
	for i := range v.Families {
		fv := &v.Families[i]
		if fv.Family != fam {
			continue
		}
		rest := slices.DeleteFunc(fv.Endpoints, func(x protocol.Endpoint) bool { return x.Addr == e.Addr })
		fv.Endpoints = append([]protocol.Endpoint{e}, rest[:min(len(rest), protocol.MaxEndpoints-1)]...)
	}
}

// addPlannerEndpointLocked adds an admitted endpoint of side r to the
// planner's view, so that later rounds aim at it.
func (s *Session) addPlannerEndpointLocked(r int, fam protocol.Family, e protocol.Endpoint) {
	v := &s.st.plan.pviews[r]
	for i := range v.Families {
		fv := &v.Families[i]
		if fv.Family != fam || len(fv.Endpoints) >= protocol.MaxEndpoints {
			continue
		}
		for _, x := range fv.Endpoints {
			if x.Addr == e.Addr {
				return
			}
		}
		fv.Endpoints = append(fv.Endpoints, e)
	}
}

// pairRND reports whether either side of the primary family is RND (random
// endpoint-dependent mapping) — in the views, or as the planner classified
// it: a side a STUN server contradicted is planned as random.
// Random-EDM evidence lets heavy start in round 2.
func pairRND(views [2]protocol.PeerView, cls plan.Classification) bool {
	if len(cls.Families) == 0 {
		return false
	}
	switch cls.PairClass {
	case engine.PairPDFRnd, engine.PairSeqRnd, engine.PairRndRnd:
		return true
	}
	for _, v := range views {
		if fv, ok := familyView(v, cls.Families[0]); ok && engine.CategoryOf(fv.Traits) == engine.CatRND {
			return true
		}
	}
	return false
}

// isName reports whether s has the wire name syntax [a-z][a-z0-9_]{0,63}.
func isName(s string) bool {
	if len(s) < 1 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// minWindow is the shortest round window; the longest is the round
// class's (protocol.BudgetClass.MaxWindowMs: 10 s, 45 s for the slow
// birthday).
const minWindow = 700 * time.Millisecond

// sessionMode is the mode a session runs in:
// background when the caller offered it and both clients accepted it in
// their probe_report, interactive ("") otherwise.
func sessionMode(offer protocol.SessionMode, reports [2]protocol.ProbeReport) protocol.SessionMode {
	if offer == protocol.ModeBackground && reports[0].Mode == protocol.ModeBackground && reports[1].Mode == protocol.ModeBackground {
		return protocol.ModeBackground
	}
	return ""
}

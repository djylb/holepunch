package coord

import (
	"encoding/base64"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

// planIn is the planning input taken under the lock.
type planIn struct {
	gen     uint64
	reports [2]protocol.ProbeReport
	echoed  [2]bool
	planner Planner
	memory  StrategyMemory
}

// planOut is what the planning computed outside the lock.
type planOut struct {
	views, pviews, raw [2]protocol.PeerView
	pair               protocol.PairFacts
	cls                Classification
	cin                ClassifyInput
	planner            Planner
	memory             StrategyMemory
	mode               string
	key                StrategyKey
	hasKey             bool
	order              []VariantID
	memHit, promoted   bool
	bgOnly             bool                 // plan.BackgroundOnly by the built-in memory
	sessionMode        protocol.SessionMode // background when offered and both reports accept it
	stunConflicts      int                  // STUN values contradicting natprobe (MergeDiag)
	term               *terminal
}

// planSession runs on the session goroutine when both reports are in: it
// merges each report with natprobe's records (cookie verification), lets the
// Planner classify the pair and plan round 1 — all outside the lock — and
// then, if nothing changed meanwhile, writes both summaries.
func (s *Session) planSession() {
	in, ok := s.planInput()
	if !ok {
		return
	}
	out := s.plan(in)
	var (
		fx  effects
		rin RoundInput
		cin ClassifyInput
		p   Planner
		go1 bool
	)
	planned := s.since(s.c.set.clock.Now())
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		fx, go1 = s.takePlanLocked(in.gen, out, planned)
		if go1 {
			rin = s.roundInputLocked(1, s.st.updated)
			cin, p = s.st.cin, s.st.planner
		}
	}()
	// The sink goes on before round 1 is planned: its anchor refresh hands
	// the probes over through it.
	s.apply(fx)
	if !go1 {
		return
	}
	d := s.decide(p, cin, rin)
	now := s.c.set.clock.Now()
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		fx = s.applyRound1Locked(in.gen, d, now)
		if s.st.gen == in.gen && s.st.state == StateSummarized {
			// Round 1's anchor refresh runs while the summaries travel and
			// the readies come back; the go waits for it.
			s.beginRefreshLocked(1, in.gen, d, p, cin, rin, s.since(now))
		}
	}()
	s.apply(fx)
}

func (s *Session) planInput() (planIn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	if st.state != StateProbing || st.reports[0] == nil || st.reports[1] == nil || st.planned {
		return planIn{}, false
	}
	return planIn{
		gen:     st.gen,
		reports: [2]protocol.ProbeReport{*st.reports[0], *st.reports[1]},
		echoed:  st.echoed,
		planner: st.planner,
		memory:  st.memory,
	}, true
}

// plan computes the session plan outside the lock.
func (s *Session) plan(in planIn) planOut {
	out := planOut{planner: in.planner, memory: in.memory}
	if !s.mergeViews(in, &out) {
		return out
	}
	out.pair = s.pairFacts(in, &out)
	cin := ClassifyInput{
		Initiator: out.pviews[0],
		Responder: out.pviews[1],
		// natprobe's own measurements, without the traits memory: the only
		// evidence the early verdict trusts.
		// Cloned, as the views are: a custom Planner may write its input,
		// and raw still feeds the traits memory at the end.
		Measured: [2]protocol.PeerView{clonePeerView(out.raw[0]), clonePeerView(out.raw[1])},
		Pair:     out.pair,
		Policy:   *s.starts[0].Policy,
		Timeouts: s.to,
		Mode:     sessionMode(s.offer, in.reports),
	}
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
// endpoints whose cookie was echoed are verified), or in relay-only mode
// the clients' own reports, whose global endpoints the planner may aim at. The
// planner sees the views as sent.
func (s *Session) mergeViews(in planIn, out *planOut) bool {
	if s.handle == nil {
		for r := range in.reports {
			out.views[r] = selfView(in.reports[r])
			out.pviews[r] = clonePeerView(out.views[r])
		}
		return true
	}
	mem := s.c.set.traits
	if s.ablate.NoMemory {
		mem = nil
	}
	for r := range in.reports {
		key := natprobe.TraitsKey{ClientKey: s.keys[r]}
		var (
			err  error
			diag natprobe.MergeDiag
		)
		if perr := life.Safe("coord.merge", func() {
			out.views[r], diag, err = s.handle.Merge(roleOf(r), in.reports[r], mem, key)
			if err == nil && mem != nil {
				// The memory's own conclusions must not renew it:
				// the traits fed back at the end come from this
				// session's evidence only.
				out.raw[r], _, err = s.handle.Merge(roleOf(r), in.reports[r], nil, key)
			}
		}); perr != nil {
			out.term = &terminal{code: protocol.ReasonInternal, detail: detailMergePanic}
			return false
		}
		if err != nil {
			out.term = &terminal{code: protocol.ReasonInternal, detail: truncate("merge: "+err.Error(), maxDetail)}
			return false
		}
		if mem == nil {
			out.raw[r] = out.views[r]
		}
		out.stunConflicts += diag.STUNConflicts
		out.pviews[r] = clonePeerView(out.views[r])
	}
	// A family no observer covers has nothing verified: it runs on the
	// clients' own reports in the restricted mode, or not at all. It never
	// feeds the traits memory.
	for _, f := range s.unobserved {
		for r := range in.reports {
			out.views[r] = withoutFamily(out.views[r], f)
			out.pviews[r] = withoutFamily(out.pviews[r], f)
			out.raw[r] = withoutFamily(out.raw[r], f)
			if s.c.cfg.DisableUnverifiedFamilies {
				continue
			}
			for _, fr := range in.reports[r].Families {
				if fr.Family == f {
					fv := selfFamilyView(fr)
					out.views[r].Families = append(out.views[r].Families, fv)
					out.pviews[r].Families = append(out.pviews[r].Families, cloneFamilyView(fv))
					break
				}
			}
		}
	}
	return true
}

// selfView is a client's view built from its own report (relay-only mode):
// every family's selfFamilyView.
func selfView(rep protocol.ProbeReport) protocol.PeerView {
	var v protocol.PeerView
	for _, fr := range rep.Families {
		v.Families = append(v.Families, selfFamilyView(fr))
	}
	return v
}

// selfFamilyView is a family view built from the client's own report, for a
// family the server cannot verify: its provisional traits and the
// addresses it reports — the observed values of its probe rows, STUN rows
// and its port mapping, then as LAN endpoints at most four local addresses
// (those of the primary and sibling sockets, and the host's global addresses
// at the primary socket's port: a host without NAT is reached there), then
// its overlay addresses at that port — none of them verified.
func selfFamilyView(fr protocol.FamilyReport) protocol.FamilyView {
	fv := protocol.FamilyView{Family: fr.Family, Traits: fr.Traits}
	fv.Traits.Family = fr.Family
	// PortAnchorMs is on the server's axis, which a client cannot know; the
	// punch-time mappings re-anchor the prediction instead.
	fv.Traits.PortAnchorMs = 0
	seen := map[netip.AddrPort]bool{}
	add := func(a netip.AddrPort, src protocol.EndpointSource, sock uint8) bool {
		if len(fv.Endpoints) >= maxViewEndpoints || seen[a] || !usableAddr(a, fr.Family) || a.Addr().IsLoopback() {
			return false
		}
		seen[a] = true
		fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Addr: a, Source: src, Socket: sock})
		return true
	}
	var primary *protocol.SocketReport
	for i, sk := range fr.Sockets {
		src := protocol.EndpointServer
		switch sk.Kind {
		case protocol.SocketPrimary:
			if primary == nil {
				primary = &fr.Sockets[i]
			}
		case protocol.SocketSecond:
			src = protocol.EndpointSecond
		case protocol.SocketSibling:
			src = protocol.EndpointSibling
		}
		for _, row := range sk.Rows {
			add(row.Observed, src, sk.ID)
		}
	}
	for _, row := range fr.STUN {
		add(row.Observed, protocol.EndpointSTUN, 0)
	}
	if fr.PortMap != nil {
		add(fr.PortMap.External, protocol.EndpointPortmap, 0)
	}
	lan := 0
	for _, sk := range fr.Sockets {
		if lan < maxLANTargets && (sk.Kind == protocol.SocketPrimary || sk.Kind == protocol.SocketSibling) &&
			add(sk.Local, protocol.EndpointLAN, sk.ID) {
			lan++
		}
	}
	if primary != nil {
		for _, ip := range fr.LocalAddrs {
			if lan < maxLANTargets && nat.ScopeOf(ip) == nat.ScopeGlobal &&
				add(netip.AddrPortFrom(ip, primary.Local.Port()), protocol.EndpointLAN, primary.ID) {
				lan++
			}
		}
		for i, ip := range fr.Overlay {
			if i < maxOverlay {
				add(netip.AddrPortFrom(ip, primary.Local.Port()), protocol.EndpointOverlay, primary.ID)
			}
		}
	}
	if fv.Traits.Samples == 0 && len(fv.Endpoints) > 0 {
		fv.Traits.Samples = 1
	}
	return fv
}

// maxViewEndpoints bounds a family view (protocol: 12).
const maxViewEndpoints = 12

// withoutFamily is v without family f.
func withoutFamily(v protocol.PeerView, f protocol.Family) protocol.PeerView {
	v.Families = slices.DeleteFunc(slices.Clone(v.Families), func(fv protocol.FamilyView) bool { return fv.Family == f })
	return v
}

func clonePeerView(v protocol.PeerView) protocol.PeerView {
	v.Families = slices.Clone(v.Families)
	for i := range v.Families {
		v.Families[i] = cloneFamilyView(v.Families[i])
	}
	return v
}

func cloneFamilyView(fv protocol.FamilyView) protocol.FamilyView {
	fv.Endpoints = slices.Clone(fv.Endpoints)
	return fv
}

// pairFacts computes what only a server seeing both clients knows. A shared
// family is unverified in relay-only mode (every family) or when no
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
		if s.handle == nil || slices.Contains(s.unobserved, f) {
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

func familyView(v protocol.PeerView, f protocol.Family) (protocol.FamilyView, bool) {
	for _, fv := range v.Families {
		if fv.Family == f {
			return fv, true
		}
	}
	return protocol.FamilyView{}, false
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
// default planner, which then plans the rest of the session.
func (s *Session) classify(p Planner, in ClassifyInput) (Classification, Planner, bool) {
	var cls Classification
	err := life.Safe("coord.plan", func() {
		if err := faultinject.Point(fiPlan); err != nil {
			panic(err)
		}
		cls = p.Classify(in)
	})
	if err == nil {
		return cls, p, true
	}
	s.c.noteCallbackPanic(s.id, err)
	if _, isDefault := p.(plan.DefaultPlanner); isDefault {
		return cls, p, false
	}
	def := plan.DefaultPlanner{}
	if life.Safe("coord.plan.default", func() { cls = def.Classify(in) }) != nil {
		return cls, def, false
	}
	return cls, def, true
}

// plannerEnd is the end a planner asked for; a planner that names no known
// reason is defective (internal).
func plannerEnd(code protocol.Reason, detail string) *terminal {
	if !code.Known() {
		return &terminal{code: protocol.ReasonInternal, detail: truncate("planner reason "+string(code), maxDetail)}
	}
	return &terminal{code: code, detail: detail}
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

// recommend asks the strategy memory for the ladder order. Only a
// variant the built-in memory proved for this pair (score >= +1) may lift
// the first round's budget cap (escalation guard).
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
	var order []VariantID
	if err := life.Safe("coord.memory", func() {
		if err := faultinject.Point(fiMemory); err != nil {
			panic(err)
		}
		order = out.memory.Recommend(out.key, cls.Ladder)
	}); err != nil {
		s.c.noteCallbackPanic(s.id, err)
		out.memory = nil
		return
	}
	if !samePermutation(order, cls.Ladder) {
		return
	}
	out.order = order
	if m, ok := out.memory.(*memory); ok {
		sc := m.score(out.key, order[0])
		out.memHit = sc > 0
		out.promoted = sc >= 1 && order[0] != cls.Ladder[0]
		out.bgOnly = plan.BackgroundOnly(func(v VariantID) int8 { return m.score(out.key, v) })
	} else {
		out.memHit = order[0] != cls.Ladder[0]
	}
}

func samePermutation(a, b []VariantID) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// takePlanLocked stores the planning result if the session did not move on;
// it reports whether round 1 is to be planned. A rejected pair or a
// transport conflict ends the session here, right after the second
// report.
func (s *Session) takePlanLocked(gen uint64, out planOut, now time.Duration) (effects, bool) {
	st := &s.st
	var fx effects
	if st.gen != gen || st.state != StateProbing {
		return fx, false
	}
	st.updated = now
	st.planned = true
	st.views, st.pviews, st.rawViews = out.views, out.pviews, out.raw
	st.pair, st.cls, st.cin, st.planner, st.memory = out.pair, out.cls, out.cin, out.planner, out.memory
	st.transport = out.mode
	st.memKey, st.hasKey, st.order = out.key, out.hasKey, out.order
	st.memHit, st.promoted, st.bgOnly, st.mode = out.memHit, out.promoted, out.bgOnly, out.sessionMode
	st.ctr.STUNConflicts = uint64(out.stunConflicts)
	s.indexViewsLocked()
	if len(st.pair.Unverified) > 0 {
		st.addWarn(protocol.WarnUnverifiedTargets)
	}
	if out.term == nil {
		st.sandwich = s.handle != nil && st.echoed[0] && st.echoed[1]
		st.pairRND = pairRND(st.views, st.cls)
		// natprobe hands over the anchor refresh's probes from now on, the
		// sandwich's once punching.
		fx.sink = s.handle != nil
		return fx, true
	}
	st.planning = false
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
		st.deadline = st.punchDeadline
	}
	s.rearmLocked(now)
}

// applyRound1Locked clamps round 1, writes both summaries and moves to
// summarized.
func (s *Session) applyRound1Locked(gen uint64, d decision, nowT time.Time) effects {
	st := &s.st
	var fx effects
	if st.gen != gen || st.state != StateProbing {
		return fx
	}
	st.planning = false
	now := s.since(nowT)
	st.updated = now
	if !s.takeDecisionLocked(d) {
		fx.end(&terminal{code: protocol.ReasonInternal, detail: "panic:planner"})
		return fx
	}
	if d.dec.Stop != "" {
		s.planEndLocked(&fx, s.stopTermLocked(d.dec.Stop), now)
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
	pairClass := st.cls.PairClass
	if !isName(pairClass) {
		pairClass = ""
	}
	for r, l := range st.links {
		sum := protocol.ProbeSummary{
			SessionID: s.id,
			Self:      st.views[r],
			Peer:      s.peerViewLocked(1 - r),
			Pair:      st.pair,
			Transport: protocol.TransportPick{Mode: st.transport, PeerData: st.reports[1-r].Transport.Data},
			Timeouts:  s.starts[r].Timeouts,
			Plan: protocol.PlanSpec{
				ID:             pid,
				PairClass:      pairClass,
				RoundsMax:      s.to.MaxRounds,
				Budget:         s.budget,
				Round1:         st.cur.plans[r],
				Mode:           st.mode,
				Advice:         st.cls.Advice,
				BackgroundOnly: st.bgOnly,
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
		fx.sink = st.sandwich
		fx.extend = s.ttl.ready + ms(s.to.HandshakeTimeoutMs) + s.ttl.punchSlack + time.Second
	}
	s.rearmLocked(now)
	s.c.emit(Event{Kind: EvPlanned, At: nowT, SessionID: s.id, Labels: s.labels, Data: PlannedData{
		PairClass: st.cls.PairClass, Variant: st.cur.name, Budget: st.cur.class, MemoryHit: st.memHit,
		Transport: st.transport,
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
	v := clonePeerView(st.views[p])
	for i := range v.Families {
		fv := &v.Families[i]
		fv.Endpoints = slices.DeleteFunc(fv.Endpoints, func(e protocol.Endpoint) bool {
			if e.Source == protocol.EndpointOverlay {
				return !st.pair.SharedOverlay[fv.Family]
			}
			if !isLAN(e.Addr.Addr()) {
				return false
			}
			switch e.Source {
			case protocol.EndpointLAN:
				return !st.pair.LikelySameLAN[fv.Family]
			case protocol.EndpointPortmap:
				return !st.pair.SamePublicIP[fv.Family]
			}
			return false
		})
	}
	return v
}

// indexViewsLocked builds the admission sets of both sides, the same sets
// the clients build from their summaries: the
// verified IPs per family — in an unverified family the first four
// distinct global unicast IPs the side reported — the overlay
// addresses a peer with an overlay may aim at, the private LAN
// addresses a peer on the same LAN may aim at, and the private port-mapping
// addresses (upstream-LAN candidates) a peer behind the same public IP may
// aim at.
func (s *Session) indexViewsLocked() {
	st := &s.st
	for r := range st.views {
		st.verified[r] = map[protocol.Family][]netip.Addr{}
		st.lan[r] = map[protocol.Family][]netip.Addr{}
		st.overlay[r] = map[protocol.Family][]netip.Addr{}
		st.upstream[r] = map[protocol.Family][]netip.AddrPort{}
		for _, fv := range st.pviews[r].Families {
			unverified, reported := st.pair.Unverified[fv.Family], 0
			for _, e := range fv.Endpoints {
				ip := e.Addr.Addr()
				switch {
				case e.Source == protocol.EndpointOverlay:
					if len(st.overlay[r][fv.Family]) < maxOverlay && !slices.Contains(st.overlay[r][fv.Family], ip) {
						st.overlay[r][fv.Family] = append(st.overlay[r][fv.Family], ip)
					}
				case e.Verified:
					if !slices.Contains(st.verified[r][fv.Family], ip) {
						st.verified[r][fv.Family] = append(st.verified[r][fv.Family], ip)
					}
				case unverified && ip.IsGlobalUnicast() && !isLAN(ip):
					if reported < reportedIPs && !slices.Contains(st.verified[r][fv.Family], ip) {
						st.verified[r][fv.Family] = append(st.verified[r][fv.Family], ip)
						reported++
					}
				case !isLAN(ip):
				case e.Source == protocol.EndpointLAN:
					if len(st.lan[r][fv.Family]) < maxLANTargets && !slices.Contains(st.lan[r][fv.Family], ip) {
						st.lan[r][fv.Family] = append(st.lan[r][fv.Family], ip)
					}
				case e.Source == protocol.EndpointPortmap:
					st.addUpstream(r, fv.Family, e.Addr)
				}
			}
		}
	}
}

// addUpstream records a private port-mapping address of side r: an
// upstream-LAN candidate.
func (st *sessionState) addUpstream(r int, fam protocol.Family, a netip.AddrPort) {
	if st.upstream[r] == nil {
		st.upstream[r] = map[protocol.Family][]netip.AddrPort{}
	}
	if list := st.upstream[r][fam]; len(list) < maxLANTargets && !slices.Contains(list, a) {
		st.upstream[r][fam] = append(list, a)
	}
}

// prependPlannerEndpointLocked puts an admitted endpoint of side r first in
// the planner's view of its family, where it supersedes the endpoints after
// it: the planner aims Direct and spray stages at the first verified IP and
// takes one server endpoint on it. A full view loses its last
// endpoint.
func (s *Session) prependPlannerEndpointLocked(r int, fam protocol.Family, e protocol.Endpoint) {
	v := &s.st.pviews[r]
	for i := range v.Families {
		fv := &v.Families[i]
		if fv.Family != fam {
			continue
		}
		rest := slices.DeleteFunc(fv.Endpoints, func(x protocol.Endpoint) bool { return x.Addr == e.Addr })
		fv.Endpoints = append([]protocol.Endpoint{e}, rest[:min(len(rest), maxViewEndpoints-1)]...)
	}
}

// addPlannerEndpointLocked adds an admitted endpoint of side r to the
// planner's view, so that later rounds aim at it.
func (s *Session) addPlannerEndpointLocked(r int, fam protocol.Family, e protocol.Endpoint) {
	v := &s.st.pviews[r]
	for i := range v.Families {
		fv := &v.Families[i]
		if fv.Family != fam || len(fv.Endpoints) >= maxViewEndpoints {
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
func pairRND(views [2]protocol.PeerView, cls Classification) bool {
	if len(cls.Families) == 0 {
		return false
	}
	switch cls.PairClass {
	case plan.PairPDFRnd, plan.PairSeqRnd, plan.PairRndRnd:
		return true
	}
	for _, v := range views {
		if fv, ok := familyView(v, cls.Families[0]); ok && plan.CategoryOf(fv.Traits) == plan.CatRND {
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

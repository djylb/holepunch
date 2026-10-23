package plan

import (
	"slices"
	"time"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// familyPlan is the per-family classification. Each shared family runs its own
// ladder; for a dual-stack session the families can be in
// different pair classes.
type familyPlan struct {
	Family    protocol.Family
	PairClass string
	SideA     protocol.Role // which role is the ladder's A side for this family
	// TierCap caps the session's BirthdayTier for this family: conservative
	// for a v6 family behind NAT66, "" for no cap.
	TierCap protocol.BirthdayTier
	Ladder  []api.VariantID
	// MaxTargets bounds the Direct targets of a side and round: 8 in a
	// verified family; in an unverified one 4, or 16 when every
	// shared family is unverified (the NoObserver mode).
	MaxTargets int
	// From is where the family's ladder starts in RoundInput.Prev: the
	// rounds before it ran on the ladder an escalation left.
	From int
	// EDM marks, by role, a side planned as endpoint dependent although
	// natprobe found its mapping endpoint independent (asEDM): a STUN
	// server contradicted the mapping, or two rounds without any
	// contact did not bear it out.
	EDM    [2]bool
	CatA   Category // category of the A side
	CatB   Category // category of the B side
	OpensA bool     // the A side's traits admit a birthday round
	OpensB bool     // the B side's traits admit a birthday round
	// Unverified: the server could not verify the family's endpoints
	// (pair.unverified). Its rounds are Direct only (directOnly),
	// to the peer's self-reported global unicast addresses, at most
	// MaxTargets of them per side and round.
	Unverified bool
	// SameLAN: the peers share a LAN (pair.same_lan). Each side then
	// aims a Direct stage of its own at the peer's LAN endpoints (lanStage).
	SameLAN bool
	// SharedOverlay: both peers reported overlay addresses
	// (pair.shared_overlay); the same stage aims at the peer's.
	SharedOverlay bool
	// CheapOnly: natprobe measured a seq_x_rnd pair that no rung after the
	// two cheap ones can open (SeqRndVerdict). Once they ran without
	// contact the family's ladder ends.
	CheapOnly bool
	// OneWay: two one-way rounds made the family a PDF×RND pair whose
	// random (B) side is the one that heard; its traits are planned
	// as random (asRandom).
	OneWay bool
	// Restart: the family runs the first round of the ladder an escalation
	// switched to, which carries the plain-punching baseline like a
	// session's first round.
	Restart bool
}

// DefaultPlanner is the stateless strategy the coordinator uses by default. It
// carries no state; every input is explicit.
type DefaultPlanner struct{}

// minWindow is the shortest round window; a round opens only when
// Remaining leaves it plus D.
const minWindow = 700 * time.Millisecond

// Classify maps the merged views to per-family ladders. It rejects with
// hard_symmetric_random, before a single punch, only when natprobe measured
// every shared family hopeless (summaryVerdict); the classification is
// otherwise a hint the rounds correct.
func (DefaultPlanner) Classify(in api.ClassifyInput) api.Classification {
	fams := familyPlans([2]protocol.PeerView{in.Initiator, in.Responder}, in.Measured, in.Pair, in.Policy, in.Mode)
	if len(fams) == 0 {
		return api.Classification{Reject: protocol.ReasonNoCommonFamily}
	}
	primary := fams[0]
	cl := api.Classification{PairClass: primary.PairClass, SideA: primary.SideA, Ladder: slices.Clone(primary.Ladder)}
	for _, fp := range fams {
		cl.Families = append(cl.Families, fp.Family)
	}
	if summaryVerdict(in, fams) {
		cl.Reject = protocol.ReasonHardSymmetricRandom // no punch at all
	}
	cl.Advice = adviceFor(primary, cl.Reject, in.Policy)
	return cl
}

// familyPlans is the classification of every family the two views share,
// in priority order. Classify reports it, and Round derives it again from
// its input: the classification carries nothing a round could not
// recompute, so a Classification of any origin plans the same rounds.
func familyPlans(views [2]protocol.PeerView, measured [2]protocol.PeerView, pair protocol.PairFacts, pol protocol.Policy,
	mode protocol.SessionMode) []familyPlan {
	shared := sharedFamilies(views[0], views[1])
	relayOnly := protocol.RelayOnly(shared, pair, views)
	background := mode == protocol.ModeBackground
	fams := make([]familyPlan, 0, len(shared))
	for _, fam := range shared {
		tr := [2]protocol.Traits{familyTraits(views[0], fam), familyTraits(views[1], fam)}
		var edm [2]bool
		for r := range tr {
			// A STUN server saw another mapping than natprobe: the
			// mapping depends on the path, and the EIM conclusion is
			// planned as endpoint dependent from the start.
			edm[r] = !pair.Unverified[fam] && tr[r].PathDependent && eimDoubt(tr[r])
		}
		fp := planFamily(fam, tr, edm, pair, pol, background, relayOnly)
		fp.CheapOnly = fp.PairClass == PairSeqRnd && SeqRndVerdict(measured, fam)
		fams = append(fams, fp)
	}
	return fams
}

// input is a round's planner input with the per-family plans of the
// families its classification runs, in Class.Families order (newInput).
type input struct {
	api.RoundInput
	fams []familyPlan
}

// newInput derives the per-family plans of in: those of the shared families
// in.Class.Families names, each once, in its order.
func newInput(in api.RoundInput) input {
	all := familyPlans(in.Views, in.Measured, in.Pair, in.Policy, in.Mode)
	fams := make([]familyPlan, 0, len(in.Class.Families))
	for _, f := range in.Class.Families {
		i := slices.IndexFunc(all, func(fp familyPlan) bool { return fp.Family == f })
		if i >= 0 && !slices.ContainsFunc(fams, func(fp familyPlan) bool { return fp.Family == f }) {
			fams = append(fams, all[i])
		}
	}
	return input{RoundInput: in, fams: fams}
}

// planFamily is the classification of one shared family from both sides'
// traits by role, the sides in edm planned as endpoint dependent (asEDM).
// background is a Background session's: a pdf_x_rnd family then runs the
// slow birthday.
func planFamily(fam protocol.Family, tr [2]protocol.Traits, edm [2]bool, pair protocol.PairFacts, pol protocol.Policy,
	background, relayOnly bool) familyPlan {
	for r := range tr {
		if edm[r] {
			tr[r] = asEDM(tr[r])
		}
	}
	iTr, rTr := tr[0], tr[1]
	catI, catR := CategoryOf(iTr), CategoryOf(rTr)
	pairClass := freshPairClass(PairClass(catI, catR), iTr, rTr)
	bothNoNAT := iTr.NoNAT == protocol.TriTrue && rTr.NoNAT == protocol.TriTrue
	if fam == protocol.FamilyUDP6 && catI == CatOpen && catR == CatOpen && bothNoNAT {
		pairClass = PairV6Direct
	}
	var tierCap protocol.BirthdayTier
	if fam == protocol.FamilyUDP6 && !bothNoNAT {
		tierCap = protocol.BirthdayConservative // NAT66 runs the v4 ladder, birthday at most conservative
	}

	sideA := canonicalSideA(catI, catR, iTr, rTr)
	catA, catB := catI, catR
	opensA, opensB := opensBirthday(iTr), opensBirthday(rTr)
	if sideA == protocol.RoleResponder {
		catA, catB = catR, catI
		opensA, opensB = opensBirthday(rTr), opensBirthday(iTr)
	}
	fp := familyPlan{
		Family: fam, PairClass: pairClass, SideA: sideA,
		CatA: catA, CatB: catB, Ladder: ladderFor(pairClass),
		OpensA: opensA, OpensB: opensB, TierCap: tierCap,
		Unverified: pair.Unverified[fam], MaxTargets: maxDirectTargets,
		SameLAN:       pair.LikelySameLAN[fam],
		SharedOverlay: pair.SharedOverlay[fam],
		EDM:           edm,
	}
	if slowViable(fp, pol) && background {
		fp.Ladder = backgroundLadder()
	}
	switch {
	case fp.Unverified && relayOnly:
		fp.MaxTargets = protocol.MaxRelayOnlyTargets
	case fp.Unverified:
		fp.MaxTargets = protocol.MaxUnverifiedTargets
	}
	return fp
}

// Round decides the next round. It owns round advancement — each family on its
// own ladder — the rescue round, the stop rules, the escalation guard, the
// BirthdayTier gate, the dual-stack shared-budget split and the invariant
// "granted = emittable", which here means that every side's MaxPackets equals
// the packets its stages expand to.
func (DefaultPlanner) Round(r api.RoundInput) api.RoundDecision {
	in := newInput(r)
	order := in.Order
	if len(order) == 0 {
		order = in.Class.Ladder
	}
	if len(order) == 0 || len(in.fams) == 0 {
		return api.RoundDecision{Stop: protocol.ReasonNoProbeEndpoint}
	}
	// An unconfirmed end without contact is hard_symmetric_random when both
	// sides of the primary family are RND, or when natprobe measured it as
	// one only the cheap rounds can open and they ran. The
	// measurement decides, not a run-time correction.
	primary := in.fams[0]
	hopeless := primary.CatA == CatRND && primary.CatB == CatRND || primary.CheapOnly && countNonRescue(in.Prev) >= CheapRounds
	if escalated := escalate(&in); escalated[0] {
		order = in.fams[0].Ladder
	}

	// Coordinator-level stop rules the planner also enforces (invariants).
	// Remaining is punchDeadline - now; D is the coordinator's margin (the
	// planner uses the coordinator's D and does not re-estimate or re-deduct).
	if in.Remaining < minWindow+in.D {
		return api.RoundDecision{Stop: TerminalReason(in.Evidence, hopeless)}
	}
	if sideBudgetTooLow(in.BudgetLeft[0]) || sideBudgetTooLow(in.BudgetLeft[1]) {
		return api.RoundDecision{Stop: protocol.ReasonPacketBudgetExceeded}
	}

	// Rescue round: one per session, not counted against max_rounds;
	// none where the next birthday round is the remedy.
	if last, ok := lastOutcome(in.Prev); ok && last.Class == api.RoundOneWay && !in.RescueUsed && !birthdayFollows(in, last) {
		return buildRescue(in, last)
	}

	picks, bindBlocked := pickFamilies(in, order)
	lead := -1
	for i := range picks {
		if picks[i].running() {
			lead = i
			break
		}
	}
	if lead < 0 {
		if bindBlocked {
			return api.RoundDecision{Stop: protocol.ReasonLocalPortBindFailed}
		}
		return stopBeforeContact(in, hopeless)
	}

	// budget_hit with no candidate and a not-lower next round -> stop.
	if (in.Evidence.BudgetHit[0] || in.Evidence.BudgetHit[1]) && !hasCandidate(in.Evidence) {
		if prev, ok := lastNonRescue(in.Prev); ok && nominalPackets(picks) >= prevNominalPackets(in, prev) {
			return api.RoundDecision{Stop: protocol.ReasonPacketBudgetExceeded}
		}
	}

	roundClass := assignClasses(in, picks)
	sides, win := buildSides(in, picks, roundClass)
	if !initiates(sides) {
		// Every stage was dropped (a blocked path and no Direct target).
		return stopBeforeContact(in, hopeless)
	}

	dec := api.RoundDecision{
		Variant:     picks[lead].vr.id,
		VariantName: picks[lead].vr.name,
		Budget:      roundClass,
		Window:      win,
		Final:       isFinal(in, picks),
		Sides:       sides,
	}
	for i := range picks {
		dec.Families = append(dec.Families, api.FamilyRound{Family: in.fams[i].Family, Variant: picks[i].vr.id, Budget: picks[i].class,
			Center: [2]uint16{predictCenter(sides[0][i]), predictCenter(sides[1][i])}})
	}
	applySandwich(&dec, in, picks)
	return dec
}

// predictCenter is the port a side's predict stage centres on, its anchor
// plus its first step, or 0 without one (FamilyRound.Center).
func predictCenter(fs protocol.FamilySide) uint16 {
	for _, st := range fs.Stages {
		if st.Kind != protocol.StagePredict || st.Anchor == 0 {
			continue
		}
		step := 1
		if len(st.Steps) > 0 && st.Steps[0] != 0 {
			step = int(st.Steps[0])
		}
		return wrapPort(int(st.Anchor) + step)
	}
	return 0
}

// ---- per-family ladder selection ----

// familyPick is one family's choice for the round.
type familyPick struct {
	ladder []api.VariantID
	idx    int     // the chosen index, or -1 when the ladder is exhausted
	vr     variant // the chosen variant (zero when exhausted)
	class  protocol.BudgetClass
	// singleSocket is, by role, whether that role runs on one socket only
	// after failing to bind more than half of its sockets.
	singleSocket [2]bool
}

func (p familyPick) running() bool { return p.idx >= 0 }

// pickFamilies chooses each family's variant: the first reachable one at or
// after the family's next ladder position. bindBlocked reports that a family
// stopped only because a forced single socket cannot run the multi-socket
// variants left on its ladder.
func pickFamilies(in input, order []api.VariantID) (picks []familyPick, bindBlocked bool) {
	single := [2]bool{forceSingleSocket(in, 0), forceSingleSocket(in, 1)}
	picks = make([]familyPick, len(in.fams))
	for i := range picks {
		ladder := in.fams[i].Ladder
		if i == 0 {
			ladder = order
		}
		p := familyPick{ladder: ladder, idx: -1, singleSocket: single}
		start := nextIndex(in, i, ladder)
		if in.fams[i].CheapOnly && start >= CheapRounds && !hasCandidate(in.Evidence) {
			start = len(ladder) // the cheap rounds found nothing: the verdict
		}
		for j := start; j < len(ladder); j++ {
			vr, ok := variantOf(ladder[j])
			if !ok || !reachable(in, i, vr, in.Round) {
				continue
			}
			if vr, ok = forFamily(vr, in.fams[i]); !ok {
				continue
			}
			if needsSockets(in, i, vr, single) {
				bindBlocked = true
				continue
			}
			p.idx, p.vr = j, vr
			break
		}
		picks[i] = p
	}
	return picks, bindBlocked
}

// nextIndex is the family's ladder position for this round: the last
// recorded variant's position plus one, except ConfirmLost repeats it (same
// variant, no step skipped), counting the rounds since the
// family's ladder started (familyPlan.From). A family whose last record is
// VInvalid has exhausted its ladder. Rescue rounds do not advance; a family
// the outcomes do not record advances one rung per round.
func nextIndex(in input, i int, ladder []api.VariantID) int {
	fam := in.fams[i].Family
	runs, rungs := 0, 0
	var last api.VariantID
	var lastClass api.RoundClass
	recorded := false
	for _, o := range in.Prev[min(in.fams[i].From, len(in.Prev)):] {
		if o.Rescue {
			continue
		}
		if o.Class != api.RoundConfirmLost {
			rungs++
		}
		if v, ok := familyVariantOf(o, i, fam); ok {
			runs++
			last, lastClass, recorded = v, o.Class, true
		}
	}
	if !recorded {
		return rungs
	}
	if last == VInvalid {
		return len(ladder)
	}
	base := indexOf(ladder, last)
	if base < 0 {
		// Not on this ladder (an Order that changed between rounds): count
		// the rounds the family ran.
		base = runs - 1
	}
	if lastClass == api.RoundConfirmLost {
		return base
	}
	return base + 1
}

// familyVariantOf returns what family i (fam) ran in outcome o.
func familyVariantOf(o api.RoundOutcome, i int, fam protocol.Family) (api.VariantID, bool) {
	for _, f := range o.Families {
		if f.Family == fam {
			return f.Variant, true
		}
	}
	if i == 0 && len(o.Families) == 0 {
		return o.Variant, true
	}
	return VInvalid, false
}

// reachable reports whether variant vr may run for family i at the given
// round under the extreme gate, the family's BirthdayTier gate (with its
// NAT66 cap), the two-sided birthday's handshake rule and opensBirthday. round is explicit so
// isFinal can look ahead to the round a successor would actually run in.
func reachable(in input, i int, vr variant, round int) bool {
	if vr.budget == protocol.BudgetExtreme && (!in.AllowExtreme || round < 3) {
		return false
	}
	if vr.reqTier != "" {
		tier := protocol.TightenBudget(in.Policy.Budget).Birthday
		if c := in.fams[i].TierCap; c != "" && c.Rank() < tier.Rank() {
			tier = c
		}
		if !tier.Valid() || tier.Rank() < vr.reqTier.Rank() {
			return false
		}
		if !sprayerOpens(in.fams[i], vr) {
			return false
		}
	}
	if vr.twoSided && (!in.AllowExtreme || in.HandshakeMs < vr.minHandshakeMs) {
		return false
	}
	return true
}

// sprayerOpens reports whether the family's birthday side may open a
// birthday round (opensBirthday).
func sprayerOpens(fp familyPlan, vr variant) bool {
	switch vr.sprayer {
	case bsA:
		return fp.OpensA
	case bsB:
		return fp.OpensB
	case bsBoth:
		return fp.OpensA && fp.OpensB
	default:
		return true
	}
}

// needsSockets reports whether vr depends on several sockets of a role that
// is forced to one socket: such a variant is skipped.
func needsSockets(in input, i int, vr variant, single [2]bool) bool {
	for role := range 2 {
		if single[role] && roleTemplate(vr, in.fams[i].SideA, role).sockets > 1 {
			return true
		}
	}
	return false
}

// roleTemplate returns the template a role runs in vr for a family whose A
// side is sideA.
func roleTemplate(vr variant, sideA protocol.Role, role int) sideTmpl {
	if role == roleIndex(sideA) {
		return vr.a
	}
	return vr.b
}

// forceSingleSocket reports whether role failed to bind more than half of its
// sockets in the last non-rescue round. The round's socket
// count is the largest the role's templates asked for in any family.
func forceSingleSocket(in input, role int) bool {
	bf := int(in.Evidence.BindFailed[role])
	prev, ok := lastNonRescue(in.Prev)
	if bf == 0 || !ok {
		return false
	}
	sockets := 0
	for i, fp := range in.fams {
		v, ok := familyVariantOf(prev, i, fp.Family)
		if !ok {
			continue
		}
		if vr, ok := familyVariant(v, fp); ok {
			sockets = max(sockets, int(roleTemplate(vr, fp.SideA, role).sockets))
		}
	}
	return sockets > 0 && bf*2 > sockets
}

// ---- escalation ----

// assignClasses gives each running family its effective class and returns
// the round's class, the highest of them. The guard is the
// round's: at most one class above the previous round's actual class — the
// same class after ConfirmLost, which repeats a variant without escalating
// — and on the first round at most min(the family's Ladder[0]
// class, balanced) unless memory promoted the primary variant. heavy needs
// round 2 with random-EDM evidence in the family, else round 3.
func assignClasses(in input, picks []familyPick) protocol.BudgetClass {
	last, hasLast := lastOutcome(in.Prev)
	var guard protocol.BudgetClass
	if hasLast {
		r := prevRank(last)
		if last.Class != api.RoundConfirmLost {
			r++
		}
		guard = protocol.ClassOfRank(r)
	}
	round := protocol.BudgetClass("")
	for i := range picks {
		p := &picks[i]
		if !p.running() {
			continue
		}
		promoted := i == 0 && !hasLast && in.MemoryPromoted
		limit := guard
		if !hasLast {
			limit = classOf(in.fams[i].Ladder[0]).Min(protocol.BudgetBalanced)
			if promoted {
				limit = protocol.BudgetHeavy
			}
		}
		eff := p.vr.budget.Min(limit)
		fp := in.fams[i]
		if eff == protocol.BudgetHeavy && in.Round < 3 && fp.CatA != CatRND && fp.CatB != CatRND && !promoted {
			eff = protocol.BudgetBalanced
		}
		if p.vr.budget == protocol.BudgetBackground && (fp.CatA == CatRND || fp.CatB == CatRND) {
			// The slow birthday is wide in time, not in rate: it escapes
			// the escalation guard, first round included — the strategy
			// memory may well start a Background session with it.
			eff = protocol.BudgetBackground
		}
		p.class = eff
		if eff.Rank() > round.Rank() {
			round = eff
		}
	}
	return round
}

// prevRank is the previous round's actual granted rank: RoundOutcome.Budget
// when the coordinator set it, otherwise the variant's template class.
func prevRank(prev api.RoundOutcome) int {
	if prev.Budget.Valid() {
		return prev.Budget.Rank()
	}
	if vr, ok := variantOf(prev.Variant); ok {
		return vr.budget.Rank()
	}
	return 1
}

func classOf(id api.VariantID) protocol.BudgetClass {
	if vr, ok := variantOf(id); ok {
		return vr.budget
	}
	return protocol.BudgetLight
}

// ---- advancement helpers ----

func lastOutcome(prev []api.RoundOutcome) (api.RoundOutcome, bool) {
	if len(prev) == 0 {
		return api.RoundOutcome{}, false
	}
	return prev[len(prev)-1], true
}

func lastNonRescue(prev []api.RoundOutcome) (api.RoundOutcome, bool) {
	for i := len(prev) - 1; i >= 0; i-- {
		if !prev[i].Rescue {
			return prev[i], true
		}
	}
	return api.RoundOutcome{}, false
}

func indexOf(order []api.VariantID, id api.VariantID) int {
	for i, v := range order {
		if v == id {
			return i
		}
	}
	return -1
}

func countNonRescue(prev []api.RoundOutcome) int {
	n := 0
	for _, p := range prev {
		if !p.Rescue {
			n++
		}
	}
	return n
}

// isFinal reports whether this round is the last. The rescue round is not
// counted against max_rounds, and a round after which no family
// has a reachable successor is Final. A successor runs no earlier than
// the next round, so the extreme gate is evaluated at round+1.
func isFinal(in input, picks []familyPick) bool {
	if in.MaxRounds > 0 && countNonRescue(in.Prev)+1 >= in.MaxRounds {
		return true
	}
	for i, p := range picks {
		if !p.running() {
			continue
		}
		for j := p.idx + 1; j < len(p.ladder); j++ {
			vr, ok := variantOf(p.ladder[j])
			if !ok || !reachable(in, i, vr, in.Round+1) {
				continue
			}
			if vr, ok = forFamily(vr, in.fams[i]); ok && !needsSockets(in, i, vr, p.singleSocket) {
				return false
			}
		}
	}
	return true
}

// nominalPackets is the round's packet volume for the budget_hit rule: the
// largest nominal "packets per side" of the running variants.
func nominalPackets(picks []familyPick) int {
	m := 0
	for _, p := range picks {
		if p.running() {
			m = max(m, maxSidePackets(p.vr))
		}
	}
	return m
}

// prevNominalPackets is nominalPackets of the recorded round prev.
func prevNominalPackets(in input, prev api.RoundOutcome) int {
	m := 0
	for i, fp := range in.fams {
		if v, ok := familyVariantOf(prev, i, fp.Family); ok {
			if vr, ok := familyVariant(v, fp); ok {
				m = max(m, maxSidePackets(vr))
			}
		}
	}
	return m
}

// familyVariant is variant id as family fp ran it (forFamily).
func familyVariant(id api.VariantID, fp familyPlan) (variant, bool) {
	vr, ok := variantOf(id)
	if !ok {
		return variant{}, false
	}
	return forFamily(vr, fp)
}

// applySandwich sets the sandwich probe on a side whose next port the peer
// predicts from a sequential allocator (port_alloc=sequential; a pool
// allocates at random inside its block, where the P_b < P_s < P_a bound
// does not hold), when the peer is endpoint independent (OPEN or PDF). The
// window brackets the side's mapping toward the peer's observed endpoint,
// and only an endpoint-independent peer sends from that endpoint: an
// endpoint-dependent peer reaches the side from new mappings the window
// says nothing about. Each running family is
// checked on its own traits and flagged on its own side: the probes of
// one family bracket that family's punches only. A side that
// initiates nothing in the family has no first punch to bracket.
func applySandwich(dec *api.RoundDecision, in input, picks []familyPick) {
	if !in.SandwichOK {
		return
	}
	for i, fp := range in.fams {
		if !picks[i].running() || fp.Unverified {
			continue // an unverified family never predicts
		}
		for role := range 2 {
			tr := familyTraits(in.Views[role], fp.Family)
			peer := CategoryOf(familyTraits(in.Views[1-role], fp.Family))
			fs := &dec.Sides[role][i]
			if CategoryOf(tr) == CatSEQ && tr.PortAlloc == protocol.AllocSequential && (peer == CatOpen || peer == CatPDF) &&
				fs.Role != protocol.SideReplyOnly {
				fs.Sandwich = true
			}
		}
	}
}

// DetailNoTarget is the stop detail of a session in which, before its first
// round, neither side had an address it may aim at: no verified public
// address and no shared LAN or overlay — for example two clients the server
// saw only at private addresses (Traits.LANObserved) on different LANs.
const DetailNoTarget = "no_target"

// stopBeforeContact ends a ladder with nothing left to run: before the first
// round it is candidate_timeout with DetailNoTarget, since no packet could
// be aimed at all; later the attribution of the evidence.
func stopBeforeContact(in input, hopeless bool) api.RoundDecision {
	if len(in.Prev) == 0 {
		return api.RoundDecision{Stop: protocol.ReasonCandidateTimeout, StopDetail: DetailNoTarget}
	}
	return api.RoundDecision{Stop: TerminalReason(in.Evidence, hopeless)}
}

// initiates reports whether any side has a stage that sends.
func initiates(sides [2][]protocol.FamilySide) bool {
	for _, ss := range sides {
		for _, fs := range ss {
			if fs.Role != protocol.SideReplyOnly {
				return true
			}
		}
	}
	return false
}

func hasCandidate(ev api.Evidence) bool {
	return ev.Hit[0] || ev.Hit[1] || len(ev.SeenFrom[0]) > 0 || len(ev.SeenFrom[1]) > 0
}

// pathBlocked reports whether any previous round saw the peer path blocked, so
// predict/random stages to that IP are dropped for the rest of the session: a
// prior Blocked class, cumulative ICMP at the threshold, or a udp_blocked
// fatal.
func pathBlocked(in input) bool {
	for _, p := range in.Prev {
		if p.Class == api.RoundBlocked {
			return true
		}
	}
	ev := in.Evidence
	return ev.ICMPUnreach[0] >= icmpUnreachThreshold || ev.ICMPUnreach[1] >= icmpUnreachThreshold ||
		ev.Fatal[0] == protocol.ReasonUDPBlocked || ev.Fatal[1] == protocol.ReasonUDPBlocked
}

// sideBudgetTooLow reports whether a side's remaining packet budget is below the
// usable minimum (BudgetLeft < 60 -> packet_budget_exceeded). A
// negative BudgetLeft means "unknown / unlimited".
func sideBudgetTooLow(left int) bool { return left >= 0 && left < minUsableBudget }

const minUsableBudget = 60

// maxSidePackets is a variant's nominal packets per side.
func maxSidePackets(vr variant) int {
	return int(max(vr.a.nominalPackets, vr.b.nominalPackets))
}

func roleIndex(r protocol.Role) int {
	if r == protocol.RoleResponder {
		return 1
	}
	return 0
}

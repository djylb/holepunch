package plan

import (
	"net/netip"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// RoundClass is the coordinator's reading of a finished round. The
// planner consumes the previous round's class to decide advancement.
type RoundClass uint8

const (
	RCNoReport    RoundClass = iota // one side's result missing
	RCConfirmed                     // a side confirmed; no further round
	RCConfirmLost                   // both hit but no confirm
	RCOneWay                        // one direction only
	RCNoContact                     // neither side saw a peer packet
	RCBlocked                       // udp_blocked / icmp_unreach >= 50
)

// Evidence is the cross-round accumulation the planner reads, indexed by role
// (0 = initiator, 1 = responder).
type Evidence struct {
	SeenFrom    [2][]netip.AddrPort // deduped peer sources (<= 8)
	Hit         [2]bool
	PeerSeenUs  [2]bool
	Sent        [2]uint32
	Fired       [2]bool // the side entered the fire window at least once
	Drift       [2]bool
	ICMPUnreach [2]uint16
	BindFailed  [2]uint16
	BudgetHit   [2]bool
	Fatal       [2]protocol.Reason
}

// FamilyRound is what one shared family runs in a round. Each family follows
// its own ladder, with its own BirthdayTier, extreme and two-sided-birthday
// gates and its own class.
type FamilyRound struct {
	Family protocol.Family
	// Budget is the family's effective class: its variant's class under the
	// round's escalation guard. RoundDecision.Budget is the highest of them;
	// it is empty for an exhausted family.
	Budget protocol.BudgetClass
	// Mapped is, by role, how many new external mappings the round made in
	// the family on the side's NAT: its granted plan's new (socket,
	// destination) pairs (SideMappings; the spray part cut to the distinct
	// ports the client reported), the peer_targets ports it was sent, two
	// for the sandwich probes of a fresh helper socket, one for a
	// re-observation probe that found a new mapping. The coordinator fills it
	// in RoundOutcome.Families; a sequential endpoint-dependent NAT
	// allocates one port per mapping, so seq_x_seq advances a side's
	// predicted port by it (pairAnchor). The planner leaves it zero
	// in RoundDecision.
	Mapped [2]int
	// Center is, by role, the port the role's predict stage centred on: the
	// peer's predicted next port, the stage's anchor plus its first step; 0
	// without a predict stage. The planner sets it; the outcome returns it, and
	// the next round of pdf_x_seq sends the ports around it once more.
	Center [2]uint16
	// Heard is, by role, whether the side heard its peer in the family
	// during the round: a hit or a peer source. The coordinator fills it in
	// RoundOutcome.Families; two one-way rounds with the same side hearing
	// and the other never make the family a PDF×RND pair with the hearer
	// as the random side (oneWaySeer). The planner leaves it zero
	// in RoundDecision.
	Heard [2]bool
	// Variant is the family's variant this round, or VInvalid once the
	// family's ladder is exhausted: its sides then only reply (reply_only)
	// while another family still runs.
	Variant VariantID
	// NoContact: neither side heard the other in the family during the
	// round, and neither saw the path blocked. The coordinator fills it in
	// RoundOutcome.Families; two in a row make a doubtful EIM side endpoint
	// dependent (escalate). The planner leaves it false in
	// RoundDecision.
	NoContact bool
}

// RoundOutcome summarises a finished round for the planner (Prev). Budget is
// the class the coordinator actually granted that round; the escalation guard
// bases the next round on it, not on the variant's template class.
type RoundOutcome struct {
	Budget protocol.BudgetClass
	// SeenFrom and Hit are this round's own evidence by role — the
	// round_result seen_from (deduplicated) and hit — not the cumulative
	// Evidence. After a one-way round the rescue round makes the side that
	// heard the other the sender, toward the sources it heard, in their
	// family: cumulative evidence would also count earlier rounds
	// and may point at the wrong side. An outcome without them leaves that
	// choice to the cumulative Evidence.
	SeenFrom [2][]netip.AddrPort
	// Families is the round's RoundDecision.Families, which the coordinator
	// copies: the planner advances each family's own ladder from it. An
	// outcome without it is read as the primary family running Variant and
	// every other family advancing one rung (none after ConfirmLost) —
	// exact for a single-family session; a dual-stack session needs it to
	// follow each family's skips and exhaustion.
	Families []FamilyRound
	Round    int
	Hit      [2]bool
	Variant  VariantID
	Class    RoundClass
	Rescue   bool
}

// ClassifyInput is the planner's one-shot classification input. The
// two views are the server's merged views by role, exactly as the clients
// receive them. Pair says, per family, which families the server could not
// verify (Pair.Unverified: Direct to self-reported global addresses only)
// and which pairs share a LAN (Pair.LikelySameLAN: the peers' LAN endpoints
// become targets).
type ClassifyInput struct {
	Initiator protocol.PeerView
	Responder protocol.PeerView
	// Measured is, by role (0 initiator, 1 responder), what natprobe itself
	// measured of each family it observed: the view Handle.Merge returns
	// without a TraitsMemory (the coordinator's raw view). A family
	// natprobe did not observe is absent — every family without a natprobe
	// registry, a family no observer covers — and so is the
	// whole view when the coordinator has none. Initiator and Responder
	// choose the ladders, but they may carry a client's self-reported
	// traits or a conclusion the traits memory raised; only these traits,
	// and only their port allocation and its confidence, can end a session
	// at summary time (summaryVerdict). Endpoints are not read.
	Measured [2]protocol.PeerView
	Pair     protocol.PairFacts
	Policy   protocol.Policy
	Timeouts protocol.Timeouts
	Features []protocol.Feature
	// Mode is the session's mode: in ModeBackground a pdf_x_rnd
	// family runs the slow birthday instead of the bursty one-sided birthday
	// rounds.
	Mode protocol.SessionMode
}

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
	Ladder  []VariantID
	// MaxTargets bounds the Direct targets of a side and round: 8 in a
	// verified family; in an unverified one 4, or 16 when every
	// shared family is unverified (the relay-only mode).
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

// Classification is the planner's one-shot output. The top-level
// PairClass/SideA/Ladder/Budgets describe the primary family (Families[0]), the
// one StrategyMemory keys on; fams holds every shared family's own plan.
// StrategyKey derivation (ClassBits) is coord's job and lives there, so this
// struct does not import internal/nat.
type Classification struct {
	Reject    protocol.Reason                    // non-empty -> do not punch
	PairClass string                             // primary family's diagnostic ladder name
	Families  []protocol.Family                  // shared workable families, priority order (v6 first)
	SideA     protocol.Role                      // the A (rule) side of the primary ladder
	Ladder    []VariantID                        // primary ladder, cheap -> expensive
	Budgets   map[VariantID]protocol.BudgetClass // per-variant class of the primary ladder
	// Advice is what a failure of the session suggests (adviceFor).
	Advice protocol.Advice

	fams       []familyPlan // per-family plans, Families[i] == fams[i].Family
	background bool         // a Background session's (ClassifyInput.Mode)
}

// MappingSample is one external mapping of a side observed while punching.
type MappingSample struct {
	Addr  netip.AddrPort
	At    time.Duration // when it was observed, on the RoundInput.FireAt axis
	Round int           // the round it was observed in
}

// RoundInput is the per-round planner input. Views is by role index.
type RoundInput struct {
	Round             int
	Class             Classification
	Order             []VariantID // memory-reordered primary ladder; empty -> Class.Ladder
	Prev              []RoundOutcome
	Evidence          Evidence
	RTT               [2]time.Duration
	Remaining         time.Duration // punchDeadline - now (D is passed separately)
	D                 time.Duration // coordinator's stop margin; the planner does not re-estimate
	BudgetLeft        [2]int        // each side's remaining grantable packets
	Recent10sDistinct [2]int        // distinct ports already granted to the peer IP in the last 10 s
	Gone              [2]bool
	RescueUsed        bool
	Views             [2]protocol.PeerView // [initiator, responder]
	Policy            protocol.Policy
	AllowExtreme      bool
	MaxRounds         int
	HandshakeMs       uint32 // handshake_timeout_ms (the two-sided birthday needs >= 30000)
	SandwichOK        bool   // both sides negotiated the sandwich feature
	// MemoryPromoted lifts the first-round "<= Ladder[0] class" cap when
	// StrategyMemory promotes a heavier variant proven for this key.
	// Failure never promotes.
	MemoryPromoted bool
	// FireAt is when this round is expected to fire, on the server's
	// monotonic axis whose origin is the session's natprobe registration —
	// the axis of protocol.Traits.PortAnchorMs. The coordinator derives it
	// from the registration time, now and D (the go leaves now and fires D
	// later). The planner extrapolates a sequential peer's next external port
	// to it: anchor + step + PortVelocity·(FireAt − anchor time). Zero means
	// unknown: no extrapolation.
	FireAt time.Duration
	// Mappings are, by role, that side's external mappings observed while
	// punching: the seen_from sources its peer reported and the remotes of
	// peer_seen about it, each with the time it was observed on the FireAt axis
	// (the fire time of the round it was seen in is a good estimate). A sample
	// later than the probe's anchor becomes the new anchor and, with the point
	// before it, re-estimates the allocation velocity. The planner does this
	// itself; the coordinator only passes the samples.
	Mappings [2][]MappingSample
	// Refresh are, by role, the anchor refreshes the coordinator had the
	// side make just before this round: where its sequential
	// allocator is now and how fast other hosts move it. A refresh is the
	// newest point of the allocator; the planner aims at it, advanced by
	// the drift it expects until the round fires.
	Refresh [2][]AnchorRefresh
}

// AnchorRefresh is one family's anchor refresh by one side: the mappings of
// its two new sockets, each made by a
// single probe about 60 ms apart, and when natprobe saw them, on the
// FireAt axis. A probe that did not come in time is the zero AddrPort: the
// coordinator waits a bounded time after the first one and goes on with
// what came, so a refresh carries one probe or both.
type AnchorRefresh struct {
	Family            protocol.Family
	First, Second     netip.AddrPort
	FirstAt, SecondAt time.Duration
}

// RoundDecision is the planner's per-round output.
type RoundDecision struct {
	Stop        protocol.Reason // non-empty -> stop; Sides is empty
	VariantName string
	Budget      protocol.BudgetClass // the highest class of the running families
	// Sides are by role; a family side's Sandwich is set where
	// applySandwich allows it, and the coordinator keeps it only when
	// both sides negotiated the feature.
	Sides [2][]protocol.FamilySide // [initiator, responder]
	// Families is what each shared family runs, in Class.Families order.
	// The coordinator copies it into the round's RoundOutcome.
	Families []FamilyRound
	Window   time.Duration
	// Variant and VariantName name the round on the wire and in
	// StrategyMemory: the primary family's variant, or — once the primary
	// ladder is exhausted while another family still runs — that family's.
	Variant VariantID
	Final   bool
	Rescue  bool
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
func (DefaultPlanner) Classify(in ClassifyInput) Classification {
	fams := sharedFamilies(in.Initiator, in.Responder)
	if len(fams) == 0 {
		return Classification{Reject: protocol.ReasonNoCommonFamily}
	}
	cl := Classification{Families: fams}
	relayOnly := true
	for _, fam := range fams {
		relayOnly = relayOnly && in.Pair.Unverified[fam]
	}
	cl.background = in.Mode == protocol.ModeBackground
	for _, fam := range fams {
		tr := [2]protocol.Traits{familyTraits(in.Initiator, fam), familyTraits(in.Responder, fam)}
		var edm [2]bool
		for r := range tr {
			// A STUN server saw another mapping than natprobe: the
			// mapping depends on the path, and the EIM conclusion is
			// planned as endpoint dependent from the start.
			edm[r] = !in.Pair.Unverified[fam] && tr[r].PathDependent && eimDoubt(tr[r])
		}
		fp := planFamily(fam, tr, edm, in.Pair, in.Policy, cl.background, relayOnly)
		fp.CheapOnly = fp.PairClass == PairSeqRnd && SeqRndVerdict(in.Measured, fam)
		cl.fams = append(cl.fams, fp)
	}
	primary := cl.fams[0]
	cl.PairClass = primary.PairClass
	cl.SideA = primary.SideA
	cl.Ladder = primary.Ladder
	cl.Budgets = variantClasses(primary.Ladder)
	if summaryVerdict(in, cl) {
		cl.Reject = protocol.ReasonHardSymmetricRandom // no punch at all
	}
	cl.Advice = adviceFor(primary, cl.Reject, in.Policy)
	return cl
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
		fp.MaxTargets = maxRelayOnlyTargets
	case fp.Unverified:
		fp.MaxTargets = maxUnverifiedTargets
	}
	return fp
}

// Round decides the next round. It owns round advancement — each family on its
// own ladder — the rescue round, the stop rules, the escalation guard, the
// BirthdayTier gate, the dual-stack shared-budget split and the invariant
// "granted = emittable", which here means that every side's MaxPackets equals
// the packets its stages expand to.
func (DefaultPlanner) Round(in RoundInput) RoundDecision {
	order := in.Order
	if len(order) == 0 {
		order = in.Class.Ladder
	}
	if len(order) == 0 || len(in.Class.fams) == 0 {
		return RoundDecision{Stop: protocol.ReasonNoProbeEndpoint}
	}
	// An unconfirmed end without contact is hard_symmetric_random when both
	// sides of the primary family are RND, or when natprobe measured it as
	// one only the cheap rounds can open and they ran. The
	// measurement decides, not a run-time correction.
	primary := in.Class.fams[0]
	hopeless := primary.CatA == CatRND && primary.CatB == CatRND || primary.CheapOnly && countNonRescue(in.Prev) >= CheapRounds
	if escalated := escalate(&in); escalated[0] {
		order = in.Class.fams[0].Ladder
	}

	// Coordinator-level stop rules the planner also enforces (invariants).
	// Remaining is punchDeadline - now; D is the coordinator's margin (the
	// planner uses the coordinator's D and does not re-estimate or re-deduct).
	if in.Remaining < minWindow+in.D {
		return RoundDecision{Stop: TerminalReason(in.Evidence, hopeless)}
	}
	if sideBudgetTooLow(in.BudgetLeft[0]) || sideBudgetTooLow(in.BudgetLeft[1]) {
		return RoundDecision{Stop: protocol.ReasonPacketBudgetExceeded}
	}

	// Rescue round: one per session, not counted against max_rounds;
	// none where the next birthday round is the remedy.
	if last, ok := lastOutcome(in.Prev); ok && last.Class == RCOneWay && !in.RescueUsed && !birthdayFollows(in, last) {
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
			return RoundDecision{Stop: protocol.ReasonLocalPortBindFailed}
		}
		return RoundDecision{Stop: TerminalReason(in.Evidence, hopeless)}
	}

	// budget_hit with no candidate and a not-lower next round -> stop.
	if (in.Evidence.BudgetHit[0] || in.Evidence.BudgetHit[1]) && !hasCandidate(in.Evidence) {
		if prev, ok := lastNonRescue(in.Prev); ok && nominalPackets(picks) >= prevNominalPackets(in, prev) {
			return RoundDecision{Stop: protocol.ReasonPacketBudgetExceeded}
		}
	}

	roundClass := assignClasses(in, picks)
	sides, win := buildSides(in, picks, roundClass)
	if !initiates(sides) {
		// Every stage was dropped (a blocked path and no Direct target).
		return RoundDecision{Stop: TerminalReason(in.Evidence, hopeless)}
	}

	dec := RoundDecision{
		Variant:     picks[lead].vr.id,
		VariantName: picks[lead].vr.name,
		Budget:      roundClass,
		Window:      win,
		Final:       isFinal(in, picks),
		Sides:       sides,
	}
	for i := range picks {
		dec.Families = append(dec.Families, FamilyRound{Family: in.Class.fams[i].Family, Variant: picks[i].vr.id, Budget: picks[i].class,
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
	ladder []VariantID
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
func pickFamilies(in RoundInput, order []VariantID) (picks []familyPick, bindBlocked bool) {
	single := [2]bool{forceSingleSocket(in, 0), forceSingleSocket(in, 1)}
	picks = make([]familyPick, len(in.Class.fams))
	for i := range picks {
		ladder := in.Class.fams[i].Ladder
		if i == 0 {
			ladder = order
		}
		p := familyPick{ladder: ladder, idx: -1, singleSocket: single}
		start := nextIndex(in, i, ladder)
		if in.Class.fams[i].CheapOnly && start >= CheapRounds && !hasCandidate(in.Evidence) {
			start = len(ladder) // the cheap rounds found nothing: the verdict
		}
		for j := start; j < len(ladder); j++ {
			vr, ok := variantOf(ladder[j])
			if !ok || !reachable(in, i, vr, in.Round) {
				continue
			}
			if vr, ok = forFamily(vr, in.Class.fams[i]); !ok {
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
func nextIndex(in RoundInput, i int, ladder []VariantID) int {
	fam := in.Class.fams[i].Family
	runs, rungs := 0, 0
	var last VariantID
	var lastClass RoundClass
	recorded := false
	for _, o := range in.Prev[min(in.Class.fams[i].From, len(in.Prev)):] {
		if o.Rescue {
			continue
		}
		if o.Class != RCConfirmLost {
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
	if lastClass == RCConfirmLost {
		return base
	}
	return base + 1
}

// familyVariantOf returns what family i (fam) ran in outcome o.
func familyVariantOf(o RoundOutcome, i int, fam protocol.Family) (VariantID, bool) {
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
func reachable(in RoundInput, i int, vr variant, round int) bool {
	if vr.budget == protocol.BudgetExtreme && (!in.AllowExtreme || round < 3) {
		return false
	}
	if vr.reqTier != "" {
		tier := protocol.TightenBudget(in.Policy.Budget).Birthday
		if c := in.Class.fams[i].TierCap; c != "" && c.Rank() < tier.Rank() {
			tier = c
		}
		if !tier.Valid() || tier.Rank() < vr.reqTier.Rank() {
			return false
		}
		if !sprayerOpens(in.Class.fams[i], vr) {
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
func needsSockets(in RoundInput, i int, vr variant, single [2]bool) bool {
	for role := range 2 {
		if single[role] && roleTemplate(vr, in.Class.fams[i].SideA, role).sockets > 1 {
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
func forceSingleSocket(in RoundInput, role int) bool {
	bf := int(in.Evidence.BindFailed[role])
	prev, ok := lastNonRescue(in.Prev)
	if bf == 0 || !ok {
		return false
	}
	sockets := 0
	for i, fp := range in.Class.fams {
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
func assignClasses(in RoundInput, picks []familyPick) protocol.BudgetClass {
	last, hasLast := lastOutcome(in.Prev)
	var guard protocol.BudgetClass
	if hasLast {
		r := prevRank(last)
		if last.Class != RCConfirmLost {
			r++
		}
		guard = classByRank(r)
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
			limit = minClass(classOf(in.Class.fams[i].Ladder[0]), protocol.BudgetBalanced)
			if promoted {
				limit = protocol.BudgetHeavy
			}
		}
		eff := minClass(p.vr.budget, limit)
		fp := in.Class.fams[i]
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
func prevRank(prev RoundOutcome) int {
	if prev.Budget.Valid() {
		return prev.Budget.Rank()
	}
	if vr, ok := variantOf(prev.Variant); ok {
		return vr.budget.Rank()
	}
	return 1
}

func classOf(id VariantID) protocol.BudgetClass {
	if vr, ok := variantOf(id); ok {
		return vr.budget
	}
	return protocol.BudgetLight
}

func classByRank(r int) protocol.BudgetClass {
	switch {
	case r <= 1:
		return protocol.BudgetLight
	case r == 2:
		return protocol.BudgetBalanced
	case r == 3:
		return protocol.BudgetHeavy
	default:
		return protocol.BudgetExtreme
	}
}

func minClass(a, b protocol.BudgetClass) protocol.BudgetClass {
	if a.Rank() <= b.Rank() {
		return a
	}
	return b
}

// ---- advancement helpers ----

func lastOutcome(prev []RoundOutcome) (RoundOutcome, bool) {
	if len(prev) == 0 {
		return RoundOutcome{}, false
	}
	return prev[len(prev)-1], true
}

func lastNonRescue(prev []RoundOutcome) (RoundOutcome, bool) {
	for i := len(prev) - 1; i >= 0; i-- {
		if !prev[i].Rescue {
			return prev[i], true
		}
	}
	return RoundOutcome{}, false
}

func indexOf(order []VariantID, id VariantID) int {
	for i, v := range order {
		if v == id {
			return i
		}
	}
	return -1
}

func countNonRescue(prev []RoundOutcome) int {
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
func isFinal(in RoundInput, picks []familyPick) bool {
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
			if vr, ok = forFamily(vr, in.Class.fams[i]); ok && !needsSockets(in, i, vr, p.singleSocket) {
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
func prevNominalPackets(in RoundInput, prev RoundOutcome) int {
	m := 0
	for i, fp := range in.Class.fams {
		if v, ok := familyVariantOf(prev, i, fp.Family); ok {
			if vr, ok := familyVariant(v, fp); ok {
				m = max(m, maxSidePackets(vr))
			}
		}
	}
	return m
}

// familyVariant is variant id as family fp ran it (forFamily).
func familyVariant(id VariantID, fp familyPlan) (variant, bool) {
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
func applySandwich(dec *RoundDecision, in RoundInput, picks []familyPick) {
	if !in.SandwichOK {
		return
	}
	for i, fp := range in.Class.fams {
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

func hasCandidate(ev Evidence) bool {
	return ev.Hit[0] || ev.Hit[1] || len(ev.SeenFrom[0]) > 0 || len(ev.SeenFrom[1]) > 0
}

// pathBlocked reports whether any previous round saw the peer path blocked, so
// predict/random stages to that IP are dropped for the rest of the session: a
// prior Blocked class, cumulative ICMP at the threshold, or a udp_blocked
// fatal.
func pathBlocked(in RoundInput) bool {
	for _, p := range in.Prev {
		if p.Class == RCBlocked {
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

package plan

import "github.com/djylb/holepunch/protocol"

// VariantID identifies a round template within the whole catalogue (at most
// 32, so StrategyMemory can index scores by it).
// The variant's name travels on the wire as RoundPlan.variant.
type VariantID uint8

// The catalogue ids. 0 is invalid; each ladder is a fixed sequence of these.
const (
	VInvalid VariantID = iota

	vEasy1
	vEasy2
	vEasy3
	vEasy4
	vEasy5

	vOpenEDM1
	vOpenEDM2
	vOpenEDM3
	vOpenEDM4

	vPDFSeq1
	vPDFSeq2
	vPDFSeq3
	vPDFSeq4
	vPDFSeq5

	vPDFRnd1
	vPDFRnd2
	vPDFRnd3
	vPDFRnd4

	vSeqSeq1
	vSeqSeq2
	vSeqSeq3

	vSeqRnd1
	vSeqRnd2
	vSeqRnd3

	vRndRnd1
	vRndRnd2
	vRndRnd3

	vPres1
	vPres2

	vPDFRndSlow

	vRescue

	numVariants // keep last
)

// Ladder-value constants: normal rounds pace at 150 pps,
// birthday rounds at 300 pps, and the new-targets ladder value is 100/s.
const (
	ladderPPS         = 150
	ladderBirthdayPPS = 300
	ladderNPS         = 100
)

// The slow birthday of a Background session.
const (
	slowSockets = 120  // the RND side's sockets
	slowOpen    = 16   // sockets opened a second
	slowNPS     = 25   // the PDF side's new ports a second
	slowStartMs = 4000 // the spray starts when half the sockets are open
	slowSpray   = 1025 // 25 a second from 4 s to 45 s
	slowPPS     = 32
)

// backgroundLadder is pdf_x_rnd in a Background session: the cheap round,
// then the slow birthday instead of the bursty one-sided birthday rounds.
func backgroundLadder() []VariantID { return []VariantID{vPDFRnd1, vPDFRndSlow} }

// birthdaySide marks which canonical side of a birthday variant performs the
// gated spray, so Round can check that side's opensBirthday.
type birthdaySide uint8

const (
	bsNone birthdaySide = iota
	bsA                 // canonical A side sprays
	bsB                 // canonical B side sprays
	bsBoth              // both sides spray
)

// stageTmpl is a stage before its concrete targets/anchor are filled from the
// peer view at Round time.
type stageTmpl struct {
	kind    protocol.StageKind
	steps   []int16 // predict step override; nil uses the peer's PortStep
	atMs    uint16
	span    uint16 // predict
	count   uint16 // random; fresh: the sockets
	repeats uint8  // direct
	// ttl is the preferred low-TTL hop of the stage's packets, 0 for the
	// normal TTL. Every kind carries it onto the wire stage unchanged, or 0
	// with low TTL disabled (stageTTL): a predict stage may be a low-TTL
	// receiver's too, as in seq_x_seq_r2.
	ttl uint8
}

// sideTmpl is one canonical side (A or B) of a round.
type sideTmpl struct {
	role        protocol.SideRole
	sendDelayMs uint16
	sockets     uint16
	// nominalPackets is the ladder table's "packets per side",
	// written for one Direct target. It only orders rounds for the
	// budget_hit rule: a side's MaxPackets is what its stages expand to
	// against the peer's actual endpoints.
	nominalPackets uint32
	maxPPS         uint16
	// newPerSec caps the side's new destinations per second below the
	// session's (0: the session's); openPerSec paces its sockets beyond
	// the primary (FamilySide.OpenPerSec, 0: all before firing). Both are
	// the slow birthday's.
	newPerSec  uint16
	openPerSec uint16
	stages     []stageTmpl
}

// variant is one round template.
type variant struct {
	id       VariantID
	name     string
	budget   protocol.BudgetClass // template ceiling class
	windowMs uint16               // base window; extended by extendWindow

	// extendWindow extends the round window to the birthday floor
	// ceil((targets−16)/MaxNewPerSec) s, so the full birthday target set can be
	// emitted at the new-targets rate. Fixed-window rounds
	// leave it false and clamp the grant instead.
	extendWindow bool
	// reqTier is the lowest BirthdayTier at which this variant may run; "" runs
	// at any tier. A variant above the session tier is skipped.
	reqTier protocol.BirthdayTier
	// twoSided marks the two-sided birthday round: it also needs
	// AllowExtreme and a handshake of at least minHandshakeMs.
	twoSided       bool
	minHandshakeMs uint32
	// sprayer is the side whose opensBirthday gates a tiered birthday round.
	sprayer birthdaySide
	// swapIfOpen swaps the A and B templates when both sides are OPEN:
	// easy's third round exchanges the roles, but a PDF side always stays
	// the receiver because it must send first.
	swapIfOpen bool

	a, b sideTmpl
}

// forFamily returns vr as family fp runs it, and false when it cannot run
// there: easy's third round swaps the sides of an OPEN×OPEN pair,
// and an unverified family runs the variant's Direct stages only
// (directOnly), so a variant without one does not run in it.
func forFamily(vr variant, fp familyPlan) (variant, bool) {
	if vr.swapIfOpen && fp.CatA == CatOpen && fp.CatB == CatOpen {
		vr.a, vr.b = vr.b, vr.a
	}
	if !fp.Unverified {
		return vr, true
	}
	vr = directOnly(vr)
	return vr, vr.a.direct() || vr.b.direct()
}

// directOnly is vr in a family the server could not verify: its
// Direct stages only — the peer's self-reported addresses are no basis for a
// prediction or a spray — on the primary socket, from which the client sends
// to such targets anyway. That is a light round whatever the
// template's class: at most 16 targets of at most 8 packets each fit light's
// 150 packets.
func directOnly(vr variant) variant {
	vr.budget = protocol.BudgetLight
	vr.extendWindow, vr.reqTier, vr.twoSided, vr.sprayer = false, "", false, bsNone
	vr.a, vr.b = vr.a.directOnly(), vr.b.directOnly()
	return vr
}

// directOnly is the side without its predict and random stages, on one
// socket; its nominal packets are its Direct repeats, one target's worth.
func (s sideTmpl) directOnly() sideTmpl {
	stages := make([]stageTmpl, 0, len(s.stages))
	nominal := uint32(0)
	for _, st := range s.stages {
		switch st.kind {
		case protocol.StageDirect:
			nominal += uint32(st.repeats)
			stages = append(stages, st)
		case protocol.StageReplyOnly:
			stages = append(stages, st)
		}
	}
	s.stages, s.sockets, s.nominalPackets = stages, 1, nominal
	return s
}

// direct reports whether the side has a Direct stage.
func (s sideTmpl) direct() bool {
	for _, st := range s.stages {
		if st.kind == protocol.StageDirect {
			return true
		}
	}
	return false
}

// firstSpray returns the side's first predict or random stage.
func (s sideTmpl) firstSpray() (stageTmpl, bool) {
	for _, st := range s.stages {
		if st.kind == protocol.StagePredict || st.kind == protocol.StageRandom {
			return st, true
		}
	}
	return stageTmpl{}, false
}

// ---- stage/side constructors ----

func sd(repeats uint8, at uint16, ttl uint8) stageTmpl {
	return stageTmpl{kind: protocol.StageDirect, repeats: repeats, atMs: at, ttl: ttl}
}
func sp(span uint16, at uint16, ttl uint8, steps ...int16) stageTmpl {
	return stageTmpl{kind: protocol.StagePredict, span: span, atMs: at, ttl: ttl, steps: steps}
}
func sr(count uint16, at uint16, ttl uint8) stageTmpl {
	return stageTmpl{kind: protocol.StageRandom, count: count, atMs: at, ttl: ttl}
}
func sro(at uint16) stageTmpl { return stageTmpl{kind: protocol.StageReplyOnly, atMs: at} }

// sfr is a fresh-socket stage: a side that keeps a fresh socket's
// port binds count fresh sockets, each sending repeats packets; its peer
// aims repeats packets at each of their ports (freshStage).
func sfr(count uint16, repeats uint8, at uint16) stageTmpl {
	return stageTmpl{kind: protocol.StageFresh, count: count, repeats: repeats, atMs: at}
}

func side(role protocol.SideRole, delay, sockets uint16, nominal uint32, pps uint16, st ...stageTmpl) sideTmpl {
	return sideTmpl{role: role, sendDelayMs: delay, sockets: sockets, nominalPackets: nominal, maxPPS: pps, stages: st}
}

// slow is s with its new destinations capped at newPerSec a second and its
// sockets beyond the primary opened at openPerSec (the slow birthday).
func slow(s sideTmpl, newPerSec, openPerSec uint16) sideTmpl {
	s.newPerSec, s.openPerSec = newPerSec, openPerSec
	return s
}

// ladderFor returns the ladder (ids, cheap to expensive) for a pair class.
// v6_direct reuses the first three easy rounds.
func ladderFor(pairClass string) []VariantID {
	switch pairClass {
	case PairEasy:
		return []VariantID{vEasy1, vEasy2, vEasy3, vEasy4, vEasy5}
	case PairV6Direct:
		return []VariantID{vEasy1, vEasy2, vEasy3}
	case PairOpenEDM:
		return []VariantID{vOpenEDM1, vOpenEDM2, vOpenEDM3, vOpenEDM4}
	case PairPDFSeq:
		return []VariantID{vPDFSeq1, vPDFSeq2, vPDFSeq3, vPDFSeq4, vPDFSeq5}
	case PairPDFRnd:
		return []VariantID{vPDFRnd1, vPDFRnd2, vPDFRnd3, vPDFRnd4}
	case PairSeqSeq:
		return []VariantID{vSeqSeq1, vSeqSeq2, vSeqSeq3}
	case PairSeqRnd:
		return []VariantID{vSeqRnd1, vSeqRnd2, vSeqRnd3}
	case PairRndRnd:
		return []VariantID{vRndRnd1, vRndRnd2, vRndRnd3}
	case PairPDFPres:
		// The fresh rounds first; the birthday rungs stay behind them for a
		// NAT that did not keep the drawn ports after all.
		return []VariantID{vPres1, vPres2, vPDFRnd2, vPDFRnd3, vPDFRnd4}
	case PairPresPres:
		return []VariantID{vPres1, vPres2, vRndRnd2, vRndRnd3}
	}
	return nil
}

// variants is the variant table, indexed by VariantID. It is built once,
// at package initialisation, and only read afterwards: variantOf hands out
// copies, and the one slice of a template that reaches a RoundDecision (a
// predict stage's steps) is cloned on the way out, so no caller can write
// into it (no package-level mutable state).
var variants = newCatalogue()

// variantOf returns the variant id, and false for an id outside the
// catalogue.
func variantOf(id VariantID) (variant, bool) {
	if id == VInvalid || int(id) >= len(variants) {
		return variant{}, false
	}
	return variants[id], true
}

// newCatalogue builds the full variant table. The B side of
// a template is the "more open / more predictable" one only by numbering;
// A/B map to initiator/responder through the Classification's SideA. Roles
// in the templates obey "send_delay > 0 => sender" and, in easy, the PDF
// side (B when mixed) is never a sender.
func newCatalogue() [numVariants]variant {
	const L, B, H, X, BG = protocol.BudgetLight, protocol.BudgetBalanced, protocol.BudgetHeavy, protocol.BudgetExtreme, protocol.BudgetBackground
	const both, send, recv = protocol.SideBoth, protocol.SideSender, protocol.SideReceiver
	v := func(id VariantID, name string, bc protocol.BudgetClass, win uint16, a, b sideTmpl) variant {
		return variant{id: id, name: name, budget: bc, windowMs: win, a: a, b: b}
	}
	var m [numVariants]variant
	for _, x := range []variant{
		// ---- easy: OPEN/PDF (A) × OPEN/PDF (B); B is the PDF side when mixed ----
		v(vEasy1, "easy_r1_direct", L, 800,
			side(both, 0, 1, 40, ladderPPS, sd(5, 0, 0)),
			side(both, 0, 1, 40, ladderPPS, sd(5, 0, 0))),
		v(vEasy2, "easy_r2_ttl", L, 1000,
			side(send, 80, 1, 40, ladderPPS, sd(5, 80, 0)),
			side(recv, 0, 1, 40, ladderPPS, sd(5, 0, 4))),
		v(vEasy3, "easy_r3_ttl", L, 1200,
			side(send, 200, 1, 40, ladderPPS, sd(5, 200, 0)),
			side(recv, 0, 1, 40, ladderPPS, sd(5, 0, 7))),
		v(vEasy4, "easy_r4_slow", L, 1500,
			side(send, 500, 1, 32, ladderPPS, sd(4, 500, 0)),
			side(both, 0, 1, 32, ladderPPS, sd(4, 0, 0))),
		v(vEasy5, "easy_r5_final", L, 3000,
			side(send, 2000, 1, 24, ladderPPS, sd(3, 2000, 0)),
			side(recv, 0, 1, 24, ladderPPS, sd(3, 0, 4))),

		// ---- open_x_edm: OPEN (A) × SEQ/RND (B) ----
		v(vOpenEDM1, "open_x_edm_r1", L, 800,
			side(both, 0, 1, 1, ladderPPS, sd(1, 0, 0), sro(0)),
			side(both, 0, 1, 6, ladderPPS, sd(6, 0, 0))),
		v(vOpenEDM2, "open_x_edm_r2", L, 1000,
			side(recv, 0, 1, 1, ladderPPS, sd(1, 0, 4), sro(0)),
			side(send, 150, 1, 6, ladderPPS, sd(6, 150, 0))),
		v(vOpenEDM3, "open_x_edm_r3", B, 1500,
			side(both, 0, 1, 17, ladderPPS, sd(1, 0, 0), sp(16, 20, 0)),
			side(send, 500, 1, 5, ladderPPS, sd(5, 500, 0))),
		v(vOpenEDM4, "open_x_edm_r4_final", B, 3000,
			side(both, 0, 1, 17, ladderPPS, sd(1, 0, 0), sp(16, 20, 0)),
			side(send, 2000, 1, 4, ladderPPS, sd(4, 2000, 0))),

		// ---- pdf_x_seq: PDF (A) × SEQ (B) ----
		v(vPDFSeq1, "pdf_x_seq_r1", B, 800,
			side(both, 0, 1, 19, ladderPPS, sd(3, 0, 0), sp(16, 20, 0)),
			side(both, 0, 1, 6, ladderPPS, sd(6, 0, 0))),
		v(vPDFSeq2, "pdf_x_seq_r2", B, 1200,
			side(send, 100, 1, 48, ladderPPS, sp(48, 100, 0)),
			side(recv, 0, 1, 6, ladderPPS, sd(6, 0, 4))),
		v(vPDFSeq3, "pdf_x_seq_r3", H, 1500,
			side(both, 0, 1, 128, ladderPPS, sp(128, 0, 0)),
			side(both, 0, 8, 16, ladderPPS, sd(2, 0, 0))),
		v(vPDFSeq4, "pdf_x_seq_r4_birthday", H, 3000,
			side(both, 0, 1, 384, ladderBirthdayPPS, sp(128, 0, 0), sr(256, 0, 0)),
			side(both, 0, 32, 64, ladderPPS, sd(2, 0, 0))),
		v(vPDFSeq5, "pdf_x_seq_r5_birthday", X, 3000,
			side(both, 0, 1, 512, ladderBirthdayPPS, sr(512, 0, 0)),
			side(both, 0, 64, 128, ladderPPS, sd(2, 0, 0))),

		// ---- pdf_x_rnd: PDF (A) × RND (B); default stops after r3 ----
		v(vPDFRnd1, "pdf_x_rnd_r1", B, 800,
			side(both, 0, 1, 10, ladderPPS, sd(5, 0, 0)),
			side(both, 0, 1, 6, ladderPPS, sd(6, 0, 0))),
		v(vPDFRnd2, "pdf_x_rnd_r2_birthday", H, 2500,
			side(both, 0, 1, 384, ladderBirthdayPPS, sp(16, 0, 0), sr(368, 0, 0)),
			side(both, 0, 32, 64, ladderPPS, sd(2, 0, 0))),
		v(vPDFRnd3, "pdf_x_rnd_r3", H, 2500,
			side(both, 0, 1, 127, ladderPPS, sr(127, 0, 0)),
			side(both, 0, 32, 64, ladderPPS, sd(2, 0, 0))),
		v(vPDFRnd4, "pdf_x_rnd_r4_birthday", X, 3500,
			side(both, 0, 1, 768, ladderBirthdayPPS, sr(768, 0, 0)),
			side(both, 0, 64, 128, ladderPPS, sd(2, 0, 0))),

		// ---- seq_x_seq ----
		v(vSeqSeq1, "seq_x_seq_r1", B, 800,
			side(both, 0, 1, 19, ladderPPS, sd(3, 0, 0), sp(16, 20, 0)),
			side(both, 0, 1, 19, ladderPPS, sd(3, 0, 0), sp(16, 20, 0))),
		v(vSeqSeq2, "seq_x_seq_r2", B, 1200,
			side(recv, 0, 1, 48, ladderPPS, sp(48, 0, 4)),
			side(both, 0, 1, 48, ladderPPS, sp(48, 0, 0))),
		v(vSeqSeq3, "seq_x_seq_r3", H, 1500,
			side(both, 0, 8, 144, ladderPPS, sd(2, 0, 0), sp(128, 0, 0)),
			side(both, 0, 8, 144, ladderPPS, sd(2, 0, 0), sp(128, 0, 0))),

		// ---- seq_x_rnd: SEQ (A) × RND (B) ----
		v(vSeqRnd1, "seq_x_rnd_r1", B, 800,
			side(both, 0, 1, 5, ladderPPS, sd(5, 0, 0)),
			side(both, 0, 1, 19, ladderPPS, sd(3, 0, 0), sp(16, 20, 0))),
		v(vSeqRnd2, "seq_x_rnd_r2", H, 1200,
			side(both, 0, 16, 32, ladderPPS, sd(2, 0, 0)),
			side(send, 100, 1, 64, ladderPPS, sp(64, 100, 0))),
		v(vSeqRnd3, "seq_x_rnd_r3", H, 3000,
			side(both, 0, 32, 64, ladderPPS, sd(2, 0, 0)),
			side(both, 0, 1, 384, ladderBirthdayPPS, sp(192, 0, 0), sr(192, 0, 0))),

		// ---- rnd_x_rnd; r3 is the two-sided birthday, extreme only ----
		v(vRndRnd1, "rnd_x_rnd_r1", L, 800,
			side(both, 0, 1, 5, ladderPPS, sd(5, 0, 0)),
			side(both, 0, 1, 5, ladderPPS, sd(5, 0, 0))),
		v(vRndRnd2, "rnd_x_rnd_r2", B, 1200,
			side(both, 0, 8, 48, ladderPPS, sd(2, 0, 0), sp(32, 0, 0)),
			side(both, 0, 8, 48, ladderPPS, sd(2, 0, 0), sp(32, 0, 0))),
		v(vRndRnd3, "rnd_x_rnd_r3_birthday_both", X, 3000,
			side(both, 0, 16, 256, ladderBirthdayPPS, sr(256, 0, 0)),
			side(both, 0, 16, 256, ladderBirthdayPPS, sr(256, 0, 0))),

		// ---- fresh sockets: pdf_x_pres and pres_x_pres ----
		// Both sides carry the same template: the side keeping fresh ports
		// binds the sockets (on top of its primary), its peer aims at them.
		// pres_r1 fits balanced's 8 sockets, pres_r2 heavy's 32. Both
		// primaries also punch each other as plain hole punching would,
		// D(3).
		v(vPres1, "pres_r1", B, 1500,
			side(both, 0, 1, 24, ladderPPS, sd(3, 0, 0), sfr(7, 3, 0)),
			side(both, 0, 1, 24, ladderPPS, sd(3, 0, 0), sfr(7, 3, 0))),
		v(vPres2, "pres_r2", H, 2500,
			side(both, 0, 1, 75, ladderPPS, sd(3, 0, 0), sfr(24, 3, 0)),
			side(both, 0, 1, 75, ladderPPS, sd(3, 0, 0), sfr(24, 3, 0))),

		// ---- slow birthday: pdf_x_rnd of a Background session ----
		// The RND side opens up to 120 sockets, 16 a second, each keeping
		// its mapping to the PDF side's endpoint alive with three packets
		// spread over the window; the PDF side sprays 1025 random ports at
		// 25 a second — below the scan detectors' 300 ports in 10 s — from
		// 4 s on, when half the sockets are open: P ≈ 1 − e^(−K·M/64512)
		// ≈ 85% in 45 s. 120 sockets, not the class's 128: the header's
		// socket index leaves 121 for round sockets.
		v(vPDFRndSlow, "pdf_x_rnd_slow", BG, 45000,
			slow(side(both, 0, 1, slowSpray, slowPPS, sr(slowSpray, slowStartMs, 0)), slowNPS, 0),
			slow(side(both, 0, slowSockets, slowSockets*3, slowPPS, sd(3, 0, 0)), 0, slowOpen)),
	} {
		m[x.id] = x
	}

	// Birthday annotations.
	annotate := func(id VariantID, tier protocol.BirthdayTier, extend bool, spr birthdaySide) {
		m[id].reqTier = tier
		m[id].extendWindow = extend
		m[id].sprayer = spr
	}
	// pdf_x_seq: r4 is the conservative one-sided birthday (fixed 3 s window,
	// grant clamped); r5 the balanced one with its window extended to fit 512
	// targets.
	annotate(vPDFSeq4, protocol.BirthdayConservative, false, bsA)
	annotate(vPDFSeq5, protocol.BirthdayBalanced, true, bsA)
	// pdf_x_rnd: r2 the conservative one-sided birthday (window extends to 4 s
	// for 384 targets), r3 the sliding-window remainder (fixed window), r4 the
	// balanced one-sided birthday.
	annotate(vPDFRnd2, protocol.BirthdayConservative, true, bsA)
	annotate(vPDFRnd3, protocol.BirthdayConservative, false, bsA)
	annotate(vPDFRnd4, protocol.BirthdayBalanced, true, bsA)
	// The slow birthday sprays from the PDF side: the default tier admits
	// it, its window is fixed.
	annotate(vPDFRndSlow, protocol.BirthdayConservative, false, bsA)
	// seq_x_rnd r3 emits 384 targets: window extends, but it is a heavy
	// prediction round, not tier-gated.
	annotate(vSeqRnd3, "", true, bsNone)
	// rnd_x_rnd r3 is the two-sided birthday: aggressive tier, AllowExtreme and a
	// handshake of at least 30 s.
	annotate(vRndRnd3, protocol.BirthdayAggressive, true, bsBoth)
	m[vRndRnd3].twoSided = true
	m[vRndRnd3].minHandshakeMs = 30000
	// easy r3 exchanges the roles of an OPEN×OPEN pair only.
	m[vEasy3].swapIfOpen = true

	// rescue round: the side that saw a packet becomes sender to the
	// real seen_from source (d=80); the silent side is a low-TTL receiver.
	m[vRescue] = variant{id: vRescue, name: "rescue", budget: L, windowMs: 1500,
		a: side(send, 80, 1, 24, ladderPPS, sd(3, 80, 0)),
		b: side(recv, 0, 1, 24, ladderPPS, sd(3, 0, 4))}
	return m
}

// variantClasses returns the per-variant BudgetClass for a ladder, used by
// Classification.Budgets.
func variantClasses(ladder []VariantID) map[VariantID]protocol.BudgetClass {
	out := make(map[VariantID]protocol.BudgetClass, len(ladder))
	for _, id := range ladder {
		if vr, ok := variantOf(id); ok {
			out[id] = vr.budget
		}
	}
	return out
}

package plan

import (
	"math"
	"math/big"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/protocol"
)

// Regression tests for planner defects, each asserting the fixed behaviour.

func maxSock(sides []protocol.FamilySide) int {
	m := 0
	for _, fs := range sides {
		if int(fs.Sockets) > m {
			m = int(fs.Sockets)
		}
	}
	return m
}

func sumField(sides []protocol.FamilySide, f func(protocol.FamilySide) int) int {
	n := 0
	for _, fs := range sides {
		n += f(fs)
	}
	return n
}

// BirthdayTier gates the birthday rounds. With tier conservative the
// balanced/aggressive birthday rounds must not run; with tier off the
// conservative one-sided birthday must not run.
func TestBirthdayTierGate(t *testing.T) {
	f := protocol.FamilyUDP4
	var p DefaultPlanner
	// tier conservative + AllowExtreme: pdf_x_seq r5 (balanced one-sided birthday) unreachable.
	cl := p.Classify(classifyInput(pdfTraits(f), seqTraits(f)))
	prev := []RoundOutcome{
		{Round: 1, Variant: vPDFSeq1, Class: RCNoContact, Budget: protocol.BudgetBalanced},
		{Round: 2, Variant: vPDFSeq2, Class: RCNoContact, Budget: protocol.BudgetBalanced},
		{Round: 3, Variant: vPDFSeq3, Class: RCNoContact, Budget: protocol.BudgetHeavy},
		{Round: 4, Variant: vPDFSeq4, Class: RCNoContact, Budget: protocol.BudgetHeavy},
	}
	in := roundInput(cl, pdfTraits(f), seqTraits(f), 5, prev)
	in.AllowExtreme = true
	in.MaxRounds = 6
	in.Policy.Budget.Birthday = protocol.BirthdayConservative
	if dec := p.Round(in); dec.Stop == "" && dec.Variant == vPDFSeq5 {
		t.Errorf("pdf_x_seq r5 (balanced one-sided birthday) ran at tier conservative: %s", dec.VariantName)
	}

	// pdf_x_rnd r4 (balanced one-sided birthday) unreachable at conservative.
	clr := p.Classify(classifyInput(pdfTraits(f), rndTraits(f)))
	prevr := []RoundOutcome{
		{Round: 1, Variant: vPDFRnd1, Class: RCNoContact, Budget: protocol.BudgetBalanced},
		{Round: 2, Variant: vPDFRnd2, Class: RCNoContact, Budget: protocol.BudgetHeavy},
		{Round: 3, Variant: vPDFRnd3, Class: RCNoContact, Budget: protocol.BudgetHeavy},
	}
	in4 := roundInput(clr, pdfTraits(f), rndTraits(f), 4, prevr)
	in4.AllowExtreme = true
	in4.MaxRounds = 6
	in4.Policy.Budget.Birthday = protocol.BirthdayConservative
	if dec := p.Round(in4); dec.Stop == "" && dec.Variant == vPDFRnd4 {
		t.Errorf("pdf_x_rnd r4 (balanced one-sided birthday) ran at tier conservative: %s", dec.VariantName)
	}

	// rnd_x_rnd r3 unreachable at conservative even with AllowExtreme.
	clrr := p.Classify(classifyInput(rndTraits(f), rndTraits(f)))
	in3 := roundInput(clrr, rndTraits(f), rndTraits(f), 3, []RoundOutcome{
		{Round: 1, Variant: vRndRnd1, Class: RCNoContact, Budget: protocol.BudgetLight},
		{Round: 2, Variant: vRndRnd2, Class: RCNoContact, Budget: protocol.BudgetBalanced},
	})
	in3.AllowExtreme = true
	in3.MaxRounds = 6
	in3.HandshakeMs = 40000
	in3.Policy.Budget.Birthday = protocol.BirthdayConservative
	if dec := p.Round(in3); dec.Stop == "" && dec.Variant == vRndRnd3 {
		t.Errorf("rnd_x_rnd two-sided birthday ran without aggressive tier: %s", dec.VariantName)
	}

	// tier off: pdf_x_rnd r2 (conservative one-sided birthday) must not run.
	in2 := roundInput(clr, pdfTraits(f), rndTraits(f), 2, []RoundOutcome{{Round: 1, Variant: vPDFRnd1, Class: RCNoContact, Budget: protocol.BudgetBalanced}})
	in2.Policy.Budget.Birthday = protocol.BirthdayOff
	if dec := p.Round(in2); dec.Stop == "" && dec.Variant == vPDFRnd2 {
		t.Errorf("pdf_x_rnd r2 one-sided birthday ran at tier off: %s sockets=%d", dec.VariantName, maxSock(dec.Sides[1]))
	}
}

// A PDF side with Unknown filtering must not open a birthday round.
func TestUnknownFilteringNoBirthday(t *testing.T) {
	f := protocol.FamilyUDP4
	a := pdfTraits(f)
	a.Filtering, a.FilteringConf = protocol.FiltUnknown, protocol.ConfNone
	b := rndTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 2, []RoundOutcome{{Round: 1, Variant: vPDFRnd1, Class: RCNoContact, Budget: protocol.BudgetBalanced}})
	in.Policy.Budget.Birthday = protocol.BirthdayConservative
	dec := p.Round(in)
	if dec.Stop == "" && dec.Variant == vPDFRnd2 {
		t.Errorf("PDF side with unknown filtering ran one-sided birthday round %s", dec.VariantName)
	}
}

// A side left without active stages (Blocked) degrades to reply_only with
// one reply_only stage, and the resulting punch_go marshals.
func TestReplyOnlyMarshals(t *testing.T) {
	f := protocol.FamilyUDP4
	var p DefaultPlanner
	cl := p.Classify(classifyInput(pdfTraits(f), seqTraits(f)))
	in := roundInput(cl, pdfTraits(f), seqTraits(f), 2, []RoundOutcome{{Round: 1, Variant: vPDFSeq1, Class: RCBlocked, Budget: protocol.BudgetBalanced}})
	in.Evidence.ICMPUnreach = [2]uint16{80, 0}
	dec := p.Round(in)
	if dec.Stop != "" {
		t.Skipf("stopped (%s) — no stages anywhere is also valid", dec.Stop)
	}
	for r := 0; r < 2; r++ {
		rp := protocol.RoundPlan{Round: 2, Variant: dec.VariantName, Budget: dec.Budget, WindowMs: uint16(dec.Window / time.Millisecond), Seed: 1, Sides: dec.Sides[r]}
		pg := protocol.PunchGo{SessionID: "s1", Round: 2, WindowMs: rp.WindowMs, Plan: &rp}
		if _, err := msgframe.Encode(pg); err != nil {
			t.Errorf("role %d (%s): punch_go does not marshal: %v", r, dec.Sides[r][0].Role, err)
		}
	}
}

// Dual stack — the two families' grants together stay within the class and
// session ceilings and BudgetLeft, and within the shared new-target bucket.
func TestDualStackBudgetMerged(t *testing.T) {
	a4, b4 := pdfTraits(protocol.FamilyUDP4), rndTraits(protocol.FamilyUDP4)
	a6, b6 := pdfTraits(protocol.FamilyUDP6), rndTraits(protocol.FamilyUDP6)
	var p DefaultPlanner
	ci := ClassifyInput{Initiator: dual(a4, a6), Responder: dual(b4, b6), Policy: protocol.Policy{Budget: protocol.DefaultBudget()}, Timeouts: protocol.DefaultTimeouts()}
	cl := p.Classify(ci)
	if len(cl.Families) != 2 {
		t.Fatalf("expected 2 families, got %v", cl.Families)
	}
	in := roundInput(cl, a4, b4, 2, []RoundOutcome{{Round: 1, Variant: vPDFRnd1, Class: RCNoContact, Budget: protocol.BudgetBalanced}})
	in.Views = [2]protocol.PeerView{dual(a4, a6), dual(b4, b6)}
	in.BudgetLeft = [2]int{500, 500}
	dec := p.Round(in)
	if dec.Stop != "" {
		t.Fatalf("stopped: %s", dec.Stop)
	}
	lim, _ := dec.Budget.Limits()
	sess := protocol.DefaultBudget()
	emit := effNPS0(sess)*int(dec.Window/time.Millisecond)/1000 + 16
	for r := 0; r < 2; r++ {
		socks := sumField(dec.Sides[r], func(fs protocol.FamilySide) int { return int(fs.Sockets) })
		pk := sumField(dec.Sides[r], func(fs protocol.FamilySide) int { return int(fs.MaxPackets) })
		spray := sumField(dec.Sides[r], sprayCount)
		if socks > int(lim.MaxSockets) || socks > int(sess.MaxSockets) {
			t.Errorf("role %d: %d sockets > class %d / session %d", r, socks, lim.MaxSockets, sess.MaxSockets)
		}
		if pk > in.BudgetLeft[r] {
			t.Errorf("role %d: %d packets > BudgetLeft %d", r, pk, in.BudgetLeft[r])
		}
		if spray > emit {
			t.Errorf("role %d: %d new targets across families > shared bucket %d", r, spray, emit)
		}
	}
}

// Per-family ladders — v6 OPEN×OPEN with v4 PDF×RND still gives v4 the
// pdf_x_rnd ladder. The primary (v6-first) family drives PairClass; v4 is a
// secondary family with its own plan.
func TestPerFamilyLadder(t *testing.T) {
	a4, b4 := pdfTraits(protocol.FamilyUDP4), rndTraits(protocol.FamilyUDP4)
	a6, b6 := openTraits(protocol.FamilyUDP6), openTraits(protocol.FamilyUDP6)
	var p DefaultPlanner
	ci := ClassifyInput{Initiator: dual(a4, a6), Responder: dual(b4, b6), Policy: protocol.Policy{Budget: protocol.DefaultBudget()}, Timeouts: protocol.DefaultTimeouts()}
	cl := p.Classify(ci)
	var v4 *familyPlan
	for i := range cl.fams {
		if cl.fams[i].Family == protocol.FamilyUDP4 {
			v4 = &cl.fams[i]
		}
	}
	if v4 == nil || v4.PairClass != PairPDFRnd {
		t.Fatalf("v4 family pair class = %v, want pdf_x_rnd", v4)
	}
}

// An extreme (or otherwise unreachable) variant reordered to the front by
// memory is skipped, not a reason to stop the session with zero packets.
func TestUnreachableVariantSkipped(t *testing.T) {
	f := protocol.FamilyUDP4
	var p DefaultPlanner
	cl := p.Classify(classifyInput(pdfTraits(f), rndTraits(f)))
	in := roundInput(cl, pdfTraits(f), rndTraits(f), 1, nil)
	in.Order = []VariantID{vPDFRnd4, vPDFRnd1, vPDFRnd2, vPDFRnd3} // extreme first
	in.AllowExtreme = false
	dec := p.Round(in)
	if dec.Stop != "" {
		t.Fatalf("round 1 stopped (%s) instead of skipping the unreachable extreme variant", dec.Stop)
	}
	if dec.Variant != vPDFRnd1 {
		t.Fatalf("round 1 chose %s, want the first reachable variant r1", dec.VariantName)
	}
}

// The escalation guard uses the previous round's actual granted class, so a
// light rescue is not a stepping stone to extreme.
func TestEscalationOnActualClass(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	prev := []RoundOutcome{
		{Round: 1, Variant: vPDFSeq1, Class: RCNoContact, Budget: protocol.BudgetBalanced},
		{Round: 2, Variant: vPDFSeq2, Class: RCNoContact, Budget: protocol.BudgetBalanced},
		{Round: 3, Variant: vPDFSeq3, Class: RCOneWay, Budget: protocol.BudgetHeavy},
	}
	var classes []protocol.BudgetClass
	for round := 4; round <= 6; round++ {
		in := roundInput(cl, a, b, round, prev)
		in.AllowExtreme = true
		in.MaxRounds = 6
		in.RescueUsed = round > 4
		in.Policy.Budget.Birthday = protocol.BirthdayBalanced
		dec := p.Round(in)
		if dec.Stop != "" {
			break
		}
		classes = append(classes, dec.Budget)
		prev = append(prev, RoundOutcome{Round: round, Variant: dec.Variant, Class: RCNoContact, Rescue: dec.Rescue, Budget: dec.Budget})
	}
	for i := 1; i < len(classes); i++ {
		if classes[i].Rank() > classes[i-1].Rank()+1 {
			t.Errorf("effective class jumped %s -> %s between adjacent rounds", classes[i-1], classes[i])
		}
	}
}

// Heavy at round 2 requires random-EDM evidence; pdf_x_seq (no RND) forced
// to a heavy variant at round 2 is capped to balanced.
func TestHeavyRound2NeedsRandomEDM(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 2, []RoundOutcome{{Round: 1, Variant: vPDFSeq2, Class: RCNoContact, Budget: protocol.BudgetBalanced}})
	in.Order = []VariantID{vPDFSeq2, vPDFSeq3, vPDFSeq4, vPDFSeq5, vPDFSeq1}
	if dec := p.Round(in); dec.Budget == protocol.BudgetHeavy {
		t.Errorf("pdf_x_seq (no random EDM) round 2 granted heavy (%s)", dec.VariantName)
	}
}

// The first round never exceeds Ladder[0]'s class without memory promotion.
func TestFirstRoundNotAboveLadder0(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := openTraits(f), rndTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b)) // open_x_edm, Ladder[0] is light
	in := roundInput(cl, a, b, 1, nil)
	in.Order = []VariantID{vOpenEDM3, vOpenEDM4, vOpenEDM1, vOpenEDM2}
	if dec := p.Round(in); dec.Budget.Rank() > protocol.BudgetLight.Rank() {
		t.Errorf("round 1 granted %s, Ladder[0] is light and MemoryPromoted=false", dec.Budget)
	}
}

// A memory-promoted heavy variant may run in the first round.
func TestMemoryPromotedFirstRound(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	order := []VariantID{vPDFSeq3} // heavy variant promoted to the front

	capped := roundInput(cl, a, b, 1, nil)
	capped.Order = order
	if dec := p.Round(capped); dec.Budget != protocol.BudgetBalanced {
		t.Fatalf("without promotion round 1 = %q, want balanced (capped)", dec.Budget)
	}
	promoted := roundInput(cl, a, b, 1, nil)
	promoted.Order = order
	promoted.MemoryPromoted = true
	if dec := p.Round(promoted); dec.Budget != protocol.BudgetHeavy {
		t.Fatalf("with promotion round 1 = %q, want heavy", dec.Budget)
	}
}

// The grant is computed after the window is clamped by Remaining, so the
// granted new targets never exceed the emittable count.
func TestGrantAfterWindowClamp(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	prev := []RoundOutcome{
		{Round: 1, Variant: vPDFSeq1, Class: RCNoContact, Budget: protocol.BudgetBalanced},
		{Round: 2, Variant: vPDFSeq2, Class: RCNoContact, Budget: protocol.BudgetBalanced},
		{Round: 3, Variant: vPDFSeq3, Class: RCNoContact, Budget: protocol.BudgetHeavy},
	}
	in := roundInput(cl, a, b, 4, prev)
	in.Remaining = 1500 * time.Millisecond
	in.D = 0
	dec := p.Round(in)
	if dec.Stop != "" {
		t.Fatalf("stopped: %s", dec.Stop)
	}
	for r := 0; r < 2; r++ {
		for _, fs := range dec.Sides[r] {
			g := sprayCount(fs)
			emit := int(fs.MaxNewPerSec)*int(dec.Window/time.Millisecond)/1000 + 16
			if g > emit {
				t.Errorf("role %d: window %v granted %d > emittable %d", r, dec.Window, g, emit)
			}
		}
	}
}

// A one-sided birthday round extends its window as max_new_per_sec tightens,
// so the full 384-target set is still granted.
func TestOneSidedBirthdayWindowExtends(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), rndTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 2, []RoundOutcome{{Round: 1, Variant: vPDFRnd1, Class: RCNoContact, Budget: protocol.BudgetBalanced}})
	in.Policy.Budget.MaxNewPerSec = 50
	dec := p.Round(in)
	g := sumField(dec.Sides[0], sprayCount)
	if g < 384 {
		t.Errorf("one-sided birthday round at nps=50: window %v grant %d < 384 (window must extend)", dec.Window, g)
	}
	// window must be at least ceil((384-16)/50) = 8 s.
	if dec.Window < 7360*time.Millisecond {
		t.Errorf("one-sided birthday window %v too short for 384 targets at nps=50", dec.Window)
	}
}

// A random grant on a pool smaller than the ladder count is capped
// to the expandable range.
func TestPoolRangeCapsGrant(t *testing.T) {
	f := protocol.FamilyUDP4
	a := pdfTraits(f)
	b := rndTraits(f)
	b.PortAlloc, b.PortAllocConf, b.PortRangeLo, b.PortRangeHi = protocol.AllocPool, protocol.ConfLow, 40000, 40099
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 2, []RoundOutcome{{Round: 1, Variant: vPDFRnd1, Class: RCNoContact, Budget: protocol.BudgetBalanced}})
	dec := p.Round(in)
	for _, fs := range dec.Sides[0] {
		for i, st := range fs.Stages {
			if st.Kind != protocol.StageRandom {
				continue
			}
			got := ExpandRandom(st.Lo, st.Hi, int(st.Count), ExpandInput{Seed: [8]byte{1}, StageIndex: i})
			if len(got) < int(st.Count) {
				t.Errorf("random [%d,%d] count %d > expandable %d", st.Lo, st.Hi, st.Count, len(got))
			}
		}
	}
}

// This round's Direct targets count toward the distinct-port budget,
// so direct + spray stays within the class ports minus the 10 s window usage.
func TestDirectCountedInDistinct(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	vb := view(b)
	for i := 0; i < 7; i++ {
		vb.Families[0].Endpoints = append(vb.Families[0].Endpoints, protocol.Endpoint{Addr: netip.AddrPortFrom(b.Observed.Addr(), uint16(41000+i)), Source: protocol.EndpointServer, Verified: true})
	}
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 1, nil)
	in.Views[1] = vb
	in.Recent10sDistinct = [2]int{50, 0} // balanced 64 -> 14 ports left
	dec := p.Round(in)
	fs := dec.Sides[0][0]
	direct := 0
	for _, st := range fs.Stages {
		direct += len(st.Targets)
	}
	total := direct + sprayCount(fs)
	if total > 64-50 {
		t.Errorf("10 s window has %d ports left; granted %d direct + %d spray = %d", 64-50, direct, sprayCount(fs), total)
	}
}

// Final does not count the rescue round against max_rounds.
func TestFinalExcludesRescue(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := openTraits(f), openTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	prev := []RoundOutcome{
		{Round: 1, Variant: vEasy1, Class: RCNoContact, Budget: protocol.BudgetLight},
		{Round: 2, Variant: vEasy2, Class: RCOneWay, Budget: protocol.BudgetLight},
		{Round: 3, Variant: vRescue, Class: RCNoContact, Rescue: true, Budget: protocol.BudgetLight},
		{Round: 4, Variant: vEasy3, Class: RCNoContact, Budget: protocol.BudgetLight},
	}
	in := roundInput(cl, a, b, 5, prev)
	in.RescueUsed = true
	in.MaxRounds = 5
	dec := p.Round(in)
	if dec.Final {
		t.Errorf("round 5 (%s) is only the 4th non-rescue round of max_rounds=5 but Final=true", dec.VariantName)
	}
	if dec.Variant != vEasy4 {
		t.Errorf("round 5 variant = %s, want easy r4", dec.VariantName)
	}
}

// A ConfirmLost repeat does not skip a ladder step.
func TestConfirmLostNoSkip(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := openTraits(f), openTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	prev := []RoundOutcome{
		{Round: 1, Variant: vEasy1, Class: RCConfirmLost, Budget: protocol.BudgetLight},
		{Round: 2, Variant: vEasy1, Class: RCNoContact, Budget: protocol.BudgetLight},
	}
	dec := p.Round(roundInput(cl, a, b, 3, prev))
	if dec.Variant != vEasy2 {
		t.Errorf("after easy1 ConfirmLost -> easy1 -> NoContact, round 3 is %s, want easy r2", dec.VariantName)
	}
}

func TestConfirmLostRepeatsVariant(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := openTraits(f), openTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	r1 := p.Round(roundInput(cl, a, b, 1, nil))
	dec := p.Round(roundInput(cl, a, b, 2, []RoundOutcome{{Round: 1, Variant: r1.Variant, Class: RCConfirmLost, Budget: r1.Budget}}))
	if dec.Variant != r1.Variant {
		t.Fatalf("ConfirmLost variant %s, want same as r1 %s", dec.VariantName, r1.VariantName)
	}
}

// A Blocked round drops predict/random for every later round, not just the
// immediately following one.
func TestBlockedPersists(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	prev := []RoundOutcome{
		{Round: 1, Variant: vPDFSeq1, Class: RCBlocked, Budget: protocol.BudgetBalanced},
		{Round: 2, Variant: vPDFSeq2, Class: RCNoContact, Budget: protocol.BudgetBalanced},
	}
	in := roundInput(cl, a, b, 3, prev)
	in.Evidence.ICMPUnreach = [2]uint16{80, 0}
	dec := p.Round(in)
	if dec.Stop != "" {
		return
	}
	for r := 0; r < 2; r++ {
		for _, fs := range dec.Sides[r] {
			if sprayCount(fs) > 0 {
				t.Errorf("round 3 after a Blocked round still sprays %d ports", sprayCount(fs))
			}
		}
	}
}

// A MultiExit peer gets Direct to every verified exit IP.
func TestMultiExitAllIPs(t *testing.T) {
	f := protocol.FamilyUDP4
	a := pdfTraits(f)
	b := pdfTraits(f)
	b.Mapping, b.MappingConf, b.MultiExit = protocol.MapUnknown, protocol.ConfLow, true
	vb := view(b)
	vb.Families[0].Endpoints = append(vb.Families[0].Endpoints, protocol.Endpoint{Addr: netip.MustParseAddrPort("198.51.100.77:40002"), Source: protocol.EndpointServer, Verified: true})
	var p DefaultPlanner
	ci := classifyInput(a, b)
	ci.Responder = vb
	cl := p.Classify(ci)
	in := roundInput(cl, a, b, 1, nil)
	in.Views[1] = vb
	dec := p.Round(in)
	ips := map[netip.Addr]bool{}
	for _, fs := range dec.Sides[0] {
		for _, st := range fs.Stages {
			for _, tg := range st.Targets {
				ips[tg.Addr()] = true
			}
		}
	}
	if len(ips) < 2 {
		t.Errorf("initiator Direct covers %d IP(s) of a 2-exit MultiExit peer", len(ips))
	}
}

// Bind_failed > sockets/2 last round forces a single socket from then on. A
// forced side runs the variants that need one socket only.
func TestBindFailedSingleSocket(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := seqTraits(f), rndTraits(f) // seq_x_rnd: the RND side never needs more than one socket
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	prev := []RoundOutcome{{Round: 1, Variant: vSeqRnd1, Class: RCNoContact, Budget: protocol.BudgetBalanced}}
	in := roundInput(cl, a, b, 2, prev)
	in.Evidence.BindFailed = [2]uint16{0, 1} // the responder failed its only socket last round
	dec := p.Round(in)
	if dec.Stop != "" || dec.Variant != vSeqRnd2 {
		t.Fatalf("round 2: %s stop %q", dec.VariantName, dec.Stop)
	}
	if s := dec.Sides[1][0].Sockets; s != 1 {
		t.Errorf("responder with bind failures asks for %d sockets", s)
	}
}

// Budget_hit with no candidate and a not-lower next round stops.
func TestBudgetHitStops(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	prev := []RoundOutcome{
		{Round: 1, Variant: vPDFSeq1, Class: RCNoContact, Budget: protocol.BudgetBalanced},
		{Round: 2, Variant: vPDFSeq2, Class: RCNoContact, Budget: protocol.BudgetBalanced},
		{Round: 3, Variant: vPDFSeq3, Class: RCNoContact, Budget: protocol.BudgetHeavy},
	}
	in := roundInput(cl, a, b, 4, prev)
	in.Evidence.BudgetHit = [2]bool{true, false}
	in.Evidence.Sent = [2]uint32{195, 28}
	in.Evidence.Fired = [2]bool{true, true}
	if dec := p.Round(in); dec.Stop == "" {
		t.Errorf("budget_hit with no candidate and heavier next round: got %s, want packet_budget_exceeded", dec.VariantName)
	}
}

// An EIM/Medium peer gets a small fallback spray in the first round.
func TestMediumConfFallback(t *testing.T) {
	f := protocol.FamilyUDP4
	a := pdfTraits(f)
	b := pdfTraits(f)
	b.MappingConf = protocol.ConfMedium
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	dec := p.Round(roundInput(cl, a, b, 1, nil))
	if sumField(dec.Sides[0], sprayCount) == 0 {
		t.Errorf("%s r1 against an EIM/Medium peer has no fallback spray", dec.VariantName)
	}
}

// In PDF×OPEN the PDF side is never a sender.
func TestPDFOpenReceiver(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := openTraits(f), pdfTraits(f) // responder = PDF
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	var prev []RoundOutcome
	for round := 1; round <= 5; round++ {
		dec := p.Round(roundInput(cl, a, b, round, prev))
		if dec.Stop != "" {
			break
		}
		if dec.Sides[1][0].Role == protocol.SideSender {
			t.Errorf("round %d (%s): PDF side is sender", round, dec.VariantName)
		}
		prev = append(prev, RoundOutcome{Round: round, Variant: dec.Variant, Class: RCNoContact, Budget: dec.Budget})
		if dec.Final {
			break
		}
	}
}

// Without AllowExtreme the ladder ends before any extreme round.
func TestExtremeGate(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	for _, dec := range chain(p, cl, a, b, 6, false, RCNoContact, func(in *RoundInput) { in.MaxRounds = 6 }) {
		if dec.Budget == protocol.BudgetExtreme {
			t.Fatal("extreme round reached without AllowExtreme")
		}
	}
}

// Every default-ladder decision marshals in the message that carries it
// (probe_summary for round 1, punch_go after) and is not changed by the
// client's protocol Normalize (a clamp would mean a planner/protocol
// mismatch). Covers valid variant names and encoded size <= Cap.
func TestSweepMarshal(t *testing.T) {
	f := protocol.FamilyUDP4
	combos := map[string][2]protocol.Traits{
		"easy": {openTraits(f), pdfTraits(f)}, "open_x_edm": {openTraits(f), rndTraits(f)},
		"pdf_x_seq": {pdfTraits(f), seqTraits(f)}, "pdf_x_rnd": {pdfTraits(f), rndTraits(f)},
		"seq_x_seq": {seqTraits(f), seqTraits(f)}, "seq_x_rnd": {seqTraits(f), rndTraits(f)},
		"rnd_x_rnd": {rndTraits(f), rndTraits(f)},
	}
	var p DefaultPlanner
	for name, c := range combos {
		for _, ext := range []bool{false, true} {
			cl := p.Classify(classifyInput(c[0], c[1]))
			var prev []RoundOutcome
			for round := 1; round <= 6; round++ {
				in := roundInput(cl, c[0], c[1], round, prev)
				in.AllowExtreme, in.MaxRounds = ext, 6
				in.Policy.Budget.Birthday = protocol.BirthdayAggressive
				in.HandshakeMs = 40000
				dec := p.Round(in)
				if dec.Stop != "" {
					break
				}
				for r := 0; r < 2; r++ {
					rp := protocol.RoundPlan{Round: uint8(round), Variant: dec.VariantName, Budget: dec.Budget, WindowMs: uint16(dec.Window / time.Millisecond), Seed: 1, Sides: dec.Sides[r]}
					msg, clamped := carrier(rp)
					if _, err := msgframe.Encode(msg); err != nil {
						t.Errorf("%s ext=%v r%d role %d: %v", name, ext, round, r, err)
					}
					if clamped {
						t.Errorf("%s ext=%v r%d role %d: client Normalize clamps the plan", name, ext, round, r)
					}
				}
				prev = append(prev, RoundOutcome{Round: round, Variant: dec.Variant, Class: RCNoContact, Budget: dec.Budget})
				if dec.Final {
					break
				}
			}
		}
	}
}

// assertEmittable checks on every side of a decision that what the stages
// expand to never exceeds the MaxPackets granted, which equals what they ask.
func assertEmittable(t *testing.T, dec RoundDecision) {
	t.Helper()
	for r := range 2 {
		for _, fs := range dec.Sides[r] {
			if need, got := stagePackets(fs), expandedPackets(fs); need != int(fs.MaxPackets) || got > int(fs.MaxPackets) {
				t.Errorf("%s role %d: stages ask %d, expand to %d, MaxPackets %d: %s", dec.VariantName, r, need, got, fs.MaxPackets, describe(fs))
			}
		}
	}
}

// honestEvidence is what an honest client reports after dec: it fired, sent
// what its stages expand to, and reports budget_hit when
// the stages needed more than MaxPackets.
func honestEvidence(dec RoundDecision) Evidence {
	var ev Evidence
	for r := range 2 {
		ev.Fired[r] = true
		for _, fs := range dec.Sides[r] {
			n := expandedPackets(fs)
			ev.Sent[r] += uint32(min(n, int(fs.MaxPackets)))
			ev.BudgetHit[r] = ev.BudgetHit[r] || n > int(fs.MaxPackets)
		}
	}
	return ev
}

func outcomeOf(round int, dec RoundDecision, class RoundClass) RoundOutcome {
	return RoundOutcome{Round: round, Variant: dec.Variant, Class: class, Rescue: dec.Rescue, Budget: dec.Budget, Families: dec.Families}
}

// The Medium-confidence fallback is part of the grant: every
// side of the first round can emit what its stages expand to.
func TestMediumFallbackEmittable(t *testing.T) {
	f := protocol.FamilyUDP4
	medOpen, medPDF := openTraits(f), pdfTraits(f)
	medOpen.MappingConf, medPDF.MappingConf = protocol.ConfMedium, protocol.ConfMedium
	var p DefaultPlanner
	for _, c := range [][2]protocol.Traits{{medOpen, rndTraits(f)}, {medPDF, seqTraits(f)}, {medPDF, rndTraits(f)}} {
		cl := p.Classify(classifyInput(c[0], c[1]))
		dec := p.Round(roundInput(cl, c[0], c[1], 1, nil))
		if dec.Stop != "" {
			t.Fatalf("%s: stop %s", cl.PairClass, dec.Stop)
		}
		if sumField(dec.Sides[1], sprayCount) == 0 {
			t.Fatalf("%s: the EDM side has no fallback toward the EIM/Medium peer", dec.VariantName)
		}
		assertEmittable(t, dec)
	}
}

// With an honest client the fallback no longer reports budget_hit, so
// the budget_hit rule does not end the session after round 1.
func TestMediumFallbackDoesNotEndSession(t *testing.T) {
	f := protocol.FamilyUDP4
	medPDF := pdfTraits(f)
	medPDF.MappingConf = protocol.ConfMedium
	var p DefaultPlanner
	for _, peer := range []protocol.Traits{seqTraits(f), rndTraits(f)} {
		cl := p.Classify(classifyInput(medPDF, peer))
		d1 := p.Round(roundInput(cl, medPDF, peer, 1, nil))
		in2 := roundInput(cl, medPDF, peer, 2, []RoundOutcome{outcomeOf(1, d1, RCNoContact)})
		in2.Evidence = honestEvidence(d1)
		if d2 := p.Round(in2); d2.Stop != "" {
			t.Fatalf("%s: stops after round 1 with %s (budget_hit %v)", cl.PairClass, d2.Stop, in2.Evidence.BudgetHit)
		}
	}
}

// A peer with several verified endpoints (primary, second socket,
// siblings) or several exits gets Direct targets that fit MaxPackets.
func TestDirectTargetsFitMaxPackets(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), rndTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 1, nil)
	vb := apdmView(b) // three mappings of the primary socket, three of the second
	for i, port := range []uint16{40020, 40030} {
		vb.Families[0].Endpoints = append(vb.Families[0].Endpoints, protocol.Endpoint{Addr: netip.AddrPortFrom(b.Observed.Addr(), port),
			Source: protocol.EndpointSibling, Socket: uint8(2 + i), Verified: true})
	}
	in.Views[1] = vb
	dec := p.Round(in)
	assertEmittable(t, dec)
	want := []netip.AddrPort{b.Observed, netip.AddrPortFrom(b.Observed.Addr(), b.Observed.Port()+10)}
	if got := dec.Sides[0][0].Stages[0].Targets; !slices.Equal(got, want) {
		t.Fatalf("PDF side aims at %v, want the first mapping of the primary and of the second socket %v", got, want)
	}
	// MultiExit: one target per exit IP, still emittable.
	b.Mapping, b.MappingConf, b.MultiExit = protocol.MapUnknown, protocol.ConfLow, true
	vb.Families[0].Traits = b
	vb.Families[0].Endpoints = append(vb.Families[0].Endpoints, protocol.Endpoint{Addr: netip.MustParseAddrPort("198.51.100.77:40002"),
		Source: protocol.EndpointServer, Socket: 0, Verified: true})
	ci := classifyInput(a, b)
	ci.Responder = vb
	cl = p.Classify(ci)
	in = roundInput(cl, a, b, 1, nil)
	in.Views[1] = vb
	dec = p.Round(in)
	assertEmittable(t, dec)
	ips := map[netip.Addr]bool{}
	for _, tg := range dec.Sides[0][0].Stages[0].Targets {
		ips[tg.Addr()] = true
	}
	if len(ips) != 2 || len(dec.Sides[0][0].Stages[0].Targets) != 2 {
		t.Fatalf("MultiExit Direct targets %v, want one per exit IP", dec.Sides[0][0].Stages[0].Targets)
	}
}

// The spray grant stays within the packet grant when BudgetLeft is
// low: the round's stages still expand to at most MaxPackets ≤ BudgetLeft.
func TestSprayGrantWithinPacketGrant(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	decs := chain(p, cl, a, b, 4, false, RCNoContact, func(in *RoundInput) {
		if in.Round == 4 {
			in.BudgetLeft = [2]int{100, 100}
		}
	})
	dec := decs[len(decs)-1]
	if dec.Stop != "" || dec.Variant != vPDFSeq4 {
		t.Fatalf("round 4: %s stop %q", dec.VariantName, dec.Stop)
	}
	assertEmittable(t, dec)
	for r := range 2 {
		if pk := sumField(dec.Sides[r], func(fs protocol.FamilySide) int { return int(fs.MaxPackets) }); pk > 100 {
			t.Fatalf("role %d granted %d > BudgetLeft 100", r, pk)
		}
	}
}

// The multi-socket side of a one-sided birthday round sends D(2) from every
// socket to every Direct target: sockets × targets × repeats fits MaxPackets,
// and the receiver aims at the sprayer's own socket only.
func TestMultiSocketDirectFitsMaxPackets(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), rndTraits(f)
	va := siblingView(a) // two sibling sockets of the PDF side
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	decs := chain(p, cl, a, b, 2, false, RCNoContact, func(in *RoundInput) { in.Views[0] = va })
	dec := decs[len(decs)-1]
	if dec.Variant != vPDFRnd2 {
		t.Fatalf("round 2 is %s", dec.VariantName)
	}
	assertEmittable(t, dec)
	recv := dec.Sides[1][0]
	if recv.Sockets != 32 || len(recv.Stages[0].Targets) != 1 || recv.Stages[0].Targets[0] != a.Observed || recv.MaxPackets != 64 {
		t.Fatalf("one-sided birthday receiver %s, want 32 sockets × D(2) to the sprayer's observed", describe(recv))
	}
	// A peer with a second socket gets both mappings; with a tight budget
	// the receiver keeps its sockets and drops targets and repeats first.
	va = apdmView(a)
	decs = chain(p, cl, a, b, 2, false, RCNoContact, func(in *RoundInput) {
		in.Views[0] = va
		if in.Round == 2 {
			in.BudgetLeft = [2]int{3000, 70}
		}
	})
	dec = decs[len(decs)-1]
	assertEmittable(t, dec)
	if recv := dec.Sides[1][0]; recv.Sockets != 32 || recv.MaxPackets > 70 || len(recv.Stages[0].Targets) != 1 || recv.Stages[0].Repeats != 2 {
		t.Fatalf("tight budget: %s", describe(recv))
	}
}

// With the endpoint set natprobe really hands over for an APDM peer,
// and an honest client, no EDM ladder ends after round 1: every ladder runs
// to its last reachable round with every side emittable.
func TestRealisticAPDMRunsLadder(t *testing.T) {
	f := protocol.FamilyUDP4
	cases := []struct {
		a, b protocol.Traits
		want int // rounds at the default tier
	}{
		{openTraits(f), rndTraits(f), 4},
		{pdfTraits(f), seqTraits(f), 4},
		{pdfTraits(f), rndTraits(f), 3},
		{seqTraits(f), rndTraits(f), 3},
		{seqTraits(f), seqTraits(f), 3},
		{rndTraits(f), rndTraits(f), 2},
	}
	var p DefaultPlanner
	for _, c := range cases {
		views := [2]protocol.PeerView{realisticView(c.a), realisticView(c.b)}
		ci := classifyInput(c.a, c.b)
		ci.Initiator, ci.Responder = views[0], views[1]
		cl := p.Classify(ci)
		var prev []RoundOutcome
		var ev Evidence
		rounds := 0
		for round := 1; round <= 6; round++ {
			in := roundInput(cl, c.a, c.b, round, prev)
			in.Views, in.Evidence, in.MaxRounds = views, ev, 6
			dec := p.Round(in)
			if dec.Stop != "" {
				break
			}
			rounds++
			assertEmittable(t, dec)
			ev = honestEvidence(dec)
			prev = append(prev, outcomeOf(round, dec, RCNoContact))
			if dec.Final {
				break
			}
		}
		if rounds != c.want {
			t.Fatalf("%s: %d rounds ran, want %d", cl.PairClass, rounds, c.want)
		}
	}
}

// A sequential peer's predicted window is centred on its port
// extrapolated to the fire time: anchor + velocity·(FireAt − PortAnchorMs).
func TestSEQPredictionExtrapolates(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	b.PortVelocity, b.PortAnchorMs = 20, 1000 // a busy CGNAT: 20 ports/s
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	predict := func(fireAt time.Duration) protocol.Stage {
		in := roundInput(cl, a, b, 1, nil)
		in.FireAt = fireAt
		for _, st := range p.Round(in).Sides[0][0].Stages {
			if st.Kind == protocol.StagePredict {
				return st
			}
		}
		t.Fatal("no predict stage")
		return protocol.Stage{}
	}
	if st := predict(0); st.Anchor != b.PortAnchor {
		t.Fatalf("FireAt unknown: anchor %d, want the probe anchor %d", st.Anchor, b.PortAnchor)
	}
	st := predict(4 * time.Second) // 3 s after the anchor: +60
	if want := b.PortAnchor + 60; st.Anchor != want {
		t.Fatalf("anchor %d, want %d", st.Anchor, want)
	}
	// The first predicted ports are the step after the extrapolated anchor.
	ports := ExpandPredict(st.Anchor, st.Steps, int(st.Span), ExpandInput{Seed: [8]byte{1}})
	if !slices.Contains(ports, b.PortAnchor+61) {
		t.Fatalf("predicted ports %v miss anchor+v·Δt+step %d", ports, b.PortAnchor+61)
	}
	// The window covers 2·(|v|·σ_t + |step|) with σ_t = D.
	in := roundInput(cl, a, b, 1, nil)
	in.FireAt, in.D = 4*time.Second, time.Second
	for _, st := range p.Round(in).Sides[0][0].Stages {
		if st.Kind == protocol.StagePredict && st.Span < 42 {
			t.Fatalf("span %d < 2·(20·1 + 1)", st.Span)
		}
	}
	// A negative step extrapolates downward.
	b.PortStep, b.PortVelocity = -1, -20
	cl = p.Classify(classifyInput(a, b))
	if st := predict(4 * time.Second); st.Anchor != b.PortAnchor-60 {
		t.Fatalf("descending: anchor %d, want %d", st.Anchor, b.PortAnchor-60)
	}
}

// A mapping of the sequential peer seen while punching,
// later than the probe anchor, becomes the anchor and re-estimates the
// velocity from the gap minus the peer's own allocation.
func TestSEQPredictionFromPunchSamples(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	b.PortAnchor, b.PortAnchorMs, b.PortVelocity = 50003, 1000, 0
	b.Observed = netip.AddrPortFrom(b.Observed.Addr(), 50003)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	in := roundInput(cl, a, b, 1, nil)
	in.FireAt = 4 * time.Second
	// At 3 s the peer's mapping toward us was 50 300: 296 ports by others in
	// 2 s besides its own one, 148 ports/s.
	in.Mappings[1] = []MappingSample{{Addr: netip.AddrPortFrom(b.Observed.Addr(), 50300), At: 3 * time.Second}}
	var anchor uint16
	for _, st := range p.Round(in).Sides[0][0].Stages {
		if st.Kind == protocol.StagePredict {
			anchor = st.Anchor
		}
	}
	if anchor != 50300+148 {
		t.Fatalf("anchor %d, want 50300 + 148·1 s = %d", anchor, 50300+148)
	}
	// A sample older than the anchor, or of another IP, changes nothing.
	in.Mappings[1] = []MappingSample{{Addr: netip.AddrPortFrom(b.Observed.Addr(), 50300), At: 500 * time.Millisecond},
		{Addr: netip.MustParseAddrPort("198.51.100.99:50900"), At: 3 * time.Second}}
	for _, st := range p.Round(in).Sides[0][0].Stages {
		if st.Kind == protocol.StagePredict && st.Anchor != 50003 {
			t.Fatalf("anchor %d moved by a stale or foreign sample", st.Anchor)
		}
	}
}

// The secondary family passes the BirthdayTier gate too: with
// birthday off, no family gets a birthday (random) stage.
func TestSecondaryFamilyTierGate(t *testing.T) {
	v6, v4 := protocol.FamilyUDP6, protocol.FamilyUDP4
	initV6, respV6 := openTraits(v6), openTraits(v6)
	respV6.Observed = observedFor(v6, 9)
	initV4, respV4 := pdfTraits(v4), rndTraits(v4)
	var p DefaultPlanner
	ci := ClassifyInput{Initiator: dual(initV4, initV6), Responder: dual(respV4, respV6), Policy: protocol.Policy{Budget: protocol.DefaultBudget()}}
	cl := p.Classify(ci)
	var prev []RoundOutcome
	for round := 1; round <= 6; round++ {
		in := roundInput(cl, initV4, respV4, round, prev)
		in.Views = [2]protocol.PeerView{dual(initV4, initV6), dual(respV4, respV6)}
		in.Policy.Budget.Birthday = protocol.BirthdayOff
		in.MaxRounds = 6
		dec := p.Round(in)
		if dec.Stop != "" {
			break
		}
		for r := range 2 {
			for _, fs := range dec.Sides[r] {
				for _, st := range fs.Stages {
					if st.Kind == protocol.StageRandom {
						t.Fatalf("round %d (%s) family %s: random stage with BirthdayTier=off", round, dec.VariantName, fs.Family)
					}
				}
			}
		}
		prev = append(prev, outcomeOf(round, dec, RCNoContact))
		if dec.Final {
			break
		}
	}
}

// Each family runs its own ladder to its end at its own class.
// v6 v6_direct (three rounds) and v4 pdf_x_seq (four at the default tier):
// the session runs four rounds, v4 reaches its heavy one-sided birthday
// round, and v6 only replies once its ladder is exhausted.
func TestSecondaryLadderRunsToEnd(t *testing.T) {
	v6, v4 := protocol.FamilyUDP6, protocol.FamilyUDP4
	initV6, respV6 := openTraits(v6), openTraits(v6)
	initV6.NoNAT, respV6.NoNAT = protocol.TriTrue, protocol.TriTrue
	respV6.Observed = observedFor(v6, 9)
	initV4, respV4 := pdfTraits(v4), seqTraits(v4)
	var p DefaultPlanner
	ci := ClassifyInput{Initiator: dual(initV4, initV6), Responder: dual(respV4, respV6), Policy: protocol.Policy{Budget: protocol.DefaultBudget()}}
	cl := p.Classify(ci)
	if cl.fams[0].PairClass != PairV6Direct || cl.fams[1].PairClass != PairPDFSeq {
		t.Fatalf("families %s/%s", cl.fams[0].PairClass, cl.fams[1].PairClass)
	}
	var prev []RoundOutcome
	var v4Variants []VariantID
	for round := 1; round <= 6; round++ {
		in := roundInput(cl, initV4, respV4, round, prev)
		in.Views = [2]protocol.PeerView{dual(initV4, initV6), dual(respV4, respV6)}
		in.MaxRounds = 6
		dec := p.Round(in)
		if dec.Stop != "" {
			break
		}
		assertEmittable(t, dec)
		v4Variants = append(v4Variants, dec.Families[1].Variant)
		if round == 4 {
			if dec.Families[0].Variant != VInvalid || dec.Sides[0][0].Role != protocol.SideReplyOnly {
				t.Fatalf("round 4: v6 runs %v (%s)", dec.Families[0].Variant, dec.Sides[0][0].Role)
			}
			if dec.Families[1].Budget != protocol.BudgetHeavy || dec.Budget != protocol.BudgetHeavy || dec.VariantName != "pdf_x_seq_r4_birthday" {
				t.Fatalf("round 4: %s at %s (v4 %s)", dec.VariantName, dec.Budget, dec.Families[1].Budget)
			}
			if span := sumField(dec.Sides[0][1:], sprayCount); span <= 16 {
				t.Fatalf("round 4: v4 one-sided birthday sprays only %d ports", span)
			}
		}
		prev = append(prev, outcomeOf(round, dec, RCNoContact))
		if dec.Final {
			break
		}
	}
	want := []VariantID{vPDFSeq1, vPDFSeq2, vPDFSeq3, vPDFSeq4}
	if !slices.Equal(v4Variants, want) {
		t.Fatalf("v4 ran %v, want %v", v4Variants, want)
	}
}

// A secondary ladder shorter than the primary is not repeated past its
// end: the family replies only.
func TestSecondaryLadderExhaustedRepliesOnly(t *testing.T) {
	v6, v4 := protocol.FamilyUDP6, protocol.FamilyUDP4
	initV6, respV6 := pdfTraits(v6), seqTraits(v6)
	initV4, respV4 := rndTraits(v4), rndTraits(v4)
	respV4.Observed = observedFor(v4, 7)
	var p DefaultPlanner
	ci := ClassifyInput{Initiator: dual(initV4, initV6), Responder: dual(respV4, respV6), Policy: protocol.Policy{Budget: protocol.DefaultBudget()}}
	cl := p.Classify(ci)
	var prev []RoundOutcome
	for round := 1; round <= 6; round++ {
		in := roundInput(cl, initV4, respV4, round, prev)
		in.Views = [2]protocol.PeerView{dual(initV4, initV6), dual(respV4, respV6)}
		in.MaxRounds = 6
		dec := p.Round(in)
		if dec.Stop != "" {
			break
		}
		if round >= 3 && (dec.Families[1].Variant != VInvalid || dec.Sides[0][1].Role != protocol.SideReplyOnly) {
			t.Fatalf("round %d: the exhausted rnd_x_rnd family runs %v", round, dec.Families[1].Variant)
		}
		prev = append(prev, outcomeOf(round, dec, RCNoContact))
		if dec.Final {
			break
		}
	}
}

// The rescue round is built in the family the one-way
// evidence is in; its plan encodes.
func TestRescueInEvidenceFamily(t *testing.T) {
	v6, v4 := protocol.FamilyUDP6, protocol.FamilyUDP4
	initV6, respV6 := openTraits(v6), pdfTraits(v6)
	initV4, respV4 := openTraits(v4), pdfTraits(v4)
	var p DefaultPlanner
	ci := ClassifyInput{Initiator: dual(initV4, initV6), Responder: dual(respV4, respV6), Policy: protocol.Policy{Budget: protocol.DefaultBudget()}}
	cl := p.Classify(ci)
	src := netip.AddrPortFrom(initV4.Observed.Addr(), 50000) // a new mapping on the initiator's verified IP
	last := RoundOutcome{Round: 1, Variant: vEasy1, Class: RCOneWay, Budget: protocol.BudgetLight}
	last.SeenFrom[1] = []netip.AddrPort{src, netip.MustParseAddrPort("198.51.100.7:50000")} // only v4 worked one way: the responder heard the initiator

	in := roundInput(cl, initV4, respV4, 2, []RoundOutcome{last})
	in.Views = [2]protocol.PeerView{dual(initV4, initV6), dual(respV4, respV6)}
	dec := p.Round(in)
	if !dec.Rescue {
		t.Fatalf("want rescue, got %+v", dec)
	}
	for r := range 2 {
		rp := protocol.RoundPlan{Round: 2, Variant: dec.VariantName, Budget: dec.Budget, WindowMs: uint16(dec.Window / time.Millisecond), Seed: 1, Rescue: true, Sides: dec.Sides[r]}
		if _, err := msgframe.Encode(protocol.PunchGo{SessionID: "s1", Round: 2, WindowMs: rp.WindowMs, Plan: &rp}); err != nil {
			t.Fatalf("role %d: rescue plan does not encode: %v", r, err)
		}
		if dec.Sides[r][0].Family != v6 || dec.Sides[r][0].Role != protocol.SideReplyOnly {
			t.Fatalf("role %d: v6 side %s", r, describe(dec.Sides[r][0]))
		}
	}
	// The source on an IP the initiator never verified is one its client
	// would refuse: the rescue leaves it out.
	if s := dec.Sides[1][1]; s.Role != protocol.SideSender || !slices.Equal(s.Stages[0].Targets, []netip.AddrPort{src}) {
		t.Fatalf("v4 hearer side %s", describe(s))
	}
	if s := dec.Sides[0][1]; s.Role != protocol.SideReceiver || s.Stages[0].TTL == 0 {
		t.Fatalf("v4 silent side %s", describe(s))
	}
	assertEmittable(t, dec)
}

// ConfirmLost repeats the variant without raising the class;
// rnd_x_rnd's two-sided birthday stays heavy.
func TestConfirmLostDoesNotEscalate(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := rndTraits(f), rndTraits(f)
	b.Observed = observedFor(f, 7)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	classes := []RoundClass{RCNoContact, RCNoContact, RCConfirmLost, RCConfirmLost}
	var prev []RoundOutcome
	for round := 1; round <= 4; round++ {
		in := roundInput(cl, a, b, round, prev)
		in.AllowExtreme, in.MaxRounds, in.HandshakeMs = true, 6, 40000
		in.Policy.Budget.Birthday = protocol.BirthdayAggressive
		dec := p.Round(in)
		if dec.Stop != "" {
			t.Fatalf("round %d stop %s", round, dec.Stop)
		}
		if round >= 4 {
			last := prev[len(prev)-1]
			if dec.Variant != last.Variant || dec.Budget != last.Budget {
				t.Fatalf("ConfirmLost repeat: %s at %s after %v at %s", dec.VariantName, dec.Budget, last.Variant, last.Budget)
			}
		}
		prev = append(prev, outcomeOf(round, dec, classes[round-1]))
	}
	// After a rescue round, ConfirmLost does not escalate either.
	in := roundInput(cl, a, b, 3, []RoundOutcome{
		{Round: 1, Variant: vRndRnd1, Class: RCOneWay, Budget: protocol.BudgetLight},
		{Round: 2, Variant: vRescue, Class: RCConfirmLost, Rescue: true, Budget: protocol.BudgetLight},
	})
	in.RescueUsed = true
	if dec := p.Round(in); dec.Budget != protocol.BudgetLight {
		t.Fatalf("after a ConfirmLost rescue: %s at %s, want light", dec.VariantName, dec.Budget)
	}
}

// A v6 family behind NAT66 runs the v4 ladder with birthday at most
// conservative: the balanced one-sided birthday never runs.
func TestNAT66BirthdayCapped(t *testing.T) {
	f := protocol.FamilyUDP6
	a, b := pdfTraits(f), seqTraits(f)
	a.NoNAT, b.NoNAT = protocol.TriFalse, protocol.TriFalse
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	decs := chain(p, cl, a, b, 6, true, RCNoContact, func(in *RoundInput) {
		in.Policy.Budget.Birthday = protocol.BirthdayBalanced
	})
	ran := map[VariantID]bool{}
	for _, d := range decs {
		ran[d.Variant] = true
	}
	if ran[vPDFSeq5] || !ran[vPDFSeq4] {
		t.Fatalf("NAT66 ran %v", ran)
	}
	// A public v6 pair keeps the session's tier.
	a.NoNAT, b.NoNAT = protocol.TriTrue, protocol.TriTrue
	cl = p.Classify(classifyInput(a, b))
	if cl.fams[0].TierCap != "" {
		t.Fatalf("no-NAT v6 capped at %s", cl.fams[0].TierCap)
	}
}

// The sandwich probe is only for a sequential allocator; a
// pool allocates at random inside its block.
func TestSandwichOnlySequential(t *testing.T) {
	f := protocol.FamilyUDP4
	pool := seqTraits(f)
	pool.PortAlloc, pool.PortAllocConf, pool.PortStep, pool.PortAnchor = protocol.AllocPool, protocol.ConfMedium, 0, 0
	pool.PortRangeLo, pool.PortRangeHi = 30000, 31023
	var p DefaultPlanner
	cl := p.Classify(classifyInput(pdfTraits(f), pool))
	if cl.PairClass != PairPDFSeq {
		t.Fatalf("pair %s", cl.PairClass)
	}
	in := roundInput(cl, pdfTraits(f), pool, 1, nil)
	in.SandwichOK = true
	if dec := p.Round(in); sandwichOf(dec) != [2]bool{} {
		t.Fatalf("sandwich %v for a pool allocator", sandwichOf(dec))
	}
	cl = p.Classify(classifyInput(pdfTraits(f), seqTraits(f)))
	in = roundInput(cl, pdfTraits(f), seqTraits(f), 1, nil)
	in.SandwichOK = true
	if dec := p.Round(in); sandwichOf(dec) != [2]bool{false, true} {
		t.Fatalf("sandwich %v for a sequential responder", sandwichOf(dec))
	}
}

// The rescue round reads the one-way round's own evidence, not the
// cumulative one: after a ConfirmLost round in which both sides heard, a
// one-way round heard by the responder makes the responder the sender. The
// responder is SEQ behind an address-dependent NAT: an APDM hearer would
// only reply (TestRescueAPDMHearerReplies).
func TestRescueUsesRoundEvidence(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	b.Mapping = protocol.MapADM
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	srcI, srcR := observedFor(f, 2), observedFor(f, 3)
	oneWay := RoundOutcome{Round: 2, Variant: vPDFSeq1, Class: RCOneWay, Budget: protocol.BudgetBalanced}
	oneWay.SeenFrom[1] = []netip.AddrPort{srcI}
	in := roundInput(cl, a, b, 3, []RoundOutcome{
		{Round: 1, Variant: vPDFSeq1, Class: RCConfirmLost, Budget: protocol.BudgetBalanced},
		oneWay,
	})
	in.Evidence.SeenFrom = [2][]netip.AddrPort{{srcR}, {srcI}} // cumulative: both heard in round 1
	in.Evidence.Hit = [2]bool{true, true}
	dec := p.Round(in)
	if !dec.Rescue {
		t.Fatalf("want rescue, got %s", dec.VariantName)
	}
	if dec.Sides[1][0].Role != protocol.SideSender || dec.Sides[1][0].Stages[0].Targets[0] != srcI {
		t.Fatalf("responder (the hearer) %s", describe(dec.Sides[1][0]))
	}
	if dec.Sides[0][0].Role != protocol.SideReceiver {
		t.Fatalf("initiator (silent) %s", describe(dec.Sides[0][0]))
	}
}

// A hearer behind an APDM NAT does not send Direct to the sources it
// heard in the rescue round — from its sockets they are new destinations,
// whose new mappings the silent side's filter refuses — and only replies;
// the silent side is still a low-TTL receiver toward the hearer. On a
// shared LAN the hearer keeps its LAN stage.
func TestRescueAPDMHearerReplies(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f) // b: APDM
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	oneWay := RoundOutcome{Round: 1, Variant: vPDFSeq1, Class: RCOneWay, Budget: protocol.BudgetBalanced}
	oneWay.SeenFrom[1] = []netip.AddrPort{observedFor(f, 2)}
	dec := p.Round(roundInput(cl, a, b, 2, []RoundOutcome{oneWay}))
	if !dec.Rescue {
		t.Fatalf("want rescue, got %s", dec.VariantName)
	}
	if fs := dec.Sides[1][0]; fs.Role != protocol.SideReplyOnly {
		t.Fatalf("APDM hearer %s, want reply_only", describe(fs))
	}
	if fs := dec.Sides[0][0]; fs.Role != protocol.SideReceiver || len(directTargetsOf(fs)) == 0 {
		t.Fatalf("silent side %s", describe(fs))
	}
	assertEmittable(t, dec)

	// The PDF side hearing the APDM one still sends to what it heard.
	oneWay.SeenFrom = [2][]netip.AddrPort{{observedFor(f, 3)}, nil}
	dec = p.Round(roundInput(cl, a, b, 2, []RoundOutcome{oneWay}))
	if fs := dec.Sides[0][0]; fs.Role != protocol.SideSender || !slices.Contains(directTargetsOf(fs), observedFor(f, 3)) {
		t.Fatalf("EIM hearer %s", describe(fs))
	}
}

// Once a side is forced to one socket (bind_failed > sockets/2), a
// ladder that only has multi-socket rounds left ends with
// local_port_bind_failed.
func TestBindFailedStopsMultiSocketLadder(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), rndTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	prev := []RoundOutcome{
		{Round: 1, Variant: vPDFRnd1, Class: RCNoContact, Budget: protocol.BudgetBalanced},
		{Round: 2, Variant: vPDFRnd2, Class: RCNoContact, Budget: protocol.BudgetHeavy},
	}
	in := roundInput(cl, a, b, 3, prev)
	in.Evidence.BindFailed = [2]uint16{0, 30} // the responder bound 2 of its 32 sockets
	if dec := p.Round(in); dec.Stop != protocol.ReasonLocalPortBindFailed {
		t.Fatalf("got %s stop %q, want local_port_bind_failed", dec.VariantName, dec.Stop)
	}
	// Few failures: the round runs with all its sockets.
	in.Evidence.BindFailed = [2]uint16{0, 10}
	if dec := p.Round(in); dec.Stop != "" || dec.Sides[1][0].Sockets != 32 {
		t.Fatalf("10/32 failures: %s stop %q", dec.VariantName, dec.Stop)
	}
}

// Easy's third round exchanges the roles only when both sides
// are OPEN; a PDF side always stays the receiver.
func TestEasyRound3Swap(t *testing.T) {
	f := protocol.FamilyUDP4
	var p DefaultPlanner
	prev := []RoundOutcome{
		{Round: 1, Variant: vEasy1, Class: RCNoContact, Budget: protocol.BudgetLight},
		{Round: 2, Variant: vEasy2, Class: RCNoContact, Budget: protocol.BudgetLight},
	}
	roles := func(a, b protocol.Traits, round int, prev []RoundOutcome) [2]protocol.SideRole {
		cl := p.Classify(classifyInput(a, b))
		dec := p.Round(roundInput(cl, a, b, round, prev))
		return [2]protocol.SideRole{dec.Sides[0][0].Role, dec.Sides[1][0].Role}
	}
	open2 := openTraits(f)
	open2.Observed = observedFor(f, 9)
	r2, r3 := roles(openTraits(f), open2, 2, prev[:1]), roles(openTraits(f), open2, 3, prev)
	if r2 != [2]protocol.SideRole{protocol.SideSender, protocol.SideReceiver} || r3 != [2]protocol.SideRole{protocol.SideReceiver, protocol.SideSender} {
		t.Fatalf("OPEN×OPEN roles r2 %v r3 %v, want swapped", r2, r3)
	}
	if r3 := roles(openTraits(f), pdfTraits(f), 3, prev); r3[1] != protocol.SideReceiver {
		t.Fatalf("OPEN×PDF r3: PDF side is %s", r3[1])
	}
	pdf2 := pdfTraits(f)
	pdf2.Observed = observedFor(f, 9)
	if r2, r3 := roles(pdfTraits(f), pdf2, 2, prev[:1]), roles(pdfTraits(f), pdf2, 3, prev); r2 != r3 {
		t.Fatalf("PDF×PDF r3 roles %v differ from r2 %v", r3, r2)
	}
}

// The round fires D after now and must end by punchDeadline:
// the window is clamped to Remaining − D.
func TestWindowEndsByDeadline(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := openTraits(f), pdfTraits(f)
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	for _, c := range []struct{ remaining, d time.Duration }{
		{1000 * time.Millisecond, 250 * time.Millisecond},
		{2800 * time.Millisecond, 2 * time.Second},
	} {
		in := roundInput(cl, a, b, 1, nil)
		in.Remaining, in.D = c.remaining, c.d
		dec := p.Round(in)
		if dec.Stop != "" {
			t.Fatalf("stop %s", dec.Stop)
		}
		if end := in.D + dec.Window; end > in.Remaining {
			t.Fatalf("round ends %v after now (D %v + window %v) > Remaining %v", end, in.D, dec.Window, in.Remaining)
		}
	}
	// The rescue round too.
	in := roundInput(cl, a, b, 2, []RoundOutcome{{Round: 1, Variant: vEasy1, Class: RCOneWay, Budget: protocol.BudgetLight}})
	in.Evidence.SeenFrom[0] = []netip.AddrPort{observedFor(f, 2)}
	in.Remaining, in.D = 1500*time.Millisecond, 500*time.Millisecond
	if dec := p.Round(in); !dec.Rescue || in.D+dec.Window > in.Remaining {
		t.Fatalf("rescue window %v with D %v, Remaining %v", dec.Window, in.D, in.Remaining)
	}
}

// fitDirect trims Direct to the grant in order: later targets, repeats,
// sockets, whole stages; reply_only stages stay.
func TestFitDirect(t *testing.T) {
	tg := []netip.AddrPort{ap("203.0.113.1:1"), ap("203.0.113.1:2"), ap("203.0.113.1:3")}
	stages := func() []protocol.Stage {
		return []protocol.Stage{{Kind: protocol.StageDirect, Targets: tg, Repeats: 3}, {Kind: protocol.StageReplyOnly}, {Kind: protocol.StageDirect, Targets: tg[:1], Repeats: 2}}
	}
	for _, c := range []struct {
		sockets, budget  int
		wantPk, wantSock int
		wantTargets      []int // per remaining Direct stage
	}{
		{1, 100, 11, 1, []int{3, 1}},
		{1, 8, 8, 1, []int{2, 1}},   // a target of the first stage goes
		{1, 4, 4, 1, []int{1, 1}},   // then repeats: 3+2 -> 2+2
		{8, 30, 24, 8, []int{1, 1}}, // 8 sockets: targets, then repeats to 1+2
		{8, 10, 10, 5, []int{1, 1}}, // one target and one repeat each: 2 per socket, 5 sockets
		{1, 1, 1, 1, []int{1}},      // one packet: the last stage goes
		{4, 0, 0, 1, nil},           // no grant: no Direct
	} {
		out, sock := fitDirect(stages(), c.sockets, c.budget)
		var targets []int
		replies := 0
		for _, st := range out {
			switch st.Kind {
			case protocol.StageDirect:
				targets = append(targets, len(st.Targets))
			case protocol.StageReplyOnly:
				replies++
			}
		}
		if pk := directPackets(out, sock); pk != c.wantPk || sock != c.wantSock || replies != 1 || !slices.Equal(targets, c.wantTargets) {
			t.Fatalf("fit(%d sockets, %d): %d packets on %d sockets, targets %v (replies %d)", c.sockets, c.budget, pk, sock, targets, replies)
		}
	}
	if s := stages(); len(s[0].Targets) != 3 || s[0].Repeats != 3 {
		t.Fatal("fitDirect changed its input")
	}
}

// predictPeer without a probe anchor time takes its first punch-time sample
// as the base; a gap below the peer's own allocations is no velocity.
func TestPredictPeerSampleBase(t *testing.T) {
	tr := seqTraits(protocol.FamilyUDP4)
	tr.PortAnchorMs, tr.PortVelocity = 0, 0
	ip := tr.Observed.Addr()
	in := RoundInput{FireAt: 5 * time.Second, D: 100 * time.Millisecond}
	in.Mappings[1] = []MappingSample{
		{Addr: netip.AddrPortFrom(ip, 41000), At: 2 * time.Second},
		{Addr: netip.AddrPortFrom(ip, 41021), At: 3 * time.Second}, // 20 by others in 1 s besides its own one
		{Addr: netip.MustParseAddrPort("198.51.100.1:9"), At: 4 * time.Second},
	}
	if p := predictPeer(in, 1, tr, ip); p.anchor != 41021+40 || p.minSpan != 2*(2+1) {
		t.Fatalf("prediction %+v, want anchor 41061 and span 6", p)
	}
	// a single sample: the new anchor, no velocity
	in.Mappings[1] = in.Mappings[1][:1]
	if p := predictPeer(in, 1, tr, ip); p.anchor != 41000 {
		t.Fatalf("prediction %+v", p)
	}
	// the peer's own allocations cover the gap: no velocity
	in.Mappings[1] = []MappingSample{{Addr: netip.AddrPortFrom(ip, 41000), At: 2 * time.Second}, {Addr: netip.AddrPortFrom(ip, 41001), At: 3 * time.Second}}
	if p := predictPeer(in, 1, tr, ip); p.anchor != 41001 {
		t.Fatalf("prediction %+v", p)
	}
	// nothing to predict from
	if p := predictPeer(RoundInput{}, 1, protocol.Traits{}, ip); p.anchor != 0 || len(p.steps) != 1 || p.steps[0] != 1 {
		t.Fatalf("prediction %+v", p)
	}
}

// A rate of other hosts may be any finite float32 a traits update carries.
// The extrapolated anchor moves by the exact remainder of the rate's move
// modulo the range — whole turns of the range leave it where it was, and it
// is the same port on every platform — and the window never outgrows the
// range.
func TestPredictPeerHugeVelocity(t *testing.T) {
	f := protocol.FamilyUDP4
	a, b := pdfTraits(f), seqTraits(f)
	b.PortAnchorMs = 1000
	var p DefaultPlanner
	cl := p.Classify(classifyInput(a, b))
	// rest is |v| modulo the range, exactly: every float32 this large is an
	// integer, and the move over the one second below is v itself.
	rest := func(v float32) int {
		n, _ := new(big.Float).SetFloat64(math.Abs(float64(v))).Int(nil)
		return int(new(big.Int).Mod(n, big.NewInt(portRange)).Int64())
	}
	turns := float32(portRange) * float32(1<<60) // whole turns of the range a second
	for _, vel := range []float32{turns, -turns, math.MaxFloat32, -math.MaxFloat32, 1e30, -3e25} {
		want := wrapPort(int(b.PortAnchor) + rest(vel))
		if vel < 0 {
			want = wrapPort(int(b.PortAnchor) - rest(vel))
		}
		if (vel == turns || vel == -turns) && want != b.PortAnchor {
			t.Fatalf("setup: %g is no whole number of turns", vel)
		}
		b.PortVelocity = vel
		in := roundInput(cl, a, b, 1, nil)
		in.FireAt = 2 * time.Second // one second after the anchor
		if pr := predictPeer(in, 1, b, b.Observed.Addr()); pr.anchor != want || pr.minSpan != portRange {
			t.Errorf("velocity %g: anchor %d, window %d; want anchor %d and the whole range", vel, pr.anchor, pr.minSpan, want)
		}
		dec := p.Round(in)
		if st := stageOf(dec.Sides[0][0], protocol.StagePredict); st == nil || st.Anchor != want {
			t.Errorf("velocity %g: predict stage %+v, want anchor %d", vel, st, want)
		}
		assertEmittable(t, dec)
	}
}

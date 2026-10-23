package plan

import (
	"slices"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// Planning an endpoint-independent side as endpoint dependent. natprobe sees a
// side's mappings toward its own observers only. A router that routes the
// server's address apart — a proxy, policy routing, a second uplink — maps the
// peer's direction elsewhere, and from one server IP that looks exactly like
// EIM. Two kinds of evidence say the conclusion is wrong:
//
//   - a STUN server saw the primary socket at another port of the same
//     public IP (protocol.Traits.PathDependent): the side is planned
//     as endpoint dependent from the first round (Classify);
//   - two consecutive rounds of an easy family — both sides endpoint
//     independent — without any contact either way while a side's EIM
//     conclusion is below High: the side is planned as endpoint
//     dependent from the next round on (escalate), instead of spending the
//     remaining rounds on the same kind of punch. A family whose other side
//     is endpoint dependent already keeps its ladder: its silence has that
//     side to explain it, and its ladder is the one built for it.
//
// A side that two silent rounds made doubtful plans its next ports by the
// allocation natprobe saw (asEDM): a side that kept its local port probably
// keeps it for a fresh socket's first mapping, which is the one toward the
// peer, so it binds fresh sockets the peer aims at exactly (pdf_x_pres,
// pres_x_pres); otherwise it is random and the birthday rounds of its new
// class apply. A side a STUN server contradicted is random whatever
// natprobe saw: its path toward the peer is another translation,
// and an allocation seen on the server's path says nothing about it.

// noContactRounds is how many consecutive rounds of a family without any
// contact make an EIM conclusion below High doubtful.
const noContactRounds = 2

// eimDoubt reports whether a side's mapping conclusion is endpoint
// independent and may be wrong: EIM (no NoNAT host, one exit) below High
// confidence, or contradicted by a STUN server.
func eimDoubt(t protocol.Traits) bool {
	return t.Samples > 0 && t.Mapping == protocol.MapEIM && t.NoNAT != protocol.TriTrue && !t.MultiExit &&
		(t.MappingConf < protocol.ConfHigh || t.PathDependent)
}

// asEDM is t as planned for a side whose endpoint independence is not
// trusted: an address-and-port-dependent mapping whose ports follow the
// allocation natprobe saw — a kept local port as PreserveFresh, anything
// else as random at low confidence, which no summary-time verdict ever
// reads as hopeless. A path-dependent side is random: natprobe saw
// its allocation on another path.
func asEDM(t protocol.Traits) protocol.Traits {
	if t.PortAlloc == protocol.AllocPreserving && !t.PathDependent {
		t.Mapping, t.MappingConf = protocol.MapAPDM, protocol.ConfMedium
		t.PortAlloc, t.PortAllocConf = protocol.AllocPreserveFresh, max(t.PortAllocConf, protocol.ConfMedium)
		return t
	}
	return asRandom(t)
}

// asRandom is t as planned for a random side: an address-and-port-dependent
// mapping with random ports at low confidence.
func asRandom(t protocol.Traits) protocol.Traits {
	t.Mapping, t.MappingConf = protocol.MapAPDM, protocol.ConfMedium
	t.PortAlloc, t.PortAllocConf = protocol.AllocRandom, protocol.ConfLow
	return t
}

// escalate applies the one-way switch and the no-contact escalation to in
// and rewrites in.Views for every
// side planned as endpoint dependent (familyPlan.EDM) or random
// (familyPlan.OneWay), so that every stage the round builds reads the
// traits it was classified with. It reports, by family index, the families
// whose ladder a switch replaced; in.fams and in.Views are copied before
// they change, never written through.
func escalate(in *input) []bool {
	out := make([]bool, len(in.fams))
	fams := in.fams
	cloned := false
	replace := func(i int, next familyPlan, from int) {
		next.From = from
		next.Restart = !ranSince(in.Prev[from:], next.Family)
		if !cloned {
			fams, cloned = slices.Clone(fams), true
		}
		fams[i], out[i] = next, true
	}
	for i, fp := range fams {
		if fp.Unverified {
			continue // an unverified family runs Direct stages only, whatever its class
		}
		if seer, from, ok := oneWaySeer(in.Prev, fp.Family); ok {
			if fp.PairClass != PairPDFRnd || roleIndex(fp.SideA) == seer {
				replace(i, oneWayPlan(fp, seer, in.Views, in.Policy, in.Mode == protocol.ModeBackground), from)
			}
			continue // the one-way evidence decides; no silent-round escalation besides
		}
		from, ok := escalationPoint(in.Prev, fp.Family)
		if !ok || fp.PairClass != PairEasy {
			continue
		}
		edm := fp.EDM
		tr := [2]protocol.Traits{familyTraits(in.Views[0], fp.Family), familyTraits(in.Views[1], fp.Family)}
		more := escalatedSides(tr, edm)
		if more == edm {
			continue
		}
		next := planFamily(fp.Family, tr, more, protocol.PairFacts{
			LikelySameLAN: map[protocol.Family]bool{fp.Family: fp.SameLAN},
			SharedOverlay: map[protocol.Family]bool{fp.Family: fp.SharedOverlay},
		}, in.Policy, in.Mode == protocol.ModeBackground, false)
		if next.PairClass == fp.PairClass {
			continue
		}
		replace(i, next, from)
	}
	in.fams = fams
	for _, fp := range fams {
		for r := range in.Views {
			switch {
			case fp.OneWay && r != roleIndex(fp.SideA):
				in.Views[r] = withTraits(in.Views[r], fp.Family, asRandom(familyTraits(in.Views[r], fp.Family)))
			case fp.EDM[r]:
				in.Views[r] = withTraits(in.Views[r], fp.Family, asEDM(familyTraits(in.Views[r], fp.Family)))
			}
		}
	}
	return out
}

// oneWayRounds is how many one-way rounds of a family — the same side hearing
// each time, the other side never — make it a PDF×RND pair.
const oneWayRounds = 2

// oneWaySeer returns the side that heard its peer in oneWayRounds rounds of
// family fam without the peer ever hearing it, and the index into prev
// after the round that made the count; false when no side did. The rounds
// need not be adjacent: a rescue round in between that found nothing — its
// silent side sends at low TTL — leaves the evidence as it was.
func oneWaySeer(prev []api.RoundOutcome, fam protocol.Family) (seer, from int, ok bool) {
	var n [2]int
	var heard [2]bool
	at := [2]int{-1, -1}
	for k, o := range prev {
		fr, found := familyRound(o, fam)
		if !found {
			continue
		}
		for s := range 2 {
			heard[s] = heard[s] || fr.Heard[s]
			if fr.Heard[s] && !fr.Heard[1-s] {
				if n[s]++; n[s] == oneWayRounds {
					at[s] = k + 1
				}
			}
		}
	}
	for s := range 2 {
		if at[s] >= 0 && !heard[1-s] {
			return s, at[s], true
		}
	}
	return 0, 0, false
}

// oneWayPlan is family fp as a PDF×RND pair after two one-way rounds: the side
// that heard is the random (B) side, whose sockets aim at the sources it heard
// (seenTargets); the silent side, whose packets arrive but whose filter turns
// the replies away, sprays the hearer's IP. The replies leave the hearer
// through mappings its peer never sent to: a proxy or an endpoint-dependent
// translation on the hearer's path toward the peer, whatever natprobe saw on
// the server's path. Interactive sessions run the conservative birthday rounds,
// Background ones the slow birthday.
func oneWayPlan(fp familyPlan, seer int, views [2]protocol.PeerView, pol protocol.Policy, background bool) familyPlan {
	silent := 1 - seer
	next := fp
	next.PairClass, next.CatA, next.CatB = PairPDFRnd, CatPDF, CatRND
	next.SideA = protocol.RoleInitiator
	if silent == 1 {
		next.SideA = protocol.RoleResponder
	}
	sTr := familyTraits(views[silent], fp.Family)
	if fp.EDM[silent] {
		sTr = asEDM(sTr)
	}
	next.OpensA, next.OpensB = opensBirthday(sTr), opensBirthday(asRandom(familyTraits(views[seer], fp.Family)))
	next.EDM, next.OneWay, next.CheapOnly = [2]bool{}, true, false
	if !background && (next.TierCap == "" || next.TierCap.Rank() > protocol.BirthdayConservative.Rank()) {
		next.TierCap = protocol.BirthdayConservative
	}
	next.Ladder = []api.VariantID{vPDFRnd2, vPDFRnd3}
	if background && slowViable(next, pol) {
		next.Ladder = []api.VariantID{vPDFRndSlow}
	}
	return next
}

// escalatedSides returns which sides of a family to plan as endpoint
// dependent once two rounds found no contact, on top of edm. When
// every doubtful side kept its local port, all of them: fresh sockets then
// aim at each other's exactly, whichever side's mapping depends on the
// path. Otherwise the single most doubtful side that did not — contradicted
// by STUN first, then the lower confidence — so that a random side meets an
// endpoint-independent one rather than another random one.
func escalatedSides(tr [2]protocol.Traits, edm [2]bool) [2]bool {
	out := edm
	var doubt, random []int
	for r := range tr {
		if edm[r] || !eimDoubt(tr[r]) {
			continue
		}
		doubt = append(doubt, r)
		if tr[r].PortAlloc != protocol.AllocPreserving {
			random = append(random, r)
		}
	}
	if len(random) == 0 {
		for _, r := range doubt {
			out[r] = true
		}
		return out
	}
	pick := random[0]
	for _, r := range random[1:] {
		if tr[r].PathDependent != tr[pick].PathDependent {
			if tr[r].PathDependent {
				pick = r
			}
		} else if tr[r].MappingConf < tr[pick].MappingConf {
			pick = r
		}
	}
	out[pick] = true
	return out
}

// escalationPoint returns the index into prev after the round that made
// the family's noContactRounds-th consecutive round without contact, the
// first such streak; false when no streak happened. A round the family did
// not run, or ran with contact, ends a streak; a rescue round never starts
// one, since one-way contact preceded it.
func escalationPoint(prev []api.RoundOutcome, fam protocol.Family) (int, bool) {
	streak := 0
	for k, o := range prev {
		fr, ok := familyRound(o, fam)
		if !ok || o.Rescue || !fr.NoContact {
			streak = 0
			continue
		}
		if streak++; streak == noContactRounds {
			return k + 1, true
		}
	}
	return 0, false
}

// familyRound returns family fam's record in outcome o.
func familyRound(o api.RoundOutcome, fam protocol.Family) (api.FamilyRound, bool) {
	for _, f := range o.Families {
		if f.Family == fam {
			return f, true
		}
	}
	return api.FamilyRound{}, false
}

// ranSince reports whether family fam ran a non-rescue round in prev.
func ranSince(prev []api.RoundOutcome, fam protocol.Family) bool {
	for _, o := range prev {
		if _, ok := familyRound(o, fam); ok && !o.Rescue {
			return true
		}
	}
	return false
}

// withTraits is v with family f's traits replaced, its family list copied.
func withTraits(v protocol.PeerView, f protocol.Family, t protocol.Traits) protocol.PeerView {
	v.Families = slices.Clone(v.Families)
	for i := range v.Families {
		if v.Families[i].Family == f {
			v.Families[i].Traits = t
		}
	}
	return v
}

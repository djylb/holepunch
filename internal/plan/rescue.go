package plan

import (
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// buildRescue builds the session's one rescue round after the one-way round
// last: in each family the one-way evidence is in, the side that
// heard the other becomes a sender (d = 80 ms) toward the sources it heard,
// and the silent side is a low-TTL receiver aimed at the hearer's verified
// endpoints; the other families only reply. A hearer behind an APDM NAT
// only replies, with its LAN stage if any. Light class, 1500 ms,
// not counted against max_rounds.
//
// The hearer and its sources come from the round's own evidence
// (last.SeenFrom, last.Hit): the cumulative Evidence also holds earlier
// rounds, in which both sides may have heard each other. An outcome recorded
// without them falls back to the cumulative Evidence. A source is aimed at
// only when the client admits it: a public IP of the
// peer goes to the Direct stage, a LAN address of a peer on the same LAN to
// the LAN stage, anything else is left out. With a shared LAN both sides
// also aim the LAN stage at the peer's LAN endpoints, as in every round.
func buildRescue(in RoundInput, last RoundOutcome) RoundDecision {
	vr, _ := variantOf(vRescue)
	seer, seen, rescued := oneWayScope(in, last)
	silent := 1 - seer

	ttlOK := lowTTLEnabled(in.Policy)
	lim, _ := protocol.BudgetLight.Limits()
	sessB := protocol.TightenBudget(in.Policy.Budget)
	budget := [2]int{int(lim.MaxPackets), int(lim.MaxPackets)}
	for r := range budget {
		if in.BudgetLeft[r] >= 0 {
			budget[r] = min(budget[r], in.BudgetLeft[r])
		}
	}

	dec := RoundDecision{Variant: vr.id, VariantName: vr.name, Budget: protocol.BudgetLight, Rescue: true,
		Window: clampWindow(time.Duration(vr.windowMs)*time.Millisecond, in.Remaining-in.D, vr.budget)}
	for _, fp := range in.Class.fams {
		fam := fp.Family
		if !rescued[fam] {
			dec.Sides[seer] = append(dec.Sides[seer], replyOnlySide(fam))
			dec.Sides[silent] = append(dec.Sides[silent], replyOnlySide(fam))
			dec.Families = append(dec.Families, FamilyRound{Family: fam})
			continue
		}
		// One allotment per rescued family: their sum stays within the
		// side's light class and remaining budget.
		share := [2]int{budget[seer] / len(rescued), budget[silent] / len(rescued)}
		silentView, _ := findFamily(in.Views[silent], fam)
		hearerView, _ := findFamily(in.Views[seer], fam)
		toSilent, toHearer := peerAddrsOf(fp, silentView), peerAddrsOf(fp, hearerView)
		// A hearer behind an APDM NAT sends nothing new toward the sources:
		// from its round sockets they are new destinations, which take new
		// mappings the silent side's filter does not admit. Its replies,
		// which leave from the socket that heard and through the mapping the
		// peer's packet came in on, are what can reach the peer.
		replyOnly := familyTraits(in.Views[seer], fam).Mapping == protocol.MapAPDM
		var sources, lan []netip.AddrPort
		for _, ap := range dedupAddrs(seen) {
			ip := ap.Addr().Unmap()
			switch {
			case protocol.FamilyOf(ip) != fam || !usableTarget(ap):
			case slices.Contains(toSilent.public, ip):
				if len(sources) < fp.MaxTargets && !replyOnly {
					sources = append(sources, ap)
				}
			case slices.Contains(toSilent.lanIPs, ip) && len(lan) < maxLANTargets:
				lan = append(lan, ap)
			}
		}
		for _, ap := range toSilent.lan {
			if len(lan) < maxLANTargets && !slices.Contains(lan, ap) {
				lan = append(lan, ap)
			}
		}
		dec.Sides[seer] = append(dec.Sides[seer],
			rescueSide(fam, protocol.SideSender, vr.a, sources, lanStage(lan, toSilent.overlay), ttlOK, lim, sessB, share[0]))
		dec.Sides[silent] = append(dec.Sides[silent],
			rescueSide(fam, protocol.SideReceiver, vr.b, toHearer.direct, lanStage(toHearer.lan, toHearer.overlay), ttlOK, lim, sessB, share[1]))
		dec.Families = append(dec.Families, FamilyRound{Family: fam, Variant: vr.id, Budget: protocol.BudgetLight})
	}
	return dec
}

// rescueSide is one side of a rescued family on one socket: the LAN stage,
// then the template's Direct stage toward targets with the template's ttl
// (stageTTL), fitted to budget packets; reply_only without a target.
func rescueSide(fam protocol.Family, role protocol.SideRole, tmpl sideTmpl, targets []netip.AddrPort, lan *protocol.Stage, ttlOK bool,
	lim protocol.ClassLimits, sessB protocol.Budget, budget int) protocol.FamilySide {
	var stages []protocol.Stage
	packets, distinct := 0, 0
	if lan = fitLAN(lan, budget); lan != nil {
		stages = append(stages, *lan)
		packets, distinct = lanPackets(lan), len(lan.Targets)
	}
	if len(targets) > 0 {
		st := tmpl.stages[0]
		direct, _ := fitDirect([]protocol.Stage{{Kind: protocol.StageDirect, AtMs: st.atMs, Targets: targets, Repeats: st.repeats, TTL: stageTTL(st, ttlOK)}},
			1, budget-packets)
		for _, d := range direct {
			distinct = max(distinct, len(d.Targets))
		}
		packets += directPackets(direct, 1)
		stages = append(stages, direct...)
	}
	if len(stages) == 0 {
		return replyOnlySide(fam)
	}
	return protocol.FamilySide{
		Family:           fam,
		Role:             role,
		SendDelayMs:      tmpl.sendDelayMs,
		Sockets:          1,
		MaxPackets:       uint32(packets),
		MaxPPS:           minU16(tmpl.maxPPS, minU16(lim.MaxPPS, nonZeroU16(sessB.MaxPPS, lim.MaxPPS))),
		MaxNewPerSec:     uint16(effNPS0(sessB)),
		MaxDistinctPorts: uint16(min(distinct, int(lim.MaxDistinctPorts))),
		Stages:           stages,
	}
}

func dedupAddrs(in []netip.AddrPort) []netip.AddrPort {
	var out []netip.AddrPort
	for _, ap := range in {
		if ap.IsValid() && !slices.Contains(out, ap) {
			out = append(out, ap)
		}
	}
	return out
}

// oneWayScope reads the one-way round last: the side that heard the other,
// the sources it heard and the families they are in — the primary family
// when only a hit without a source was reported. The round's own evidence
// decides; an outcome recorded without it falls back to the cumulative
// Evidence.
func oneWayScope(in RoundInput, last RoundOutcome) (seer int, seen []netip.AddrPort, fams map[protocol.Family]bool) {
	from, hit := last.SeenFrom, last.Hit
	if len(from[0])+len(from[1]) == 0 && !hit[0] && !hit[1] {
		from, hit = in.Evidence.SeenFrom, in.Evidence.Hit
	}
	if (len(from[1]) > 0 || hit[1]) && len(from[0]) == 0 && !hit[0] {
		seer = 1
	}
	fams = map[protocol.Family]bool{}
	for _, ap := range from[seer] {
		if f := protocol.FamilyOf(ap.Addr().Unmap()); slices.Contains(in.Class.Families, f) {
			fams[f] = true
		}
	}
	if len(fams) == 0 {
		fams[in.Class.Families[0]] = true
	}
	return seer, from[seer], fams
}

// birthdayFollows reports whether the one-way round last needs no rescue:
// every family the one-way path is in is a verified PDF×RND pair whose
// random side is the one that heard. Its replies leave through mappings the
// silent side never sent to, so replying from them cannot reach
// that side; the birthday round that follows on the ladder is the remedy,
// its sockets aimed at the sources heard (seenTargets).
func birthdayFollows(in RoundInput, last RoundOutcome) bool {
	seer, _, fams := oneWayScope(in, last)
	for _, fp := range in.Class.fams {
		if fams[fp.Family] && (fp.PairClass != PairPDFRnd || fp.Unverified || roleIndex(fp.SideA) == seer) {
			return false
		}
	}
	return true
}

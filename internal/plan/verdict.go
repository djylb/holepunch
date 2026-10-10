package plan

import "github.com/djylb/holepunch/protocol"

// CheapRounds is how many rungs of a ladder every pair runs before the
// evidence may end it: rnd_x_rnd's r1 and r2, seq_x_rnd's r1 and
// r2 under its verdict (SeqRndVerdict).
const CheapRounds = 2

// summaryVerdict reports whether Classify may end the session at summary
// time, without sending a punch packet.
//
// The NAT classification is a hint: it picks the first rounds and the
// budget class, and the rounds then correct it from what punching shows
// (peer_seen, round_result, drift, the rescue round). A verdict that skips
// all of that must rest on the server's own measurement at its highest
// confidence, so every shared family has to be hopeless: its ladder is
// rnd_x_rnd, natprobe measured both sides' port allocation as Random with
// High confidence (ClassifyInput.Measured — not a client's self-reported
// traits, not a conclusion the traits memory raised), and no rung after the
// two cheap ones can run in this session. Anything less runs the cheap
// rounds and lets their evidence end the ladder (TerminalReason).
func summaryVerdict(in ClassifyInput, cl Classification) bool {
	for i, fp := range cl.fams {
		if fp.PairClass != PairRndRnd || !measuredRandom(in.Measured[0], fp.Family) || !measuredRandom(in.Measured[1], fp.Family) ||
			laterRungRuns(in, cl, i) {
			return false
		}
	}
	return len(cl.fams) > 0
}

// measuredRandom reports whether natprobe measured the side's port
// allocation in family f as Random with High confidence.
func measuredRandom(v protocol.PeerView, f protocol.Family) bool {
	tr := familyTraits(v, f)
	return tr.Samples > 0 && tr.PortAlloc == protocol.AllocRandom && tr.PortAllocConf == protocol.ConfHigh
}

// laterRungRuns reports whether a rung of family i's ladder after the cheap
// ones could run in this session: within max_rounds, and through the same
// gates Round applies (reachable) — the BirthdayTier with the family's NAT66
// cap, opensBirthday and the two-sided birthday's handshake rule. Classify does not know
// AllowExtreme and assumes it, so that a doubt keeps the session punching;
// the session policy's tier is already clamped to conservative without it
// (protocol.SessionBudgetLimit), which keeps the two-sided birthday out by
// default.
func laterRungRuns(in ClassifyInput, cl Classification, i int) bool {
	fp := cl.fams[i]
	rin := RoundInput{Class: cl, Policy: in.Policy, AllowExtreme: true, HandshakeMs: in.Timeouts.HandshakeTimeoutMs}
	for j := CheapRounds; j < len(fp.Ladder); j++ {
		round := j + 1
		if mr := int(in.Timeouts.MaxRounds); mr > 0 && round > mr {
			break
		}
		if vr, ok := familyVariant(fp.Ladder[j], fp); ok && reachable(rin, i, vr, round) {
			return true
		}
	}
	return false
}

// SeqRndVerdict reports whether natprobe measured family f of the pair as one
// the seq_x_rnd ladder cannot open after its two cheap rounds: one side's
// allocation sequential (SEQ) with its filtering address-and-port dependent
// (APDF) at High confidence, the other's allocation Random at High confidence.
// A SEQ mapping toward the RND side only admits the endpoint it was opened for,
// and the RND side never sends from it: the success is bounded by the RND
// packets that happen to land on a SEQ mapping over the port range — about
// 0.7 % for the whole default ladder. So after the two cheap rounds found no
// contact the ladder ends with hard_symmetric_random, as rnd_x_rnd does; the
// third rung runs only when the SEQ side's filtering admits more than that one
// endpoint. Like the summary verdict it reads only what natprobe itself
// measured (ClassifyInput.Measured), and the two rounds of real evidence come
// first.
func SeqRndVerdict(measured [2]protocol.PeerView, f protocol.Family) bool {
	for seq := range 2 {
		tr := familyTraits(measured[seq], f)
		if tr.Samples > 0 && CategoryOf(tr) == CatSEQ && tr.Filtering == protocol.FiltPDF && tr.FilteringConf == protocol.ConfHigh &&
			measuredRandom(measured[1-seq], f) {
			return true
		}
	}
	return false
}

// slowViable reports whether family fp can run the slow birthday of a
// Background session: a verified PDF × RND family whose PDF side
// may spray, with birthday rounds allowed at all (the tier is not off).
func slowViable(fp familyPlan, pol protocol.Policy) bool {
	tier := protocol.TightenBudget(pol.Budget).Birthday
	if c := fp.TierCap; c != "" && c.Rank() < tier.Rank() {
		tier = c
	}
	return fp.PairClass == PairPDFRnd && !fp.Unverified && fp.OpensA && tier.Rank() >= protocol.BirthdayConservative.Rank()
}

// adviceFor is what a failure of a session whose primary family is fp
// suggests: background_viable when the slow
// birthday can connect the pair — about 85% in its 45 s, against about 22%
// for the interactive ladder — relay_only when no mode is expected to:
// two random sides, a SEQ(APDF) × RND pair natprobe measured, or a
// pair rejected at summary time. Other pairs get no advice: a
// retry as before is the right move.
func adviceFor(fp familyPlan, reject protocol.Reason, pol protocol.Policy) protocol.Advice {
	switch {
	case reject == protocol.ReasonHardSymmetricRandom, fp.PairClass == PairRndRnd, fp.CheapOnly:
		return protocol.AdviceRelayOnly
	case slowViable(fp, pol):
		return protocol.AdviceBackgroundViable
	}
	return ""
}

// BackgroundOnly reports whether a pair of exits connects only through the
// slow birthday, from the strategy memory's scores for its key:
// the slow birthday succeeded (score ≥ +1) and every interactive rung of
// pdf_x_rnd that ran failed (none above 0, one below). score reads one
// variant's score; the coordinator passes its built-in memory's.
func BackgroundOnly(score func(VariantID) int8) bool {
	if score(vPDFRndSlow) < 1 {
		return false
	}
	failed := false
	for _, v := range ladderFor(PairPDFRnd) {
		s := score(v)
		if s > 0 {
			return false
		}
		failed = failed || s < 0
	}
	return failed
}

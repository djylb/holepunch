package plan

import (
	"net/netip"

	"github.com/djylb/holepunch/protocol"
)

// In pdf_x_seq the PDF side predicts the SEQ side's mapping toward the PDF
// side's observed endpoint: the SEQ side opens it with its Direct stage in
// the first round and refreshes it with the Direct stage of every later
// round, from the same socket to the same endpoint, so the mapping keeps
// its port. The predict stage drops the ports already sent to the IP
// (ExpandInput.Exclude), which is right for the speculative spread but
// means that when every packet of the first round toward the centre was
// lost on the way, the SEQ side's mapping, still alive, is never aimed at
// again. So a later round first sends the ports around the previous round's
// centre once more.

// resendStage is the Direct stage of a pdf_x_seq round from the second on
// that sends once more, one packet each, the ports at most two allocation
// steps around the centre role predicted for its peer in the previous round
// (FamilyRound.Center): the centre, one step after, one before, two after.
// The mapping it aims at is alive while the SEQ side refreshed it in that
// round, which its Direct stage toward this side did; consecutive rounds
// are seconds apart. So only the round right after a round of the same
// family with a centre resends, and not after a rescue round. The stage
// starts with the side's first spray stage and is part of the grant like
// any Direct stage (what is granted is what is sent); being a Direct
// stage, nothing already sent is taken off it. It is nil when there is
// nothing to resend, the side does not spray this round or the path is
// blocked.
func resendStage(in RoundInput, fp familyPlan, tmpl sideTmpl, role int, ip netip.Addr, ttlOK, blocked bool) *protocol.Stage {
	spray, ok := tmpl.firstSpray()
	if fp.PairClass != PairPDFSeq || blocked || !ip.IsValid() || !ok {
		return nil
	}
	last, ok := lastOutcome(in.Prev)
	if !ok || last.Rescue {
		return nil
	}
	var center uint16
	var prev VariantID
	for _, f := range last.Families {
		if f.Family == fp.Family {
			center, prev = f.Center[role], f.Variant
		}
	}
	vr, ok := familyVariant(prev, fp)
	if center == 0 || !ok || !roleTemplate(vr, fp.SideA, 1-role).direct() {
		return nil
	}
	step := int(familyTraits(in.Views[1-role], fp.Family).PortStep)
	if step == 0 {
		step = 1
	}
	var targets []netip.AddrPort
	// At most four ports, nearest first and forward first: a sequential
	// allocator only moves on.
	for _, k := range [...]int{0, 1, -1, 2} {
		p := wrapPort(int(center) + k*step)
		if avoidPort(p, nil) {
			continue
		}
		targets = append(targets, netip.AddrPortFrom(ip, p))
	}
	if len(targets) == 0 {
		return nil
	}
	return &protocol.Stage{Kind: protocol.StageDirect, AtMs: spray.atMs, Targets: targets, Repeats: 1, TTL: stageTTL(spray, ttlOK)}
}

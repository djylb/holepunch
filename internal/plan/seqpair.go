package plan

import (
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/protocol"
)

// A sequential endpoint-dependent NAT gives every new (internal endpoint,
// destination) pair the next port. Between the probe's anchor and a SEQ
// side's predict stage, the side's own packets move its allocator: its
// Direct targets, every earlier round's predict and random ports, the
// peer_targets it was sent, its sandwich probes and the re-observation
// probe. In seq_x_seq both sides spray, and each must aim at exactly
// the ports the other's spray allocates, so the planner counts those
// mappings (FamilyRound.Mapped, which the coordinator fills) instead of
// extrapolating by PortVelocity.

// SideMappings is how many new external mappings the family side fs makes
// on an endpoint-dependent NAT, split into its Direct stages' and its spray
// stages'. A Direct target maps once on every
// round socket that never sent to it before — the client keeps its round
// sockets and sends a round's Direct stages from the first Sockets of them,
// so sent(t), the most sockets that sent to t in earlier rounds, are the
// ones that already hold a mapping; sent may be nil. A target on a LAN
// address crosses no NAT. Every predict and random port is new: the client
// never sends one twice to an IP. A fresh socket maps once per
// destination, and a fresh_peer port is a new destination like a spray
// port.
func SideMappings(fs protocol.FamilySide, sent func(netip.AddrPort) int) (direct, spray int) {
	for _, st := range fs.Stages {
		switch st.Kind {
		case protocol.StageDirect:
			for _, t := range st.Targets {
				if netaddr.Private(t.Addr()) {
					continue
				}
				prev := 0
				if sent != nil {
					prev = sent(t)
				}
				direct += max(int(max(fs.Sockets, 1))-prev, 0)
			}
		case protocol.StagePredict:
			spray += int(st.Span)
		case protocol.StageRandom:
			spray += int(st.Count)
		case protocol.StageFresh:
			direct += int(st.Count) * max(len(st.Targets), 1)
		case protocol.StageFreshPeer:
			spray += int(st.Count)
		}
	}
	return direct, spray
}

// pairSeqWindows turns the predict stage of each seq_x_seq family whose two
// sides allocate sequentially into a paired stage (Stage.Pair): its window is
// exactly the ports the peer's own predict stage of the round allocates — just
// after the peer's last mapping before it (pairAnchor), forward only — and both
// sides get the same span, so that their pair orders cover the same positions
// (pairOrders). Cutting a span takes its packets and ports off the side's
// grant: MaxPackets stays what the stages expand to.
func pairSeqWindows(in input, picks []familyPick, sides *[2][]protocol.FamilySide) {
	for fi, p := range picks {
		fp := in.fams[fi]
		if !p.running() || !pairedFamily(in, fp) {
			continue
		}
		n := min(predictSpan(sides[0][fi]), predictSpan(sides[1][fi]))
		var (
			pre [2]int
			at  [2]time.Duration // when each side's predict stage starts, on the FireAt axis
		)
		for role := range 2 {
			pre[role] = preMappings(sides[role][fi], prevDirectSockets(in, fi, role))
			at[role] = in.FireAt + predictAt(sides[role][fi])
		}
		for role := range 2 {
			peer := 1 - role
			mine := &sides[role][fi]
			si := slices.IndexFunc(mine.Stages, func(st protocol.Stage) bool { return st.Kind == protocol.StagePredict })
			if si < 0 {
				continue
			}
			st := &mine.Stages[si]
			tr := familyTraits(in.Views[peer], fp.Family)
			step := int(tr.PortStep)
			if step == 0 {
				step = 1
			}
			anchor, ok := pairAnchor(in, peer, fp.Family, st.IP, tr, step, pre[peer], at[peer])
			if !ok {
				continue
			}
			st.Anchor, st.Steps, st.Pair = anchor, []int16{int16(step)}, true
			if cut := int(st.Span) - n; n > 0 && cut > 0 {
				st.Span = uint16(n)
				mine.MaxPackets -= uint32(cut)
				mine.MaxDistinctPorts = uint16(max(int(mine.MaxDistinctPorts)-cut, 1))
			}
		}
	}
}

// pairedFamily reports whether a family's predict stages are paired: a
// seq_x_seq family whose two sides both allocate sequentially. A pool
// allocates at random inside its block, where neither the window nor the
// pair order holds (as for the sandwich).
func pairedFamily(in input, fp familyPlan) bool {
	if fp.CatA != CatSEQ || fp.CatB != CatSEQ {
		return false
	}
	for r := range 2 {
		if familyTraits(in.Views[r], fp.Family).PortAlloc != protocol.AllocSequential {
			return false
		}
	}
	return true
}

// pairAnchor is the port role's NAT allocated last before the first mapping of
// its predict stage this round, on ip: a known point of its allocator advanced
// by step for every mapping role made since. pre is what role maps this round
// before its predict stage (preMappings).
//
// An anchor refresh made just before the round is where the
// allocator is now, read off the NAT itself: its newest mapping, past the
// refresh's own later mapping when only the first probe came, advanced by
// pre and by the others' drift it measured until at, when role's predict
// stage starts (refreshDrift). It stands alone: the points below are
// older and reach the present only through the counted mappings, and a
// count the NAT did not see — packets lost before it — would carry them
// past the allocator.
//
// Without a refresh, two points are known. The probe's anchor, PortAnchor
// on the IP it was measured on, is followed by every earlier round's
// mappings. A mapping of role seen while punching (in.Mappings: a seen_from
// its peer reported, a drifted mapping coord adopted) is followed by the
// mappings of the rounds after its own; those of its own round after it
// are not counted. Either is a lower bound of where the allocator is —
// other hosts behind the NAT only move it further — so the one further
// along wins.
//
// The window is not extrapolated by PortVelocity: natprobe measures it over
// a single gap, where one foreign mapping reads as tens of ports a second;
// the pair orders absorb the few foreign mappings a quiet NAT makes.
func pairAnchor(in input, role int, fam protocol.Family, ip netip.Addr, tr protocol.Traits, step, pre int, at time.Duration) (uint16, bool) {
	ip = ip.Unmap()
	if r, ok := refreshFor(in, role, fam, ip); ok {
		lambda, _ := refreshRate(in, role, r, tr, step)
		port, _, _, after := anchorNewest(r)
		return wrapPort(int(port) + step*(after+pre+refreshDrift(lambda, r, at))), true
	}
	var best uint16
	consider := func(port uint16, after int) {
		c := wrapPort(int(port) + step*(mappedSince(in, fam, role, after)+pre))
		if best == 0 || ahead(c, best, step) {
			best = c
		}
	}
	anchor := tr.PortAnchor
	if anchor == 0 {
		anchor = tr.Observed.Port()
	}
	if obs := tr.Observed.Addr().Unmap(); anchor != 0 && (!obs.IsValid() || obs == ip) {
		consider(anchor, 0)
	}
	for _, s := range in.Mappings[role] {
		if s.Addr.Addr().Unmap() == ip && s.Addr.Port() != 0 {
			consider(s.Addr.Port(), s.Round)
		}
	}
	return best, best != 0
}

// ahead reports whether port a is further than b along a sequential
// allocator of the given step, which wraps inside [1024, 65535]: the
// shorter way round from b to a goes in the step's direction.
func ahead(a, b uint16, step int) bool {
	d := ((int(a)-int(b))%portRange + portRange) % portRange // b → a going up
	if step > 0 {
		return d != 0 && d < portRange/2
	}
	return d > portRange/2
}

// mappedSince sums what role mapped in family fam in the rounds after round
// `after` (FamilyRound.Mapped).
func mappedSince(in input, fam protocol.Family, role, after int) int {
	n := 0
	for _, o := range in.Prev {
		if o.Round <= after {
			continue
		}
		for _, f := range o.Families {
			if f.Family == fam {
				n += f.Mapped[role]
			}
		}
	}
	return n
}

// predictAt is when a side's first predict stage starts after the fire.
func predictAt(fs protocol.FamilySide) time.Duration {
	for _, st := range fs.Stages {
		if st.Kind == protocol.StagePredict {
			return time.Duration(st.AtMs) * time.Millisecond
		}
	}
	return 0
}

// predictSpan is the span of a side's first predict stage, 0 without one.
func predictSpan(fs protocol.FamilySide) int {
	for _, st := range fs.Stages {
		if st.Kind == protocol.StagePredict {
			return int(st.Span)
		}
	}
	return 0
}

// preMappings is the mappings a side makes this round before its predict
// stage: the Direct targets it sends at or before the stage's start (the
// client sends due Direct packets before spray), on the sockets that never
// sent the Direct stage before (prevSockets).
func preMappings(fs protocol.FamilySide, prevSockets int) int {
	at := -1
	for _, st := range fs.Stages {
		if st.Kind == protocol.StagePredict {
			at = int(st.AtMs)
			break
		}
	}
	early := fs
	early.Stages = slices.DeleteFunc(slices.Clone(fs.Stages), func(st protocol.Stage) bool {
		return st.Kind != protocol.StageDirect || (at >= 0 && int(st.AtMs) > at)
	})
	direct, _ := SideMappings(early, func(netip.AddrPort) int { return prevSockets })
	return direct
}

// prevDirectSockets is the most sockets role sent Direct stages from in an
// earlier round of family fi, by the ladder templates and the first
// round's baseline (takesBaseline): the Direct targets — the peer's
// verified endpoints — are the same every round.
func prevDirectSockets(in input, fi, role int) int {
	fp := in.fams[fi]
	n := 0
	for _, o := range in.Prev {
		v, ok := familyVariantOf(o, fi, fp.Family)
		if !ok {
			continue
		}
		if o.Rescue {
			v = vRescue
		}
		if vr, ok := familyVariant(v, fp); ok {
			if t := roleTemplate(vr, fp.SideA, role); t.direct() || o.Round == 1 && takesBaseline(fp, role) {
				n = max(n, int(t.sockets))
			}
		}
	}
	return n
}

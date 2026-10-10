package plan

import (
	"net/netip"
	"slices"

	"github.com/djylb/holepunch/protocol"
)

// The plain-punching baseline. Ordinary hole
// punching — both sides sending to each other's observed endpoint as the
// round fires, the Plain ablation's one round — is a subset of every
// plan: in a session's first round each side's primary socket sends to its
// peer's verified Direct targets at the normal TTL as the side fires, in
// all at least as many packets as Plain's round sends, whatever rung the
// ladder or the strategy memory starts on. A classification that is wrong
// either way then costs packets, never a connection plain punching would
// have made. The one exception is the side that by design only
// replies, the OPEN side of open_x_edm: an endpoint-dependent peer never
// sends from the endpoint its packets would go to, and its one Direct
// packet only opens its own filter.

// Baseline sizes. plainPackets is what the Plain ablation's round sends a
// side's peer: easy_r1_direct's D(5) to the one endpoint a single probe
// port verifies. baselineRepeats is the least each target gets:
// the two endpoints a full probe verifies — the peer's primary and second
// sockets' mappings — take three each, six in all.
const (
	plainPackets    = 5
	baselineRepeats = 3
)

// baselineRepeatsFor is how many packets each of n verified targets gets in
// the baseline: baselineRepeats, or more where so few targets would leave
// the side short of plainPackets.
func baselineRepeatsFor(n int) uint8 {
	return uint8(max(baselineRepeats, ceilDiv(plainPackets, max(n, 1))))
}

// takesBaseline reports whether role sends the baseline in a first round of
// family fp: a verified family, other than the OPEN side of open_x_edm. An
// unverified family has no verified targets; its rounds are Direct only
// anyway (directOnly).
func takesBaseline(fp familyPlan, role int) bool {
	return !fp.Unverified && !(fp.PairClass == PairOpenEDM && role == roleIndex(fp.SideA))
}

// withBaseline returns a first round's Direct stages with the baseline in
// them: the stage that fires with the side — at its send delay, which
// every stage waits for — at the normal TTL toward the peer's targets gets
// at least baselineRepeatsFor them; without such a stage, a baseline stage
// is put first. A low-TTL stage does not count: its packets stop short of
// the peer's NAT.
func withBaseline(direct []protocol.Stage, targets []netip.AddrPort, sendDelayMs uint16) []protocol.Stage {
	reps := baselineRepeatsFor(len(targets))
	for i, st := range direct {
		if st.Kind == protocol.StageDirect && st.TTL == 0 && st.AtMs <= sendDelayMs && slices.Equal(st.Targets, targets) {
			direct[i].Repeats = max(st.Repeats, reps)
			return direct
		}
	}
	base := protocol.Stage{Kind: protocol.StageDirect, Targets: slices.Clone(targets), Repeats: reps}
	return append([]protocol.Stage{base}, direct...)
}

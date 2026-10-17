// Package plan is the pure-function direct-connection strategy engine the
// server coordinator (coord) and the client runtime share.
//
// It has two faces, both pure and free of goroutines and I/O:
//
//   - The server face. CategoryOf maps one side's protocol.Traits to a NAT
//     category and PairClass combines two categories into a ladder
//     name. DefaultPlanner.Classify turns the merged peer views into a
//     Classification: the shared families, each family's own ladder, the
//     canonical side mapping, whether each side may open a birthday round and
//     the NAT66 birthday cap. The classification is a hint the rounds
//     correct: Classify ends a session before any punch
//     (hard_symmetric_random) only when natprobe itself measured both sides
//     of every shared family as Random with High confidence
//     (ClassifyInput.Measured) and no rung after the two cheap ones can
//     run; a seq_x_rnd pair natprobe measured as SEQ with APDF filtering
//     against Random, both at High confidence, ends with the same reason
//     once its two cheap rounds found no contact (SeqRndVerdict).
//     A random side whose fresh socket keeps its local port
//     (AllocPreserveFresh) turns pdf_x_rnd and rnd_x_rnd into pdf_x_pres
//     and pres_x_pres: fresh sockets at ports both sides draw from the pair
//     seed instead of a birthday (FreshPorts). In a Background
//     session pdf_x_rnd runs the slow birthday, the background class's
//     long, gentle round; Classification.Advice tells a failed
//     session's caller whether that is worth it (background_viable) or the
//     relay is all there is (relay_only), and BackgroundOnly reads the
//     strategy memory's verdict that only the slow birthday connects a pair.
//     An EIM side a STUN server contradicted (Traits.PathDependent)
//     is classified as endpoint dependent from the start, and the peer
//     aims at its STUN mapping on the verified IP as one more Direct
//     target; an easy family that found no contact in two consecutive
//     rounds plans its doubtful EIM sides as endpoint dependent from then
//     on (escalate).
//     DefaultPlanner.Round turns the per-round input into a
//     RoundDecision. Each family advances its own ladder (recorded in
//     RoundDecision.Families and fed back through RoundOutcome.Families) under
//     its own BirthdayTier, extreme and two-sided-birthday gates; the round's
//     class is the highest family class under the escalation guard, and the
//     families share each side's sockets, packets and new-target bucket. Whatever rung a
//     session starts on — the ladder's first or one the strategy memory
//     promoted — its first round contains plain hole punching: each side's
//     primary socket sends to the peer's verified endpoints at the normal
//     TTL as the side fires, at least as many packets as the Plain
//     ablation's round, the OPEN side of open_x_edm excepted
//     (withBaseline). Both sides' plans come from one classification, so
//     they never disagree on how hard the pair is. Round also owns the
//     rescue round (built in the family of the one-way evidence), the stop
//     rules and the packet invariant: every side's MaxPackets is exactly
//     what its stages expand to — Direct from every socket to every
//     target, Direct trimmed first when the grant is short. A sequential peer's predicted
//     window is centred on its port extrapolated to the round's fire time,
//     anchor + step + velocity·Δt, re-anchored on the mappings seen while
//     punching; from the second round of pdf_x_seq on, the
//     ports around the previous round's centre are sent once more.
//     In seq_x_seq the two predict stages are paired instead
//     (Stage.pair): each aims forward, without extrapolation, at exactly the
//     ports the peer's own predict stage allocates — the peer's anchor
//     advanced by the mappings it made since, which the coordinator counts
//     into RoundOutcome.Families[].Mapped (SideMappings) — with the
//     same span on both sides; their orders pair every shift up to four
//     positions on either side in a window of 16. Before a round
//     the coordinator may refresh a SEQ side's anchor — always in a paired
//     family, on noise evidence elsewhere, never in a family natprobe
//     found hopeless (RefreshWanted) — and the planner then aims at
//     the refresh's newest mapping, read off the NAT and so preferred to
//     any counted anchor, advanced by the others' rate since the probe's
//     anchor, kept short (RoundInput.Refresh). The sandwich probe is set
//     only on a SEQ side whose peer is endpoint independent, per family, and
//     a rescue sender behind an APDM NAT only replies. Every target is one
//     the client admits: a verified IP of the peer; in a family the
//     server could not verify (pair.unverified) Direct stages only, to at
//     most four of the global addresses the peer reported — sixteen when no
//     family is verified, the NoObserver mode — eight packets each, in
//     a light round; on a shared LAN (pair.same_lan) a Direct stage of its
//     own toward the peer's LAN endpoints, four targets of two packets each
//     at most, before the public ones. Upstream-LAN candidates are not plan
//     targets: the coordinator pushes them as peer_targets. The
//     equality "MaxPackets = what the stages expand to" is the planner's
//     contract; the coordinator's clamps may leave a side with less or
//     more. coord wraps these two methods; the dependency runs coord ->
//     internal/plan and never the reverse (this package imports neither
//     coord nor internal/nat).
//
//   - The client face. ExpandStage and DirectOffsets turn one protocol.Stage
//     plus the 8-byte spray seed into the concrete, ordered target sequence the
//     sender emits — predicted ports, random ports, Direct repeat offsets, the
//     sensitive/sub-1024 filter, the deterministic scatter and the hard "no run
//     of more than three consecutive ports" fixup; ScatterPorts gives a
//     peer_targets port window the same scatter. The spray seed is
//     udpwire.SpraySeed(token, route, role, round, seed), computed by the
//     caller; the same seed reproduces the same sequence on both peers, while a
//     different session, round or role yields a different one. A paired predict
//     stage (ExpandPaired) is ordered by the initiator's spray seed on both
//     sides instead, so that the two orders pair the sides' mappings: the one
//     exemption from "role in the seed".
//
// Attribute is the failure-attribution decision table shared by both sides.
//
// Production code here depends only on the standard library and protocol; the
// spray seed arrives as a [8]byte, so the package never imports udpwire (only
// the tests do, to build seeds with udpwire.SpraySeed). It starts no
// goroutines, does no I/O and keeps no package-level mutable state: the variant
// table is built once at initialisation and only read afterwards, so a Round
// costs no table construction.
package plan

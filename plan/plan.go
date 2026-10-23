package plan

import (
	"net/netip"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Planner decides the punch. Both methods must be pure functions of their
// input: a planner keeps no state between calls, and everything a later
// Round needs is in its RoundInput. A planner may write its input, which
// is its own copy.
type Planner interface {
	// Classify runs once, when both probe reports are in.
	Classify(in ClassifyInput) Classification
	// Round runs before every round.
	Round(in RoundInput) RoundDecision
}

// VariantID identifies a round template of the built-in catalogue, which
// has at most 32 of them; 0 is no variant. The variant's name travels on
// the wire as the round plan's variant.
type VariantID uint8

// RoundClass is the coordinator's reading of a finished round. A planner
// reads the previous rounds' classes to decide how to go on.
type RoundClass uint8

// Round classes.
const (
	RoundNoReport    RoundClass = iota // one side's round_result is missing
	RoundConfirmed                     // a side confirmed; no further round
	RoundConfirmLost                   // both sides saw each other, no confirmation
	RoundOneWay                        // only one direction carried packets
	RoundNoContact                     // no peer packet either way
	RoundBlocked                       // udp_blocked, or ICMP unreachable >= 50
)

// ClassifyInput is the classification input. Every view is by role: the
// server's merged view of the side exactly as the clients receive it.
type ClassifyInput struct {
	Initiator protocol.PeerView
	Responder protocol.PeerView
	// Measured is, by role (0 initiator, 1 responder), what natprobe itself
	// measured of each family it observed, before the traits memory: a
	// family natprobe did not observe is absent, and so is the whole view
	// when the coordinator runs without a natprobe registry. Initiator and
	// Responder may carry a client's self-reported traits or a conclusion
	// the traits memory raised; these traits do not.
	Measured [2]protocol.PeerView
	// Pair holds the facts about the pair: the families the server could
	// not verify (Pair.Unverified: Direct stages to self-reported global
	// addresses only), the pairs that share a LAN (Pair.LikelySameLAN) or
	// overlay addresses (Pair.SharedOverlay).
	Pair     protocol.PairFacts
	Policy   protocol.Policy
	Timeouts protocol.Timeouts
	// Features are the optional features both clients negotiated.
	Features []protocol.Feature
	// Mode is the session's mode: background only when the caller offered
	// it and both clients accepted it.
	Mode protocol.SessionMode
}

// Classification is the one-shot classification. PairClass, SideA and
// Ladder describe the primary family, Families[0]: the coordinator derives
// the pair's StrategyKey from its SideA and the views, reorders Ladder by
// the strategy memory into RoundInput.Order and reports PairClass.
type Classification struct {
	// Reject, when set, ends the session before any punch with this
	// reason; Round is not called.
	Reject protocol.Reason
	// PairClass is the primary family's diagnostic ladder name, sent to
	// the clients when it has the wire name syntax.
	PairClass string
	// Families are the shared families the rounds run, in priority order
	// (v6 first). An empty list rejects the session (no_common_family).
	Families []protocol.Family
	// SideA is the primary family's canonical (rule) side: the same pair
	// of NAT exits has the same SideA whichever client initiates.
	SideA protocol.Role
	// Ladder is the primary family's variants, cheap to expensive. The
	// class of Ladder[0] caps the first round (at most balanced) unless the
	// strategy memory promoted a variant proven for the pair.
	Ladder []VariantID
	// Advice is what a failure of the session suggests; the summaries
	// carry it.
	Advice protocol.Advice
}

// Evidence is the cross-round accumulation of both clients' round results,
// by role (0 initiator, 1 responder).
type Evidence struct {
	SeenFrom    [2][]netip.AddrPort // deduplicated peer sources, at most 8 a side
	Hit         [2]bool             // the side heard its peer
	PeerSeenUs  [2]bool             // the peer reported hearing the side
	Sent        [2]uint32           // packets the side initiated
	Fired       [2]bool             // the side entered the fire window at least once
	Drift       [2]bool             // the side's mapping moved while punching
	ICMPUnreach [2]uint16           // ICMP unreachable messages the side received
	BindFailed  [2]uint16           // sockets the side failed to bind
	BudgetHit   [2]bool             // the side ran out of its grant
	Fatal       [2]protocol.Reason  // the side's fatal reason, if any
}

// FamilyRound is what one shared family runs in a round. A planner fills
// Family, Variant, Budget and Center in RoundDecision.Families; the
// coordinator copies them into the round's RoundOutcome.Families and adds
// Mapped, Heard and NoContact, which a planner leaves zero.
type FamilyRound struct {
	Family protocol.Family
	// Budget is the family's effective class; RoundDecision.Budget is the
	// highest of them. It is empty for a family whose ladder is exhausted.
	Budget protocol.BudgetClass
	// Mapped is, by role, how many new external mappings the round made in
	// the family on the side's NAT: its granted plan's new (socket,
	// destination) pairs, cut to the distinct ports the client reported,
	// the peer_targets it was sent, and its sandwich, re-observation and
	// anchor-refresh probes. A sequential endpoint-dependent NAT allocates
	// one port per mapping, so it tells how far the side's next port moved.
	Mapped [2]int
	// Center is, by role, the port the role's predict stage centred on,
	// 0 without one.
	Center [2]uint16
	// Heard is, by role, whether the side heard its peer in the family
	// during the round: a hit or a peer source.
	Heard [2]bool
	// Variant is the family's variant this round, or 0 once its ladder is
	// exhausted: its sides then only reply while another family still runs.
	Variant VariantID
	// NoContact: neither side heard the other in the family during the
	// round, and neither saw the path blocked.
	NoContact bool
}

// RoundOutcome summarises a finished round.
type RoundOutcome struct {
	// Budget is the class the coordinator actually granted the round,
	// which may be lower than the decision's.
	Budget protocol.BudgetClass
	// SeenFrom and Hit are the round's own evidence by role — the
	// round_result seen_from (deduplicated) and hit — where Evidence is
	// cumulative.
	SeenFrom [2][]netip.AddrPort
	// Families is the round's RoundDecision.Families with the coordinator's
	// per-family results added.
	Families []FamilyRound
	// Round is the round's number, from 1.
	Round int
	// Hit is, by role, whether the side reported a hit: a peer packet that
	// authenticated during the round.
	Hit [2]bool
	// Variant is the variant the round ran (RoundDecision.Variant).
	Variant VariantID
	// Class is the coordinator's reading of the round from both sides'
	// round_result.
	Class RoundClass
	// Rescue reports that the round was the rescue round the coordinator
	// adds after the ladder's last.
	Rescue bool
}

// MappingSample is one external mapping of a side observed while punching.
type MappingSample struct {
	Addr  netip.AddrPort
	At    time.Duration // when it was observed, on the RoundInput.FireAt axis
	Round int           // the round it was observed in
}

// AnchorRefresh is one family's anchor refresh by one side: the mappings of
// two new sockets, each made by a single probe about 60 ms apart, and when
// natprobe saw them, on the RoundInput.FireAt axis. A probe that did not
// come in time is the zero AddrPort: a refresh carries one probe or both.
type AnchorRefresh struct {
	Family            protocol.Family
	First, Second     netip.AddrPort
	FirstAt, SecondAt time.Duration
}

// RoundInput is the per-round planner input. Everything by role is
// indexed 0 for the initiator and 1 for the responder.
type RoundInput struct {
	Round int
	// Class is the session's classification.
	Class Classification
	// Order is Class.Ladder as the strategy memory reordered it; empty
	// means Class.Ladder.
	Order    []VariantID
	Prev     []RoundOutcome
	Evidence Evidence
	RTT      [2]time.Duration
	// Remaining is the punch deadline minus now; D is the coordinator's
	// start margin, which Remaining still contains.
	Remaining time.Duration
	D         time.Duration
	// BudgetLeft is each side's remaining grantable packets; negative
	// means unlimited.
	BudgetLeft [2]int
	// Recent10sDistinct is, by role, the distinct ports already granted
	// toward the peer's IP in the last 10 s.
	Recent10sDistinct [2]int
	Gone              [2]bool // the side's control link is gone
	RescueUsed        bool    // the session's one rescue round ran
	// Views are the planner views by role: the ClassifyInput views and the
	// endpoints the coordinator admitted since.
	Views [2]protocol.PeerView
	// Measured, Pair and Mode are those of the ClassifyInput.
	Measured     [2]protocol.PeerView
	Pair         protocol.PairFacts
	Mode         protocol.SessionMode
	Policy       protocol.Policy
	AllowExtreme bool   // the coordinator allows the extreme class
	MaxRounds    int    // rounds the session may run, the rescue round not counted
	HandshakeMs  uint32 // the session's handshake_timeout_ms
	SandwichOK   bool   // both sides negotiated the sandwich feature
	// MemoryPromoted reports that the strategy memory moved a variant proven
	// for the pair to the front of Order: the first round may then rise
	// above the class of Ladder[0], up to heavy.
	MemoryPromoted bool
	// FireAt is when this round is expected to fire, on the server's
	// monotonic axis whose origin is the session's natprobe registration —
	// the axis of protocol.Traits.PortAnchorMs. Zero means unknown.
	FireAt time.Duration
	// Mappings are, by role, the side's external mappings observed while
	// punching: the sources its peer reported and the remotes of the
	// peer_seen about it, at most 16 a side.
	Mappings [2][]MappingSample
	// Refresh are, by role, the anchor refreshes the coordinator had the
	// side make just before this round: where its sequential allocator is
	// now and how fast other hosts move it.
	Refresh [2][]AnchorRefresh
}

// RoundDecision is the per-round planner output.
type RoundDecision struct {
	// Stop, when set, ends the punch with this reason; Sides is then
	// ignored.
	Stop protocol.Reason
	// StopDetail is the detail of a Stop (punch_result.detail).
	StopDetail string
	// VariantName and Variant name the round on the wire and in the
	// strategy memory: the primary family's variant, or that of the family
	// still running once the primary ladder is exhausted.
	VariantName string
	// Budget is the round's class, the highest of the families'.
	Budget protocol.BudgetClass
	// Sides are by role, each with one FamilySide per entry of Families.
	// The coordinator keeps a side's Sandwich only when both sides
	// negotiated the feature.
	Sides [2][]protocol.FamilySide
	// Families is what each shared family runs, in Class.Families order.
	Families []FamilyRound
	// Window is the round's duration.
	Window  time.Duration
	Variant VariantID // see VariantName
	// Final marks the session's last round.
	Final  bool
	Rescue bool // the round is the session's rescue round
}

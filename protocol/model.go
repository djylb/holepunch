package protocol

import (
	"math"
	"net/netip"
	"time"
)

// Shared sub-structures of the control messages. The JSON tag is the wire
// field name. Addresses are netip values, encoded as their
// text form ("1.2.3.4:5", "[2001:db8::1]:5"); optional ones use omitzero so
// that a zero value is left out instead of encoded as "".

// ---- capabilities ----

// ClientCaps is probe_report.caps: this host's runtime capabilities for the
// session (not protocol semantics).
type ClientCaps struct {
	Impl       string          `json:"impl"`               // "holepunch-go/1.0.0", <= 64 B
	Families   []FamilyCaps    `json:"families"`           // <= 2
	MaxSockets uint16          `json:"max_sockets"`        // sockets this host can use for the session
	PortMap    []PortMapMethod `json:"port_map,omitempty"` // enabled methods: pcp | natpmp | upnp
}

// FamilyCaps is one family's capabilities.
type FamilyCaps struct {
	Family  Family `json:"family"`
	LowTTL  bool   `json:"low_ttl"`            // per-packet TTL / hop limit
	RecvErr bool   `json:"recv_err,omitempty"` // Linux IP_RECVERR (ICMP soft-signal counting)
}

// ---- probing ----

// ProbeSpecVersion is the only ProbeSpec.V this implementation runs; any
// other value is control_version_mismatch with detail probe_v.
const ProbeSpecVersion = 3

// MaxProbeSTUN is the most STUN servers a ProbeSpec lists. A client asks at
// most 8 of each family, all at once.
const MaxProbeSTUN = 16

// ProbeSpec is punch_start.probe.
type ProbeSpec struct {
	Observers    []ObserverSpec   `json:"observers"`             // <= 16
	STUN         []netip.AddrPort `json:"stun,omitempty"`        // <= MaxProbeSTUN; literal addresses
	RTTHintMs    uint16           `json:"rtt_hint_ms,omitempty"` // known control-link RTT; omitted when unknown
	V            uint8            `json:"v"`                     // ProbeSpecVersion
	ExtraReply   bool             `json:"extra"`                 // hint only; the ack declares what is really sent
	SecondSocket bool             `json:"second_socket"`         // probe a second socket when APDM is suspected
	Siblings     uint8            `json:"siblings"`              // sibling interfaces to probe, clamped to 2
}

// ObserverSpec is one natprobe observer.
type ObserverSpec struct {
	ID    uint8          `json:"id"`
	Addr  netip.AddrPort `json:"addr"`  // literal ip:port
	Group uint8          `json:"group"` // same group = same server public IP
	Alt   bool           `json:"alt,omitempty"`
}

// SocketKind is SocketReport.Kind.
type SocketKind string

// Socket kinds.
const (
	SocketPrimary SocketKind = "primary"
	SocketSecond  SocketKind = "second"
	SocketSibling SocketKind = "sibling"
)

// FamilyReport is one family of probe_report.families.
type FamilyReport struct {
	Family     Family         `json:"family"`
	Failure    Reason         `json:"failure,omitempty"`     // probe_timeout | udp_blocked | no_probe_endpoint | internal
	Sockets    []SocketReport `json:"sockets"`               // [0] is the primary socket; <= 6
	Filters    []FilterReport `json:"filters,omitempty"`     // <= 24
	STUN       []RowReport    `json:"stun,omitempty"`        // self-reported; <= 8
	PortMap    *PortMapReport `json:"port_map,omitempty"`    // self-reported; later results go in punch_ready
	LocalAddrs []netip.Addr   `json:"local_addrs,omitempty"` // <= 16; overlay addresses left out
	// Overlay are the host's addresses of the family on overlay, tunnel and
	// virtual-bridge interfaces (Tailscale, WireGuard, ZeroTier, docker …)
	// and in 100.64/10, on which the primary socket also listens: they are
	// candidates of their own kind, never LAN ones. Empty when the client
	// excludes them or binds its primary
	// socket to one address; <= 2.
	Overlay []netip.Addr `json:"overlay,omitempty"`
	Traits  Traits       `json:"traits"` // client provisional; the server recomputes
}

// SocketReport is one probed socket.
type SocketReport struct {
	ID    uint8          `json:"id"` // sock = family<<7 | index
	Kind  SocketKind     `json:"kind"`
	Local netip.AddrPort `json:"local"`
	Rows  []RowReport    `json:"rows"` // one per observer (first value); <= 16
}

// RowReport is one (socket, observer) observation.
type RowReport struct {
	Observer uint8          `json:"o"`
	Observed netip.AddrPort `json:"a,omitzero"`    // the value in the ack (the server overrides it)
	FirstSeq uint32         `json:"tx"`            // seq of the row's first probe
	SentMs   uint32         `json:"s"`             // relative to the probe start
	RTTMs    uint16         `json:"rtt,omitempty"` // 0 = no ack
	Cookie   uint32         `json:"c,omitempty"`   // COOKIE of the row's latest ack; 0 = no ack
}

// FilterReport counts extra/alt replies seen by the client.
type FilterReport struct {
	Socket    uint8 `json:"socket"`
	Observer  uint8 `json:"observer"`
	ExtraSeen uint8 `json:"extra_seen"`
	AltSeen   uint8 `json:"alt_seen"`
}

// PortMapMethod is the port-mapping protocol that produced a mapping.
type PortMapMethod string

// Port-mapping methods.
const (
	PortMapUPnP   PortMapMethod = "upnp"
	PortMapPCP    PortMapMethod = "pcp"
	PortMapNATPMP PortMapMethod = "natpmp"
)

// Valid reports whether m is one of the three methods.
func (m PortMapMethod) Valid() bool { return m == PortMapUPnP || m == PortMapPCP || m == PortMapNATPMP }

// PortMapReport is a port-mapping result on the wire (port_map).
type PortMapReport struct {
	Method       PortMapMethod  `json:"method"`
	External     netip.AddrPort `json:"external,omitzero"`
	Internal     netip.AddrPort `json:"internal,omitzero"`
	LeaseSeconds uint32         `json:"lease_seconds"`
}

// PortMappingInfo is the port mapping held by a session (holepunch Result,
// portmapper.Mapper.Map). Report gives its wire
// form.
type PortMappingInfo struct {
	Method   PortMapMethod
	External netip.AddrPort
	Internal netip.AddrPort
	Lease    time.Duration
}

// Report is the wire form of i; the lease is rounded down to whole seconds.
func (i PortMappingInfo) Report() PortMapReport {
	secs := int64(i.Lease / time.Second)
	return PortMapReport{Method: i.Method, External: i.External, Internal: i.Internal,
		LeaseSeconds: uint32(min(max(secs, 0), math.MaxUint32))}
}

// ClockSample is the minimum-RTT sample of the UDP probe path. The offset is
// diagnostic only: no protocol decision reads a wall clock.
type ClockSample struct {
	RTTMs    uint32 `json:"rtt_ms"`
	OffsetMs int64  `json:"offset_ms"`
}

// Transport is the client's upper-layer transport offer.
type Transport struct {
	Mode string `json:"mode"`           // a name of <= 16 B, or empty
	Data string `json:"data,omitempty"` // opaque, <= 8 KiB (a QUIC certificate, for example)
}

// TransportPick is the server's transport decision, the same on both sides.
type TransportPick struct {
	Mode     string `json:"mode"`
	PeerData string `json:"peer_data,omitempty"` // the peer's Transport.Data, verbatim
}

// ---- server views ----

// PeerView is the server's authoritative view of one client.
type PeerView struct {
	Families []FamilyView `json:"families"` // <= 2
}

// FamilyView is one family of a PeerView.
type FamilyView struct {
	Family    Family     `json:"family"`
	Traits    Traits     `json:"traits"`
	Endpoints []Endpoint `json:"endpoints"` // <= 12
}

// EndpointSource says where an Endpoint comes from.
type EndpointSource string

// Endpoint sources.
const (
	EndpointServer  EndpointSource = "server"
	EndpointSecond  EndpointSource = "second"
	EndpointSibling EndpointSource = "sibling"
	EndpointSTUN    EndpointSource = "stun"
	EndpointPortmap EndpointSource = "portmap"
	EndpointLAN     EndpointSource = "lan"
	// EndpointOverlay is an overlay address of the client at its primary
	// socket's port (FamilyReport.Overlay).
	EndpointOverlay EndpointSource = "overlay"
	// EndpointLocalPort is the verified public IP at the primary socket's local
	// port, when natprobe saw that socket at another port: a NAT that keeps the
	// local port on the path toward the peer maps it there. A guess, never
	// verified.
	EndpointLocalPort EndpointSource = "local_port"
)

// Endpoint is a candidate address of a client.
type Endpoint struct {
	Addr     netip.AddrPort `json:"addr"`
	Source   EndpointSource `json:"src"`
	Socket   uint8          `json:"sock"`
	Verified bool           `json:"v"` // recorded by the server and its cookie echoed
}

// PairFacts holds what only a server seeing both clients can compute.
type PairFacts struct {
	SharedFamilies []Family        `json:"shared_families"` // v6 first
	SamePublicIP   map[Family]bool `json:"same_public_ip,omitempty"`
	LikelySameLAN  map[Family]bool `json:"same_lan,omitempty"`
	// SharedOverlay marks the families in which both clients reported
	// overlay addresses: each may aim at the other's.
	SharedOverlay map[Family]bool `json:"shared_overlay,omitempty"`
	ProbeRTTMs    map[Role]uint32 `json:"probe_rtt_ms,omitempty"`    // by role
	ClockOffsetMs map[Role]int64  `json:"clock_offset_ms,omitempty"` // by role; diagnostic
	// Unverified marks the families whose peer endpoints the server could not
	// verify: every family when the coordinator runs without a natprobe
	// registry, or a family the server has no observer for. Such a
	// family carries only Direct stages to self-reported global addresses.
	Unverified map[Family]bool `json:"unverified,omitempty"`
}

// ---- plans ----

// PlanSpec is probe_summary.plan.
type PlanSpec struct {
	ID        string    `json:"id"`               // 1..64 B of [A-Za-z0-9_-]
	PairClass string    `json:"pair_class"`       // diagnostic name, e.g. "pdf_x_seq"
	RoundsMax uint8     `json:"rounds_max"`       // 1..6 (<= timeouts.max_rounds; rescue not counted)
	Ladder    []string  `json:"ladder,omitempty"` // informative; <= 16 names
	Budget    Budget    `json:"budget"`           // this side's session budget
	Round1    RoundPlan `json:"round1"`           // the first round, for pre-binding
	// Mode is the session's mode: background only when the server offered
	// it and both clients accepted it.
	Mode SessionMode `json:"mode,omitempty"`
	// Advice is what to do should the session fail.
	Advice Advice `json:"advice,omitempty"`
	// BackgroundOnly: the server's strategy memory saw this pair of exits
	// connect only through the slow birthday of a Background session; the
	// caller may go to the relay and Background at once.
	BackgroundOnly bool `json:"background_only,omitempty"`
}

// RoundPlan is one round for this side.
type RoundPlan struct {
	Round    uint8        `json:"round"`            // 1..8 (rescue rounds take a number too)
	Variant  string       `json:"variant"`          // diagnostic / memory name
	Budget   BudgetClass  `json:"budget"`           // the round's ceiling class
	WindowMs uint16       `json:"window_ms"`        // from firing; <= 10000
	Final    bool         `json:"final,omitempty"`  // no round follows
	Rescue   bool         `json:"rescue,omitempty"` // rescue round
	Seed     uint32       `json:"seed"`             // server random; input of the spray seed
	Sides    []FamilySide `json:"sides"`            // 1..2, this side only
}

// SideRole is FamilySide.Role.
type SideRole string

// Side roles: who initiates in a round.
const (
	SideSender    SideRole = "sender"
	SideReceiver  SideRole = "receiver"
	SideBoth      SideRole = "both"
	SideReplyOnly SideRole = "reply_only"
)

// FamilySide is one family's part of a round.
type FamilySide struct {
	Family           Family   `json:"family"`
	Role             SideRole `json:"role"`
	SendDelayMs      uint16   `json:"send_delay_ms,omitempty"` // <= 3000
	Sockets          uint16   `json:"sockets"`                 // 1..256
	MaxPackets       uint32   `json:"max_packets"`             // initiated packets this round
	MaxPPS           uint16   `json:"max_pps"`                 // <= 1500
	MaxNewPerSec     uint16   `json:"max_new_per_sec"`         // <= 256
	MaxDistinctPorts uint16   `json:"max_distinct_ports"`      // per peer IP this round
	// OpenPerSec paces the side's sockets beyond the primary: the k-th is
	// opened k/OpenPerSec seconds after firing, sends its Direct stages then —
	// each target's repeats spread over the rest of the window, so its mapping
	// stays alive — and is closed when the round ends unless it heard the peer.
	// 0 opens them all before firing, kept for later rounds. Set for the slow
	// birthday of a Background session.
	OpenPerSec uint16 `json:"open_per_sec,omitempty"`
	// Sandwich runs the sandwich probe in this family, only when
	// the feature was negotiated. It is per family: the coordinator matches
	// a probe to the family whose round it brackets, so the two families of
	// a dual-stack side never mix their windows.
	Sandwich bool    `json:"sandwich,omitempty"`
	Stages   []Stage `json:"stages"` // 1..8
}

// StageKind is Stage.Kind.
type StageKind string

// Stage kinds.
const (
	StageDirect    StageKind = "direct"
	StagePredict   StageKind = "predict"
	StageRandom    StageKind = "random"
	StageReplyOnly StageKind = "reply_only"
	// StageFresh binds Count fresh sockets, beyond the side's Sockets, at
	// the local ports FreshPorts draws from the initiator's spray seed of
	// the round, on a NAT whose fresh socket keeps its local port for its
	// first mapping (AllocPreserveFresh). Each
	// sends Repeats packets to every one of Targets — the peer's endpoints
	// — or, when IP is set instead (the peer runs a fresh stage too), to
	// IP and the port of the same draw. They are released at the round's
	// end unless they heard the peer.
	StageFresh StageKind = "fresh"
	// StageFreshPeer aims at the peer's fresh sockets: Repeats packets from
	// the primary socket to IP and each of the Count ports of the same draw.
	StageFreshPeer StageKind = "fresh_peer"
)

// Stage is one stage of a round.
type Stage struct {
	Kind    StageKind        `json:"kind"`
	AtMs    uint16           `json:"at_ms"`             // relative to firing
	Targets []netip.AddrPort `json:"targets,omitempty"` // direct: <= 16
	IP      netip.Addr       `json:"ip,omitzero"`       // predict / random target IP
	Anchor  uint16           `json:"anchor,omitempty"`  // predict start port
	Steps   []int16          `json:"steps,omitempty"`   // predict steps, <= 3, may be negative
	Span    uint16           `json:"span,omitempty"`    // predict ports, <= 4096
	Count   uint16           `json:"count,omitempty"`   // random ports, <= 4096
	Lo      uint16           `json:"lo,omitempty"`      // random range low (optional)
	Hi      uint16           `json:"hi,omitempty"`      // random range high (optional; 0 = 65535)
	Repeats uint8            `json:"repeats,omitempty"` // direct repeats per target, <= 8
	TTL     uint8            `json:"ttl,omitempty"`     // 0 = system default; [2,64] = low TTL for initiated packets
	// Pair marks a paired predict stage, the predict stage of seq_x_seq: its
	// ports are the Span ports Anchor+Steps[0]·1 … Anchor+Steps[0]·Span,
	// wrapping inside [1024, 65535] — exactly where the peer's sequential NAT
	// allocates the mappings of the peer's own paired stage — sent in an order
	// both sides draw from the initiator's spray seed of the round, so that
	// their mappings target each other in pairs (internal/plan.ExpandPaired).
	// Only a predict stage may be paired.
	Pair bool `json:"pair,omitempty"`
}

// FreshSockets is how many fresh sockets the side binds this round: the
// Count of its fresh stage, 0 without one (StageFresh). They come on top
// of Sockets in every socket limit.
func (s FamilySide) FreshSockets() int {
	for _, st := range s.Stages {
		if st.Kind == StageFresh {
			return int(st.Count)
		}
	}
	return 0
}

// PortWindow is a port window pushed by peer_targets.
type PortWindow struct {
	IP netip.Addr `json:"ip"`
	Lo uint16     `json:"lo"`
	Hi uint16     `json:"hi"` // hi - lo <= 63
}

// FamilyReady is one family of punch_ready.
type FamilyReady struct {
	Family   Family         `json:"family"`
	Sockets  uint16         `json:"sockets"`            // pre-bound sockets, primary included
	Clamped  bool           `json:"clamped,omitempty"`  // the plan was clamped locally
	Rejected uint16         `json:"rejected,omitempty"` // targets removed by admission
	PortMap  *PortMapReport `json:"port_map,omitempty"` // port mapping finished after probe_report
}

// FamilyOutcome is one family of round_result.
type FamilyOutcome struct {
	Remap         *Remap           `json:"remap,omitempty"` // the primary socket's new mapping, re-observed this round
	Family        Family           `json:"family"`
	SeenFrom      []netip.AddrPort `json:"seen_from,omitempty"` // peer sources seen this round, <= 4
	Sent          uint32           `json:"sent"`
	Recv          uint32           `json:"recv"`
	DistinctPorts uint16           `json:"distinct_ports"`
	ICMPUnreach   uint16           `json:"icmp_unreach,omitempty"`
	BindFailed    uint16           `json:"bind_failed,omitempty"`
	Rejected      uint16           `json:"rejected,omitempty"` // targets admission refused this round
	Hit           bool             `json:"hit"`                // a peer success was received
	PeerSeenUs    bool             `json:"peer_seen_us"`       // a peer_seen about us arrived this round
	BudgetHit     bool             `json:"budget_hit,omitempty"`
	Drift         bool             `json:"drift,omitempty"`
	// Halted: the side stopped initiating in this family for the rest of
	// the round on a spike of write or bind failures, as the slow birthday
	// of a Background session does.
	Halted bool `json:"halted,omitempty"`
}

// Remap is a new mapping of a family's primary socket that the client
// re-observed in a round without contact: observer
// Observer's probe_ack showed Observed. Cookie echoes that ack's COOKIE, so
// the server can verify the mapping as it verifies the probe's: only
// a client that receives at Observed can know it.
type Remap struct {
	Observer uint8          `json:"o"`
	Observed netip.AddrPort `json:"a"`
	Cookie   uint32         `json:"c"`
}

// CandKind is PathInfo.CandKind: how the confirmed target was found.
type CandKind string

// Candidate kinds.
const (
	CandDirect        CandKind = "direct"
	CandPredicted     CandKind = "predicted"
	CandRandom        CandKind = "random"
	CandBirthday      CandKind = "birthday"
	CandPeerReflexive CandKind = "peer_reflexive"
	CandLAN           CandKind = "lan"
	CandTargets       CandKind = "targets"
	CandOverlay       CandKind = "overlay" // an overlay address of the peer
)

// PathKind is PathInfo.Kind: what kind of network a confirmed path runs over,
// so that a caller can tell a tunnel from a direct path.
type PathKind string

// Path kinds.
const (
	PathPublic  PathKind = "public"  // through the public Internet: observed, predicted or sprayed mappings
	PathLAN     PathKind = "lan"     // a LAN the two clients share
	PathOverlay PathKind = "overlay" // an overlay or tunnel network both clients are on (Tailscale, WireGuard, ZeroTier …)
	PathPortmap PathKind = "portmap" // a port mapping of the peer's gateway (UPnP, NAT-PMP, PCP)
)

// Valid reports whether k is one of the four path kinds.
func (k PathKind) Valid() bool {
	switch k {
	case PathPublic, PathLAN, PathOverlay, PathPortmap:
		return true
	}
	return false
}

// HandoverEvidence is PathInfo.ConfirmedBy: what completed the UDP handover.
type HandoverEvidence string

// Handover evidence.
const (
	ConfirmedByAck        HandoverEvidence = "ack"
	ConfirmedByUpperLayer HandoverEvidence = "upper_layer"
	ConfirmedByQuiet      HandoverEvidence = "quiet"
	ConfirmedByReady      HandoverEvidence = "ready"
)

// MaxPaths is the most confirmed paths one session hands over: the primary
// path and up to MaxPaths-1 extra paths.
const MaxPaths = 8

// PathInfo is a confirmed path: the primary path of round_result and
// punch_result, or one of punch_result.extra_paths.
type PathInfo struct {
	Family      Family           `json:"family"`
	Local       netip.AddrPort   `json:"local"`
	Remote      netip.AddrPort   `json:"remote"`
	Round       uint8            `json:"round"`
	Epoch       uint16           `json:"epoch"`
	Sock        uint8            `json:"sock"`
	Cand        uint16           `json:"cand"`
	CandKind    CandKind         `json:"cand_kind"`
	Kind        PathKind         `json:"kind"`                   // the network the path runs over
	RTTMs       uint16           `json:"rtt_ms"`                 // UDP path RTT
	ConfirmedBy HandoverEvidence `json:"confirmed_by,omitempty"` // punch_result only
}

// Stats are punch_result.stats.
type Stats struct {
	Drops     map[string]uint32 `json:"drops"` // keys: DropKeys; unknown keys are kept (forward compatible)
	Sent      uint32            `json:"sent"`
	Recv      uint32            `json:"recv"`
	Replies   uint32            `json:"replies"`
	Rounds    uint8             `json:"rounds"`
	Hits      uint8             `json:"hits"`
	BudgetHit bool              `json:"budget_hit,omitempty"`
}

// The keys of Stats.Drops: the client's packet-drop classes. Packets of
// another protocol version, of an old session and of
// another session all fail authentication and count as auth.
const (
	DropShort          = "short"
	DropForeign        = "foreign"
	DropRate           = "rate"
	DropAuth           = "auth"
	DropPayload        = "payload"
	DropRole           = "role"
	DropReplay         = "replay"
	DropBudget         = "budget"
	DropTargetRejected = "target_rejected"
	DropSendErr        = "send_err"
)

// DropKeys returns the ten keys of Stats.Drops.
func DropKeys() []string {
	return []string{DropShort, DropForeign, DropRate, DropAuth, DropPayload, DropRole, DropReplay, DropBudget,
		DropTargetRejected, DropSendErr}
}

// Timing is punch_result.timing.
type Timing struct {
	ProbeMs       uint32 `json:"probe_ms"`
	SummaryWaitMs uint32 `json:"summary_wait_ms"`
	GoWaitMs      uint32 `json:"go_wait_ms"`
	PunchMs       uint32 `json:"punch_ms"`
	HandoverMs    uint32 `json:"handover_ms"`
}

// Warning values of punch_result.warn and coord results (open: unknown
// names are kept).
const (
	WarnClockSkew                 = "clock_skew"
	WarnGoroutineJoinTimeout      = "goroutine_join_timeout"
	WarnLowTTLUnsupported         = "low_ttl_unsupported"
	WarnPeerResultMissing         = "peer_result_missing"
	WarnUnverifiedTargets         = "unverified_targets"
	WarnInsecureControlForTesting = "insecure_control_for_testing"
	WarnInterfaceListUnavailable  = "interface_list_unavailable" // no LAN addresses this session
	// WarnLANObserved means the server saw a client only at private addresses
	// (Traits.LANObserved), a deployment where clients reach the server
	// over a LAN route or a hairpin without source NAT.
	WarnLANObserved = "lan_observed"
)

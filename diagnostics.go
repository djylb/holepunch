package holepunch

import (
	"maps"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// Diagnostics is the full account of a session: how it went and why it ended.
// Session.Diagnostics and Error.Diagnostics return deep copies; token and
// route never appear in it.
type Diagnostics struct {
	SessionID string
	Role      protocol.Role
	Phase     Phase           // the phase the session ended in
	Reason    protocol.Reason // "" on success
	LastEvent string
	Timeline  []Transition         // at most 64, session and family scopes, most recent kept
	Self      []protocol.Traits    // per family: this side's traits from probe_summary, with punch-time corrections
	Peer      []protocol.Traits    // per family: the peer's traits from probe_summary
	Plan      *protocol.PlanSpec   // probe_summary.plan
	Rounds    []protocol.RoundPlan // the rounds actually run (rescue included)
	Path      *protocol.PathInfo   // on success: the confirmed path, with confirmed_by
	// ExtraPaths are, on success, the extra paths handed over with Path, as
	// punch_result.extra_paths reports them.
	ExtraPaths []protocol.PathInfo
	Families   []FamilyDiagnostics
	Counters   Counters
	Timing     Timing
	RTT        time.Duration // the server's estimate of this control link's RTT (punch_go.rtt_ms)
	Warn       []string      // at most 8: clock_skew, goroutine_join_timeout, low_ttl_unsupported, unverified_targets, insecure_control_for_testing, interface_list_unavailable, control_unreturnable, abort_after_confirm, control_lost_after_confirm
}

// FamilyDiagnostics is one address family of a session.
type FamilyDiagnostics struct {
	Family     protocol.Family
	Strategy   string         // diagnostic name "<pair_class>/<variant>" of the family's last round ("<pair_class>" before one ran), with ";lowttl=unavailable" when the family sends no low TTL
	Candidates map[string]int // candidate state -> count
	Confirmed  netip.AddrPort // the confirmed remote of this family's path: the primary path's, else the first extra path's
	Counters   Counters
	// Hints are likely causes of what the traits show, for people; no
	// decision depends on them: HintHostFirewall, HintPeerHostFirewall,
	// HintServerSeesLAN, HintPeerServerSeesLAN.
	Hints []string
}

// Hints of FamilyDiagnostics.Hints.
const (
	// HintHostFirewall means this side's mapping is endpoint independent — or
	// there is no NAT — but its filtering is port dependent, which is what
	// a host firewall (Windows Defender Firewall, iptables, pf) makes of a
	// full-cone NAT: it lets in only replies to the exact remote a socket
	// sent to. The library plans by the filtering it measured and never
	// counts on the host letting packets in; allowing inbound UDP for the
	// program may connect more peers directly.
	HintHostFirewall = "host_firewall"
	// HintPeerHostFirewall is HintHostFirewall for the peer.
	HintPeerHostFirewall = "peer_host_firewall"
	// HintServerSeesLAN means the server's public observers saw this side
	// only at a private address (protocol.Traits.LANObserved): it reaches
	// the server over a LAN route, or through a router hairpin that keeps
	// the source address, so the server knows none of its public addresses.
	// It connects to a peer on the same LAN directly, and to others only at
	// the addresses its STUN servers or port mapping reported, if the server
	// allows them. Letting the server see the client through its public
	// address — a hairpin with source NAT, or no LAN route to the server's
	// public IP — removes the restriction.
	HintServerSeesLAN = "server_sees_lan"
	// HintPeerServerSeesLAN is HintServerSeesLAN for the peer.
	HintPeerServerSeesLAN = "peer_server_sees_lan"
)

// hostFirewallLikely reports whether traits show port-dependent filtering
// on an endpoint-independent mapping or without NAT, the shape a host
// firewall gives a full cone.
func hostFirewallLikely(t protocol.Traits) bool {
	return t.Filtering == protocol.FiltPDF && t.FilteringConf >= protocol.ConfMedium &&
		(t.NoNAT == protocol.TriTrue || t.Mapping == protocol.MapEIM && t.MappingConf >= protocol.ConfMedium)
}

// familyHints are the hints of one family from both sides' traits.
func familyHints(self, peer protocol.Traits) []string {
	var out []string
	if hostFirewallLikely(self) {
		out = append(out, HintHostFirewall)
	}
	if hostFirewallLikely(peer) {
		out = append(out, HintPeerHostFirewall)
	}
	if self.LANObserved {
		out = append(out, HintServerSeesLAN)
	}
	if peer.LANObserved {
		out = append(out, HintPeerServerSeesLAN)
	}
	return out
}

// Counters are the packet and event counts of a session or family. Drops uses
// the keys of punch_result.stats.drops (protocol.DropKeys).
type Counters struct {
	TxPackets        int            // initiated packets (bounded by MaxPackets)
	TxByStage        map[string]int // direct, predict, random, birthday, warmup (low TTL), reply, handshake, handover, probe
	TxOpeners        int            // datagrams of any stage that opened their flow as a STUN-wrapped opener
	RxPackets        int            // datagrams read
	RxVerified       int            // peer packets that passed AEAD, role and replay checks
	Drops            map[string]int
	TokenMismatch    int  // AEAD failures from a verified peer IP outside the handover window (token_mismatch evidence; not Drops["auth"])
	TargetRejected   int  // targets refused by admission
	ReplyUnlisted    int  // replies to peer-reflexive sources outside the verified set
	DistinctTargets  int  // distinct initiated destinations
	SocketsOpened    int  // sockets opened by the session
	PeakPPS          int  // most initiated packets within any second
	BudgetUsedPct    int  // initiated packets as a percentage of MaxPackets
	ControlFramesIn  int  // control frames read
	ControlFramesOut int  // control frames written
	ProgressDropped  int  // progress copies dropped (local queue full or delivery window over)
	CallbackPanics   int  // panics recovered in user callbacks and implementations
	LeakedGoroutines int  // goroutines still running when cleanup gave up waiting; always 0 in a healthy build
	PeerSeenUs       bool // the peer reported, through peer_seen, receiving our packets
}

// Transition is one phase change.
type Transition struct {
	Scope    string // "session", "udp4" or "udp6"
	From, To Phase
	Event    string
	At       time.Time
}

// txStage indexes Counters.TxByStage.
type txStage uint8

const (
	txDirect txStage = iota
	txPredict
	txRandom
	txBirthday
	txFresh
	txWarmup
	txReply
	txHandshake
	txHandover
	txProbe
	numTxStages
)

var txStageNames = [numTxStages]string{"direct", "predict", "random", "birthday", "fresh", "warmup", "reply", "handshake", "handover", "probe"}

// dropKind indexes Counters.Drops in the order of protocol.DropKeys.
type dropKind uint8

const (
	dropShort dropKind = iota
	dropForeign
	dropRate
	dropAuth
	dropPayload
	dropRole
	dropReplay
	dropBudget
	dropTargetRejected
	dropSendErr
	numDrops
)

var dropNames = [numDrops]string{
	protocol.DropShort, protocol.DropForeign, protocol.DropRate, protocol.DropAuth, protocol.DropPayload,
	protocol.DropRole, protocol.DropReplay, protocol.DropBudget, protocol.DropTargetRejected, protocol.DropSendErr,
}

// dropOf maps a receive-pipeline outcome to its drop counter.
func dropOf(e udpwire.DecodeError) (dropKind, bool) {
	switch e {
	case udpwire.ErrShort:
		return dropShort, true
	case udpwire.ErrForeign:
		return dropForeign, true
	case udpwire.ErrRate:
		return dropRate, true
	case udpwire.ErrAuth:
		return dropAuth, true
	case udpwire.ErrPayload:
		return dropPayload, true
	case udpwire.ErrRole:
		return dropRole, true
	case udpwire.ErrReplay:
		return dropReplay, true
	case udpwire.OK, udpwire.ErrRoute:
		// Accepted, or a drop only natprobe makes.
	}
	return 0, false
}

// famCounters are the lock-free counters of one family; the hot paths only
// increment them.
type famCounters struct {
	tx             atomic.Int64
	byStage        [numTxStages]atomic.Int64
	openers        atomic.Int64
	rx             atomic.Int64
	verified       atomic.Int64
	drops          [numDrops]atomic.Int64
	tokenMismatch  atomic.Int64
	targetRejected atomic.Int64
	replyUnlisted  atomic.Int64
	sockets        atomic.Int64
	peerSeenUs     atomic.Bool
}

func (c *famCounters) drop(k dropKind) { c.drops[k].Add(1) }

// snapshot renders c as public Counters (family part only).
func (c *famCounters) snapshot() Counters {
	out := Counters{
		TxPackets:      int(c.tx.Load()),
		TxByStage:      map[string]int{},
		TxOpeners:      int(c.openers.Load()),
		RxPackets:      int(c.rx.Load()),
		RxVerified:     int(c.verified.Load()),
		Drops:          map[string]int{},
		TokenMismatch:  int(c.tokenMismatch.Load()),
		TargetRejected: int(c.targetRejected.Load()),
		ReplyUnlisted:  int(c.replyUnlisted.Load()),
		SocketsOpened:  int(c.sockets.Load()),
		PeerSeenUs:     c.peerSeenUs.Load(),
	}
	for i := range numTxStages {
		if v := c.byStage[i].Load(); v > 0 {
			out.TxByStage[txStageNames[i]] = int(v)
		}
	}
	for i := range numDrops {
		out.Drops[dropNames[i]] = int(c.drops[i].Load())
	}
	return out
}

// sumCounters adds the family counters into a session total.
func sumCounters(parts ...Counters) Counters {
	out := Counters{TxByStage: map[string]int{}, Drops: map[string]int{}}
	for _, k := range dropNames {
		out.Drops[k] = 0
	}
	for _, p := range parts {
		out.TxPackets += p.TxPackets
		out.TxOpeners += p.TxOpeners
		out.RxPackets += p.RxPackets
		out.RxVerified += p.RxVerified
		out.TokenMismatch += p.TokenMismatch
		out.TargetRejected += p.TargetRejected
		out.ReplyUnlisted += p.ReplyUnlisted
		out.SocketsOpened += p.SocketsOpened
		out.PeerSeenUs = out.PeerSeenUs || p.PeerSeenUs
		for k, v := range p.TxByStage {
			out.TxByStage[k] += v
		}
		for k, v := range p.Drops {
			out.Drops[k] += v
		}
	}
	return out
}

// clone deep-copies d (maps and slices), so callers can keep and mutate it.
func (d Diagnostics) clone() Diagnostics {
	out := d
	out.Timeline = append([]Transition(nil), d.Timeline...)
	out.Self = append([]protocol.Traits(nil), d.Self...)
	out.Peer = append([]protocol.Traits(nil), d.Peer...)
	if d.Plan != nil {
		p := clonePlan(*d.Plan)
		out.Plan = &p
	}
	if d.Rounds != nil {
		out.Rounds = make([]protocol.RoundPlan, len(d.Rounds))
		for i, r := range d.Rounds {
			out.Rounds[i] = cloneRound(r)
		}
	}
	if d.Path != nil {
		p := *d.Path
		out.Path = &p
	}
	out.ExtraPaths = slices.Clone(d.ExtraPaths)
	out.Families = make([]FamilyDiagnostics, len(d.Families))
	for i, f := range d.Families {
		f.Candidates = maps.Clone(f.Candidates)
		f.Counters = f.Counters.clone()
		f.Hints = append([]string(nil), f.Hints...)
		out.Families[i] = f
	}
	if d.Families == nil {
		out.Families = nil
	}
	out.Counters = d.Counters.clone()
	out.Warn = append([]string(nil), d.Warn...)
	return out
}

func (c Counters) clone() Counters {
	c.TxByStage = maps.Clone(c.TxByStage)
	c.Drops = maps.Clone(c.Drops)
	return c
}

// clonePlan deep-copies a plan spec.
func clonePlan(p protocol.PlanSpec) protocol.PlanSpec {
	p.Ladder = append([]string(nil), p.Ladder...)
	p.Round1 = cloneRound(p.Round1)
	return p
}

// cloneRound deep-copies a round plan, down to the stage targets.
func cloneRound(r protocol.RoundPlan) protocol.RoundPlan {
	if r.Sides == nil {
		return r
	}
	sides := make([]protocol.FamilySide, len(r.Sides))
	for i, s := range r.Sides {
		if s.Stages != nil {
			st := make([]protocol.Stage, len(s.Stages))
			for j, g := range s.Stages {
				g.Targets = append([]netip.AddrPort(nil), g.Targets...)
				g.Steps = append([]int16(nil), g.Steps...)
				st[j] = g
			}
			s.Stages = st
		}
		sides[i] = s
	}
	r.Sides = sides
	return r
}

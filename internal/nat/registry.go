package nat

import (
	"net/netip"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Registration registers a session's probe route with a natprobe Registry.
type Registration struct {
	SessionID string           // 1..64 bytes, the protocol session id
	Route     protocol.RouteID // punch_start.wire.route_id
	Token     protocol.Token   // the session token (HKDF IKM); only a digest is kept
	TTL       time.Duration    // coord: BindTimeout + probe_timeout + ReportSlack + 5 s; ≤ 0 means 60 s
}

// Observation is natprobe's record of one observation slot (role, socket,
// observer).
type Observation struct {
	Socket, Observer uint8
	Alt              bool           // the observer belongs to the alt (second IP) group
	LAN              bool           // the observer is advertised on a private address: LAN evidence only
	Observed         netip.AddrPort // latest value
	First            netip.AddrPort // first value; ≠ Observed means drift
	Changes          uint8          // value changes
	Count            uint8          // accepted probes, retransmissions and keepalives included
	FirstSeq         uint32         // seq of the slot's first accepted probe
	Cookie           uint32         // return-path cookie of the current Observed
	FirstAt, LastAt  time.Time      // Registry clock
	ExtraSent        uint8          // extra replies sent for the slot
	AltSent          uint8          // change-IP replies sent for the slot
}

// Drift is a moved mapping of a role's primary socket: the latest value of
// a slot of a main-group observer at a public address, which changed since
// the slot's first probe — a new port, or after a rebind a new IP.
type Drift struct {
	Family   protocol.Family
	Observer uint8
	Observed netip.AddrPort // the mapping now, a usable target of Family
	Cookie   uint32         // the return-path cookie of Observed
}

// EchoedBy reports whether the remap echo m vouches for d: the client
// echoed d's value with its cookie. natprobe draws a new cookie whenever the
// value changes, so the echo vouches for this value only.
func (d Drift) EchoedBy(m *protocol.Remap) bool {
	return m != nil && d.Cookie != 0 && m.Cookie == d.Cookie && m.Observer == d.Observer && m.Observed == d.Observed
}

// MergeDiag counts what a merge did not take at face value.
type MergeDiag struct {
	Unverified        int // client rows claiming an answer the server never recorded (dropped)
	CookieMissing     int // server-recorded rows whose cookie was not echoed correctly (not verified)
	Conflicts         int // the client's ack value ≠ the server's record (SNAT proxy, wrong advertised address)
	RejectedEndpoints int // self-reported STUN and port-mapping addresses that failed the constraints
	// STUNConflicts counts admitted STUN values that contradict natprobe's
	// own records (ObsTable.STUNConflicts): STUN is a hint, recorded but
	// never classified against natprobe.
	STUNConflicts int
	MemoryPanics  int // TraitsMemory.Apply panicked; its advice was ignored
}

// TraitsKey identifies one NAT across sessions: a stable identity the
// caller provides (a client id or a hash of its key, for example; empty keys
// by public IP only), the family, and the public IP — a new public IP may
// well be another NAT. natprobe re-exports it.
type TraitsKey struct {
	ClientKey string
	Family    protocol.Family
	PublicIP  netip.Addr
}

// TraitsMemory is the cross-session traits memory. The coordinator calls
// Apply when it merges a client's probe_report with natprobe's records, and
// Observe when a session ends, with the session's direct measurements. A nil
// TraitsMemory turns the memory off. natprobe re-exports it.
// Callers may provide their own implementation, for example a persistent
// one; it must be safe for concurrent use and must not block.
type TraitsMemory interface {
	// Apply refines current with what is remembered for k. It only reads,
	// only fills unknown fields or raises one confidence level, and never
	// overturns direct evidence.
	//holepunch:callback
	Apply(k TraitsKey, current protocol.Traits) protocol.Traits
	// Observe records a session's final traits for k; succeeded says
	// whether the session connected.
	//
	// final must be a direct measurement that the memory did not correct: the
	// traits the merge produced without a memory (MergeResult.Raw),
	// corrected by punch_result.traits. Apply's output never enters Observe. A
	// conclusion Apply raised would otherwise come back as evidence and renew
	// itself for ever, while a direct measurement that agrees with a remembered
	// conclusion is fresh evidence and renews it.
	//holepunch:callback
	Observe(k TraitsKey, final protocol.Traits, succeeded bool)
}

// MergeResult is one merge of a probe_report with natprobe's records.
type MergeResult struct {
	// View is the server's authoritative view of the role, refined by the
	// traits memory.
	View protocol.PeerView
	// Raw is the same merge without the memory, from the same records:
	// the session's own evidence, the only one that may feed the memory
	// back. It is View when no memory was given.
	Raw  protocol.PeerView
	Diag MergeDiag
}

// ProbeHandle is one session's natprobe registration, held by the
// coordinator session. Several handles may share one entry (idempotent
// registration); closing any of them closes the entry. Its methods are safe
// for concurrent use.
type ProbeHandle interface {
	// Observations returns a copy of role's slots ordered by (socket,
	// observer); nil for a role other than initiator or responder.
	Observations(role protocol.Role) []Observation
	// Drifted returns role's moved primary mappings (Drift), ordered by
	// (socket, observer); nil for a role other than initiator or responder.
	// Only the primary socket counts: it is the one the peer aims at.
	Drifted(role protocol.Role) []Drift
	// ProbesLeft is how many more probes of role the entry accepts in its
	// lifetime: the coordinator asks for an anchor refresh only while two
	// are left.
	ProbesLeft(role protocol.Role) int
	// Registered returns when the entry was registered, read from the
	// Registry's clock: the origin of the slot times and of
	// Traits.PortAnchorMs that Merge derives from them.
	Registered() time.Time
	// Extend renews the registration to max(current expiry, now+ttl); it
	// does nothing after Close or once the registration expired.
	Extend(ttl time.Duration)
	// Close ends the registration: the route's packets are dropped from now
	// on. It is idempotent.
	Close()
	// Announce records the observers announced to role in its punch_start,
	// whose addresses decide which observations are LAN evidence.
	Announce(role protocol.Role, observers []protocol.ObserverSpec)
	// Merge computes the server's authoritative view of role from its
	// probe_report, and the same view without the traits memory, from one
	// snapshot of the records. mem refines the view, or is nil; clientKey
	// completes its key; verifiedOnly keeps a LAN-observed family to
	// verified endpoints. It never panics.
	Merge(role protocol.Role, rep protocol.ProbeReport, mem TraitsMemory, clientKey string, verifiedOnly bool) (MergeResult, error)
	// AttachSandwichSink sets the session's sandwich event sink. A natprobe
	// reader calls it after it has answered the probe, outside every lock
	// and inside a recover boundary, at most one call at a time per
	// session; events queued before the sink was attached are delivered by
	// AttachSandwichSink itself, on the caller's goroutine, so the caller
	// must not hold a lock the sink takes. The sink must not block.
	AttachSandwichSink(sink func(SandwichEvent))
}

// RegisterProbe registers reg with registry, which must be a
// *natprobe.Registry, and returns its handle. natprobe assigns the variable
// in its init and coord calls it, so that the registration is part of no
// public API: an exported Registry method would be one. registry is untyped
// because this package cannot name natprobe's type (natprobe imports it);
// any other value is an error. It stays nil in a binary without natprobe.
var RegisterProbe func(registry any, reg Registration) (ProbeHandle, error)

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

// ProbeHandle is one session's natprobe registration, held by the
// coordinator session. Several handles may share one entry (idempotent
// registration); closing any of them closes the entry. Its methods are safe
// for concurrent use.
type ProbeHandle interface {
	// Observations returns a copy of role's slots ordered by (socket,
	// observer); nil for a role other than initiator or responder.
	Observations(role protocol.Role) []Observation
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
	// probe_report. mem is the natprobe.TraitsMemory that refines it, or nil;
	// clientKey completes its key; verifiedOnly keeps a LAN-observed family
	// to verified endpoints. It never panics.
	Merge(role protocol.Role, rep protocol.ProbeReport, mem any, clientKey string, verifiedOnly bool) (protocol.PeerView, MergeDiag, error)
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
// in its init and coord calls it: the registration is not part of any
// public API. It stays nil in a binary without natprobe.
var RegisterProbe func(registry any, reg Registration) (ProbeHandle, error)

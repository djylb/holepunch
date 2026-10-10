package natprobe

import (
	"cmp"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
)

// Handle is a session's registration, held by the coordinator session.
// Several handles may share one entry (idempotent registration); closing any
// of them closes the entry.
type Handle struct {
	r    *Registry
	e    *entry
	once sync.Once
}

// ServerObservation is natprobe's record of one observation slot
// (role, socket, observer).
type ServerObservation struct {
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

// Observations returns a copy of role's slots ordered by (socket, observer);
// nil for a role other than initiator or responder.
func (h *Handle) Observations(role protocol.Role) []ServerObservation {
	if h == nil || h.e == nil || !role.IsPunch() {
		return nil
	}
	e := h.e
	rs := &e.roles[role.Code()-1]
	rs.mu.Lock()
	out := make([]ServerObservation, 0, len(rs.slots))
	for _, s := range rs.slots {
		out = append(out, ServerObservation{
			Socket: s.sock, Observer: s.obs, Alt: s.flags&slotAlt != 0, LAN: s.flags&slotPrivate != 0,
			Observed: s.last.addrPort(), First: s.first.addrPort(), Changes: s.changes, Count: s.count,
			FirstSeq: s.firstSeq, Cookie: s.cookie,
			FirstAt: e.created.Add(time.Duration(s.firstAt) * time.Millisecond), LastAt: e.created.Add(time.Duration(s.lastAt) * time.Millisecond),
			ExtraSent: s.extraSent, AltSent: s.altSent,
		})
	}
	rs.mu.Unlock()
	slices.SortFunc(out, func(a, b ServerObservation) int {
		return cmp.Or(cmp.Compare(a.Socket, b.Socket), cmp.Compare(a.Observer, b.Observer))
	})
	return out
}

// ProbesLeft is how many more probes of role the entry accepts in its
// lifetime (RegistryConfig.ProbeBudgetPerRole): the coordinator asks for
// an anchor refresh only while two are left. 0
// for a nil Handle or a role other than initiator or responder.
func (h *Handle) ProbesLeft(role protocol.Role) int {
	if h == nil || h.e == nil || !role.IsPunch() {
		return 0
	}
	rs := &h.e.roles[role.Code()-1]
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return max(int(h.r.cfg.ProbeBudgetPerRole)-int(rs.accepted), 0)
}

// Registered returns when the entry was registered, read from the Registry's
// clock: the origin of the slot times and of Traits.PortAnchorMs that Merge
// derives from them. Handles of an idempotent registration share the first
// one's entry and so its time. It is the zero time for a nil Handle.
func (h *Handle) Registered() time.Time {
	if h == nil || h.e == nil {
		return time.Time{}
	}
	return h.e.created
}

// Extend renews the registration to max(current expiry, now+ttl), for
// example to punchDeadline + 1 s when sandwich probing was negotiated.
// It does nothing after Close or once the registration expired: an expired
// entry is gone, whether or not a writer already dropped it from its
// shard. A ttl too large for the clock saturates.
func (h *Handle) Extend(ttl time.Duration) {
	if h == nil || h.e == nil || h.e.closed.Load() {
		return
	}
	mono := h.r.mono(h.r.now())
	h.e.extendAlive(mono, addSat(mono, int64(ttl)))
}

// Close ends the registration: from now on the route's packets are dropped
// silently and no new sandwich sink call starts (a call already running may
// still be returning). It is idempotent and safe for concurrent use.
func (h *Handle) Close() {
	if h == nil || h.e == nil {
		return
	}
	h.once.Do(func() {
		h.e.closed.Store(true)
		h.r.remove(h.e)
		h.e.sandwich.close()
	})
}

// setEventFunc sets the session's sandwich sink. Only coord calls it, through
// nat.AttachSandwichSink. The events queued before it are
// delivered here, on coord's goroutine; a panic of the sink is counted in
// the Registry and reaches ServerStats.Panics.
func (h *Handle) setEventFunc(sink func(nat.SandwichEvent)) {
	if h == nil || h.e == nil {
		return
	}
	if p := h.e.sandwich.attach(sink, h.r.cfg.SandwichQueue); p > 0 {
		h.r.sinkPanics.Add(uint64(p))
	}
}

// init installs the natprobe → coord sandwich bridge: the hook is not part
// of any public API.
func init() {
	nat.AttachSandwichSink = func(h any, sink func(nat.SandwichEvent)) {
		if hh, ok := h.(*Handle); ok {
			hh.setEventFunc(sink)
		}
	}
}

package natprobe

import (
	"cmp"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
)

// handle is a session's registration, the nat.ProbeHandle the coordinator
// session holds. Several handles may share one entry (idempotent
// registration); closing any of them closes the entry.
type handle struct {
	r    *Registry
	e    *entry
	once sync.Once
}

// Observations returns a copy of role's slots ordered by (socket, observer);
// nil for a role other than initiator or responder.
func (h *handle) Observations(role protocol.Role) []nat.Observation {
	if h == nil || h.e == nil || !role.IsPunch() {
		return nil
	}
	e := h.e
	rs := &e.roles[role.Code()-1]
	rs.mu.Lock()
	out := make([]nat.Observation, 0, len(rs.slots))
	for _, s := range rs.slots {
		out = append(out, nat.Observation{
			Socket: s.sock, Observer: s.obs, Alt: s.flags&slotAlt != 0, LAN: rs.lan(s),
			Observed: s.last.addrPort(), First: s.first.addrPort(), Changes: s.changes, Count: s.count,
			FirstSeq: s.firstSeq, Cookie: s.cookie,
			FirstAt: e.created.Add(time.Duration(s.firstAt) * time.Millisecond), LastAt: e.created.Add(time.Duration(s.lastAt) * time.Millisecond),
			ExtraSent: s.extraSent, AltSent: s.altSent,
		})
	}
	rs.mu.Unlock()
	slices.SortFunc(out, func(a, b nat.Observation) int {
		return cmp.Or(cmp.Compare(a.Socket, b.Socket), cmp.Compare(a.Observer, b.Observer))
	})
	return out
}

// Announce records the observers announced to role in its punch_start:
// with ScopeAuto, an observer announced at a private address counts as LAN
// evidence only. Later calls replace earlier ones.
func (h *handle) Announce(role protocol.Role, observers []protocol.ObserverSpec) {
	if h == nil || h.e == nil || !role.IsPunch() {
		return
	}
	rs := &h.e.roles[role.Code()-1]
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.announced, rs.private, rs.anyAnnounced = [4]uint64{}, [4]uint64{}, true
	for _, o := range observers {
		rs.announced[o.ID/64] |= 1 << (o.ID % 64)
		if nat.ScopeOf(o.Addr.Addr()) == nat.ScopePrivate {
			rs.private[o.ID/64] |= 1 << (o.ID % 64)
		}
	}
}

// unannounced reports whether obs is an observer the role was not
// announced, while it was announced some: a probe to a free slot's id. The
// caller holds rs.mu.
func (rs *roleState) unannounced(obs uint8) bool {
	return rs.anyAnnounced && rs.announced[obs/64]&(1<<(obs%64)) == 0
}

// lan reports whether s's observations are LAN evidence: a ScopePrivate
// group's, or with ScopeAuto one announced at a private address. The
// caller holds rs.mu.
func (rs *roleState) lan(s slot) bool {
	return s.flags&slotPrivate != 0 || s.flags&slotPublic == 0 && rs.private[s.obs/64]&(1<<(s.obs%64)) != 0
}

// ProbesLeft is how many more probes of role the entry accepts in its
// lifetime (RegistryConfig.ProbeBudgetPerRole): the coordinator asks for
// an anchor refresh only while two are left. 0
// for a nil handle or a role other than initiator or responder.
func (h *handle) ProbesLeft(role protocol.Role) int {
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
// one's entry and so its time. It is the zero time for a nil handle.
func (h *handle) Registered() time.Time {
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
func (h *handle) Extend(ttl time.Duration) {
	if h == nil || h.e == nil || h.e.closed.Load() {
		return
	}
	mono := h.r.mono(h.r.now())
	h.e.extendAlive(mono, addSat(mono, int64(ttl)))
}

// Close ends the registration: from now on the route's packets are dropped
// silently and no new sandwich sink call starts (a call already running may
// still be returning). It is idempotent and safe for concurrent use.
func (h *handle) Close() {
	if h == nil || h.e == nil {
		return
	}
	h.once.Do(func() {
		h.e.closed.Store(true)
		h.r.remove(h.e)
		h.e.sandwich.close()
	})
}

// AttachSandwichSink sets the session's sandwich sink. The events queued
// before it are delivered here, on coord's goroutine; a panic of the sink is
// counted in the Registry and reaches ServerStats.Panics.
func (h *handle) AttachSandwichSink(sink func(nat.SandwichEvent)) {
	if h == nil || h.e == nil {
		return
	}
	if p := h.e.sandwich.attach(sink, h.r.cfg.SandwichQueue); p > 0 {
		h.r.sinkPanics.Add(uint64(p))
	}
}

// init installs the natprobe → coord bridge: a session's registration is
// not part of any public API.
func init() {
	nat.RegisterProbe = func(registry any, reg nat.Registration) (nat.ProbeHandle, error) {
		r, ok := registry.(*Registry)
		if !ok {
			return nil, errors.New("natprobe: not a *Registry")
		}
		h, err := r.register(reg)
		if err != nil {
			return nil, err
		}
		return h, nil
	}
}

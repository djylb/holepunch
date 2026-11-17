package natprobe

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// Registry defaults and bounds.
const (
	defaultMaxEntries    = 16384
	defaultSlotsPerRole  = 24
	maxSlotPairs         = 256 * 256 // distinct (socket, observer) pairs: both are bytes
	defaultProbeBudget   = 96
	defaultExtraQuota    = 8
	defaultAltQuota      = 2
	defaultSessionPerSec = 16
	defaultSessionBurst  = 32
	defaultSandwichQueue = 8
	defaultTTL           = 60 * time.Second // the library's fallback; coord passes BindTimeout+probe+ReportSlack+5 s
	fullSweepGap         = time.Second
	minSweepLen          = 64 // below it the table is not swept for growth alone
)

// tokenTagDomain separates the token digest kept for idempotent
// registration from every other use of the token.
const tokenTagDomain = "holepunch/1 natprobe token tag" //nolint:gosec // G101: a domain-separation label, not a credential

// RegistryConfig configures a Registry; zero fields take the defaults.
type RegistryConfig struct {
	MaxEntries         int         // live sessions, default 16384, negative unlimited; when full the expired entries are dropped, then ErrRegistryFull
	SlotsPerRole       int         // observation slots (socket, observer) per role, default 24, negative unlimited (at most 65536 pairs exist)
	ProbeBudgetPerRole uint16      // probes accepted per (session, role) in its lifetime, default 96
	ExtraQuotaPerRole  uint8       // extra replies per (session, role), default 8
	AltQuotaPerRole    uint8       // change-IP replies per (session, role), default 2
	SessionRate        Rate        // per (session, role), default {16, 32}
	SandwichQueue      int         // undelivered sandwich events per session, default 8, negative unlimited; more are dropped
	Clock              clock.Clock // nil means the system clock; the clock of every expiry and rate decision
}

// Registry holds the registered probe routes. It is safe for concurrent use,
// starts no goroutine and needs no Close or upkeep: closed entries leave the
// table at once, an expired one when its route is registered again, and all
// expired ones in a sweep (at most once a second) when the table is full or
// has doubled since the last sweep. Several Servers and Coordinators may
// share one.
//
// The table is a sync.Map: lookups, the per-packet path, take no lock, and
// its index grows and shrinks with the entries, so that an empty registry
// costs a few words and a write costs the same at ten entries as at a
// million.
type Registry struct {
	cfg   RegistryConfig
	m     sync.Map // protocol.RouteID → *entry
	now   func() time.Time
	epoch time.Time    // origin of the monotonic nanoseconds of expiry and rate state
	live  atomic.Int64 // entries in m, expired ones not yet removed included
	// swept is when the last sweep ran (registry monotonic ns): a sweep runs
	// at most once per fullSweepGap, so that a table full of live entries
	// does not make every registration scan all of them.
	swept atomic.Int64
	// keptAtSweep is the table's length after the last sweep; a table that
	// doubled since is swept again, which bounds the expired entries kept to
	// the live ones at an amortised O(1) per registration.
	keptAtSweep atomic.Int64

	// sinkPanics counts sandwich sink panics recovered on the coordinator's
	// goroutine (AttachSandwichSink delivering the queued events). The
	// Servers sharing the Registry move it into their Panics on Stats.
	sinkPanics atomic.Uint64
}

// NewRegistry returns an empty registry. It starts no goroutine.
func NewRegistry(cfg RegistryConfig) *Registry {
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = defaultMaxEntries
	}
	if cfg.SlotsPerRole == 0 {
		cfg.SlotsPerRole = defaultSlotsPerRole
	}
	if cfg.SlotsPerRole < 0 {
		cfg.SlotsPerRole = maxSlotPairs
	}
	if cfg.SandwichQueue == 0 {
		cfg.SandwichQueue = defaultSandwichQueue
	}
	if cfg.ProbeBudgetPerRole == 0 {
		cfg.ProbeBudgetPerRole = defaultProbeBudget
	}
	if cfg.ExtraQuotaPerRole == 0 {
		cfg.ExtraQuotaPerRole = defaultExtraQuota
	}
	if cfg.AltQuotaPerRole == 0 {
		cfg.AltQuotaPerRole = defaultAltQuota
	}
	if cfg.SessionRate.PerSec <= 0 {
		cfg.SessionRate = Rate{PerSec: defaultSessionPerSec, Burst: defaultSessionBurst}
	}
	if cfg.SessionRate.Burst <= 0 {
		cfg.SessionRate.Burst = max(cfg.SessionRate.PerSec*2, 1)
	}
	now := time.Now
	if cfg.Clock != nil {
		now = cfg.Clock.Now
	}
	r := &Registry{cfg: cfg, now: now}
	r.epoch = now()
	return r
}

// mono converts t to the registry's monotonic nanoseconds.
func (r *Registry) mono(t time.Time) int64 { return int64(t.Sub(r.epoch)) }

// lookup is the hot-path read: one lock-free map lookup.
func (r *Registry) lookup(route protocol.RouteID) *entry {
	if v, ok := r.m.Load(route); ok {
		return v.(*entry)
	}
	return nil
}

// register registers reg and returns its handle:
//   - the same SessionID, route and token as a live entry: an idempotent
//     renewal to max(old, now+TTL) and a new Handle on the same entry, with
//     the observations kept, so an initiator that probes before the responder
//     joins loses nothing;
//   - the route is held by another session: ErrRouteInUse;
//   - the same route and SessionID with another token: ErrConflict;
//   - MaxEntries live entries after the expired ones are dropped (at most
//     once a second): ErrRegistryFull.
//
// It never replaces a live entry. Session ids are not indexed (a session
// keeps its handle), so a session that registers again under a new route
// gets a second entry.
func (r *Registry) register(reg nat.Registration) (*handle, error) {
	if r == nil {
		return nil, errors.New("natprobe: nil registry")
	}
	switch {
	case reg.SessionID == "" || len(reg.SessionID) > protocol.MaxSessionID:
		return nil, fmt.Errorf("natprobe: invalid registration: session id of %d bytes", len(reg.SessionID))
	case reg.Route.IsZero():
		return nil, errors.New("natprobe: invalid registration: zero route")
	case reg.Token.IsZero():
		return nil, errors.New("natprobe: invalid registration: zero token")
	}
	ttl := reg.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if n := r.live.Load(); n >= minSweepLen && n >= 2*r.keptAtSweep.Load() && r.claimSweep() {
		r.sweep(r.now())
	}
	h, err := r.registerOnce(reg, ttl)
	if errors.Is(err, ErrRegistryFull) && r.claimSweep() && r.sweep(r.now()) > 0 {
		h, err = r.registerOnce(reg, ttl)
	}
	return h, err
}

// registerOnce is one attempt of register. Concurrent writers of the same
// route serialise on the map's compare-and-swap; the loop retries only when
// another writer changed the route meanwhile.
func (r *Registry) registerOnce(reg nat.Registration, ttl time.Duration) (*handle, error) {
	now := r.now()
	mono := r.mono(now)
	tag := tokenTag(reg.Token)
	var e *entry // built once, outside the retries
	reserved := false
	release := func() {
		if reserved {
			r.live.Add(-1)
		}
	}
	for {
		cur := r.lookup(reg.Route)
		if cur != nil && cur.alive(mono) {
			switch {
			case cur.id != reg.SessionID:
				release()
				return nil, ErrRouteInUse
			case subtle.ConstantTimeCompare(cur.tokenTag[:], tag[:]) != 1:
				release()
				return nil, ErrConflict
			}
			if cur.extendAlive(mono, addSat(mono, int64(ttl))) {
				release()
				return &handle{r: r, e: cur}, nil
			}
		}
		if cur != nil { // dead: it leaves the table whatever follows
			if r.m.CompareAndDelete(reg.Route, cur) {
				r.live.Add(-1)
			}
			continue
		}
		if !reserved {
			if !r.reserve() {
				return nil, ErrRegistryFull
			}
			reserved = true
		}
		if e == nil {
			codec, err := udpwire.NewCodec(reg.Token, reg.Route, udpwire.RoleServer, udpwire.PadPolicy{}, r.now)
			if err != nil {
				release()
				return nil, fmt.Errorf("natprobe: session codec: %w", err)
			}
			e = newEntry(reg, tag, codec, now, r.cfg)
			e.expiresAt.Store(addSat(mono, int64(ttl)))
		}
		if _, loaded := r.m.LoadOrStore(reg.Route, e); !loaded {
			return &handle{r: r, e: e}, nil
		}
	}
}

// reserve takes one of the MaxEntries places; concurrent writers race on
// it, so it is a compare-and-swap loop. A negative MaxEntries is unlimited.
func (r *Registry) reserve() bool {
	if r.cfg.MaxEntries < 0 {
		r.live.Add(1)
		return true
	}
	for n := r.live.Load(); n < int64(r.cfg.MaxEntries); n = r.live.Load() {
		if r.live.CompareAndSwap(n, n+1) {
			return true
		}
	}
	return false
}

func tokenTag(token protocol.Token) [16]byte {
	sum := sha256.Sum256(append([]byte(tokenTagDomain), token[:]...))
	return [16]byte(sum[:16])
}

// claimSweep reports whether a full sweep may run now: one per fullSweepGap,
// the first caller of a gap winning it.
func (r *Registry) claimSweep() bool {
	now := r.mono(r.now())
	last := r.swept.Load()
	return (last == 0 || now-last >= int64(fullSweepGap)) && r.swept.CompareAndSwap(last, now)
}

// sweep removes every closed and expired entry and returns how many it
// removed. It holds no lock: each removal is a compare-and-delete, so an
// entry renewed or replaced meanwhile stays.
func (r *Registry) sweep(now time.Time) (removed int) {
	mono := r.mono(now)
	r.m.Range(func(k, v any) bool {
		if !v.(*entry).alive(mono) && r.m.CompareAndDelete(k, v) {
			removed++
			r.live.Add(-1)
		}
		return true
	})
	r.keptAtSweep.Store(r.live.Load())
	return removed
}

// Len returns the number of entries in the table, expired ones that were
// not swept yet included.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return int(r.live.Load())
}

// remove deletes e if it is still in the table; a concurrent register or
// sweep may have removed it already, and then nothing is counted twice.
func (r *Registry) remove(e *entry) {
	if r.m.CompareAndDelete(e.route, e) {
		r.live.Add(-1)
	}
}

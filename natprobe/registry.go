package natprobe

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// Registry defaults and bounds.
const (
	defaultMaxEntries    = 16384
	maxMaxEntries        = 1 << 24
	defaultSlotsPerRole  = 24
	maxSlotsPerRole      = 64
	defaultProbeBudget   = 96
	defaultExtraQuota    = 8
	defaultAltQuota      = 2
	defaultSessionPerSec = 16
	defaultSessionBurst  = 32
	defaultSandwichQueue = 8
	maxSandwichQueue     = 1024
	defaultTTL           = 60 * time.Second // the library's fallback; coord passes BindTimeout+probe+ReportSlack+5 s
	shardCount           = 64
	sweepBatch           = 4096
	maxSessionID         = 64 // protocol session ids are 1..64 bytes
)

// tokenTagDomain separates the token digest kept for idempotent
// registration from every other use of the token.
const tokenTagDomain = "holepunch/1 natprobe token tag"

// RegistryConfig configures a Registry; zero fields take the defaults.
type RegistryConfig struct {
	MaxEntries         int              // live sessions, default 16384; when full the target shard is swept, then ErrRegistryFull
	SlotsPerRole       int              // observation slots (socket, observer) per role, default 24, at most 64
	ProbeBudgetPerRole uint16           // probes accepted per (session, role) in its lifetime, default 96
	ExtraQuotaPerRole  uint8            // extra replies per (session, role), default 8
	AltQuotaPerRole    uint8            // change-IP replies per (session, role), default 2
	SessionRate        Rate             // per (session, role), default {16, 32}
	SandwichQueue      int              // undelivered sandwich events per session, default 8; more are dropped
	Clock              func() time.Time // nil means time.Now; the clock of every expiry and rate decision
}

// Registration registers a session's probe route.
type Registration struct {
	SessionID string           // 1..64 bytes, the protocol session id
	Route     protocol.RouteID // punch_start.wire.route_id
	Token     protocol.Token   // the session token (HKDF IKM); only a digest is kept
	TTL       time.Duration    // coord: BindTimeout + probe_timeout + ReportSlack + 5 s; ≤ 0 means 60 s
}

// Registry holds the registered probe routes. It is safe for concurrent use,
// starts no goroutine and needs no Close. Several Servers may share one.
type Registry struct {
	cfg    RegistryConfig
	now    func() time.Time
	epoch  time.Time // origin of the monotonic nanoseconds of expiry and rate state
	shards [shardCount]shard
	live   atomic.Int64 // entries in the shard maps, expired ones not yet removed included

	// sinkPanics counts sandwich sink panics recovered on the coordinator's
	// goroutine (AttachSandwichSink delivering the queued events). The
	// Servers sharing the Registry move it into their Panics on Stats.
	sinkPanics atomic.Uint64
}

// shard is one copy-on-write map. Readers load the map pointer without a
// lock; writers copy the map under wmu. A sharded RWMutex would make the
// readers contend on the reader count instead.
type shard struct {
	wmu sync.Mutex
	m   atomic.Pointer[map[protocol.RouteID]*entry]
	_   [48]byte // one shard per cache line
}

// NewRegistry returns an empty registry. It starts no goroutine.
func NewRegistry(cfg RegistryConfig) *Registry {
	cfg.MaxEntries = defaultBounded(cfg.MaxEntries, defaultMaxEntries, maxMaxEntries)
	cfg.SlotsPerRole = defaultBounded(cfg.SlotsPerRole, defaultSlotsPerRole, maxSlotsPerRole)
	cfg.SandwichQueue = defaultBounded(cfg.SandwichQueue, defaultSandwichQueue, maxSandwichQueue)
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
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	r := &Registry{cfg: cfg, now: now}
	r.epoch = now()
	return r
}

// defaultBounded returns v, or def when v ≤ 0, at most hi.
func defaultBounded(v, def, hi int) int {
	if v <= 0 {
		v = def
	}
	return min(v, hi)
}

// mono converts t to the registry's monotonic nanoseconds.
func (r *Registry) mono(t time.Time) int64 { return int64(t.Sub(r.epoch)) }

func (sh *shard) load() map[protocol.RouteID]*entry {
	if p := sh.m.Load(); p != nil {
		return *p
	}
	return nil
}

// lookup is the hot-path read: one atomic load and one map lookup.
func (r *Registry) lookup(route protocol.RouteID) *entry {
	return r.shards[route[0]%shardCount].load()[route]
}

// Register registers reg and returns its Handle:
//   - the same SessionID, route and token as a live entry: an idempotent
//     renewal to max(old, now+TTL) and a new Handle on the same entry, with
//     the observations kept, so a visitor that probes before the provider
//     joins loses nothing;
//   - the route is held by another session: ErrRouteInUse;
//   - the same route and SessionID with another token: ErrConflict;
//   - MaxEntries live entries after the target shard's expired ones are
//     dropped: ErrRegistryFull.
//
// It never replaces a live entry. Session ids are not indexed (a session
// keeps its *Handle), so a session that registers again under a new route
// gets a second entry.
func (r *Registry) Register(reg Registration) (*Handle, error) {
	if r == nil {
		return nil, errors.New("natprobe: nil registry")
	}
	switch {
	case reg.SessionID == "" || len(reg.SessionID) > maxSessionID:
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
	now := r.now()
	mono := r.mono(now)
	tag := tokenTag(reg.Token)
	sh := &r.shards[reg.Route[0]%shardCount]
	sh.wmu.Lock()
	defer sh.wmu.Unlock()
	cur := sh.load()
	if e := cur[reg.Route]; e != nil && e.alive(mono) {
		switch {
		case e.id != reg.SessionID:
			return nil, ErrRouteInUse
		case subtle.ConstantTimeCompare(e.tokenTag[:], tag[:]) != 1:
			return nil, ErrConflict
		}
		if e.extendAlive(mono, addSat(mono, int64(ttl))) {
			return &Handle{r: r, e: e}, nil
		}
	}
	// The shard is copied anyway: leave its dead entries behind, then
	// reserve a place.
	next := make(map[protocol.RouteID]*entry, len(cur)+1)
	removed := 0
	for k, v := range cur {
		if v.alive(mono) {
			next[k] = v
		} else {
			removed++
		}
	}
	r.live.Add(-int64(removed))
	if !r.reserve() {
		sh.m.Store(&next)
		return nil, ErrRegistryFull
	}
	codec, err := udpwire.NewCodec(reg.Token, reg.Route, udpwire.RoleServer, udpwire.PadPolicy{}, r.now)
	if err != nil {
		r.live.Add(-1)
		sh.m.Store(&next)
		return nil, fmt.Errorf("natprobe: session codec: %w", err)
	}
	e := newEntry(reg, tag, codec, now, r.cfg)
	e.expiresAt.Store(addSat(mono, int64(ttl)))
	next[reg.Route] = e
	sh.m.Store(&next)
	return &Handle{r: r, e: e}, nil
}

// reserve takes one of the MaxEntries places; writers of different shards
// race on it, so it is a compare-and-swap loop.
func (r *Registry) reserve() bool {
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

// Sweep removes closed and expired entries, at most 4096 per call, and
// returns how many it removed. The single sweeper calls it.
func (r *Registry) Sweep(now time.Time) (removed int) {
	if r == nil {
		return 0
	}
	mono := r.mono(now)
	for i := range r.shards {
		if removed >= sweepBatch {
			break
		}
		sh := &r.shards[i]
		if !hasDead(sh.load(), mono) {
			continue
		}
		removed += r.sweepShard(sh, mono, sweepBatch-removed)
	}
	return removed
}

// sweepShard removes at most limit dead entries of sh.
func (r *Registry) sweepShard(sh *shard, mono int64, limit int) int {
	sh.wmu.Lock()
	defer sh.wmu.Unlock()
	cur := sh.load()
	next := make(map[protocol.RouteID]*entry, len(cur))
	n := 0
	for k, v := range cur {
		if !v.alive(mono) && n < limit {
			n++
			continue
		}
		next[k] = v
	}
	if n > 0 {
		sh.m.Store(&next)
		r.live.Add(-int64(n))
	}
	return n
}

func hasDead(m map[protocol.RouteID]*entry, mono int64) bool {
	for _, v := range m {
		if !v.alive(mono) {
			return true
		}
	}
	return false
}

// Len returns the number of entries in the table, expired ones that were
// not swept yet included.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return int(r.live.Load())
}

// remove deletes e from its shard if it is still there; a concurrent
// Register or Sweep may have removed it already, and then nothing is
// counted twice.
func (r *Registry) remove(e *entry) {
	sh := &r.shards[e.route[0]%shardCount]
	sh.wmu.Lock()
	defer sh.wmu.Unlock()
	cur := sh.load()
	if cur[e.route] != e {
		return
	}
	next := make(map[protocol.RouteID]*entry, len(cur))
	for k, v := range cur {
		if v != e {
			next[k] = v
		}
	}
	sh.m.Store(&next)
	r.live.Add(-1)
}

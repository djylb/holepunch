package natprobe

import (
	"container/list"
	"hash/maphash"
	"net/netip"
	"sync"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/protocol"
)

// TraitsKey identifies one NAT across sessions: a
// stable identity the caller provides (a client id or a hash of its key,
// for example; empty keys by public IP only), the family, and the public IP — a new
// public IP may well be another NAT.
type TraitsKey struct {
	ClientKey string
	Family    protocol.Family
	PublicIP  netip.Addr
}

// TraitsMemory is the cross-session traits memory. The coordinator calls
// Apply when it merges a client's probe_report with natprobe's records, and
// Observe when a session ends, with the session's direct measurements. A nil
// TraitsMemory turns the memory off.
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
	// traits the merge produced without a memory (coord's raw views),
	// corrected by punch_result.traits. Apply's output never enters Observe. A
	// conclusion Apply raised would otherwise come back as evidence and renew
	// itself for ever, while a direct measurement that agrees with a remembered
	// conclusion is fresh evidence and renews it.
	//holepunch:callback
	Observe(k TraitsKey, final protocol.Traits, succeeded bool)
}

// TraitsMemoryConfig configures NewTraitsMemory; zero fields take the defaults.
type TraitsMemoryConfig struct {
	TTL        time.Duration // default 24 h: how long a learned conclusion stays usable
	MaxEntries int           // default 65536 (about 100 B each); a hard bound
	Clock      clock.Clock   // nil means the system clock
}

const (
	defaultMemoryTTL     = 24 * time.Hour
	defaultMemoryEntries = 65536
	memoryShards         = 16
	maxMemoConflicts     = 2
)

// NewTraitsMemory returns the in-memory TraitsMemory: a sharded LRU with lazy
// TTL checks and eviction on insert, without goroutines. It records the
// evidence of a session whatever its outcome: the traits are measurements
// of the NAT, not of the punch.
//
// Each remembered conclusion (mapping, filtering, hairpin, sequential step
// and velocity) expires TTL after it was last measured: only evidence
// younger than the TTL may raise a confidence. Observe renews exactly
// the conclusions its direct measurement establishes; an observation
// without such evidence — a session that measured only one server IP, or
// nothing — renews nothing.
func NewTraitsMemory(cfg TraitsMemoryConfig) TraitsMemory {
	if cfg.TTL <= 0 {
		cfg.TTL = defaultMemoryTTL
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = defaultMemoryEntries
	}
	now := time.Now
	if cfg.Clock != nil {
		now = cfg.Clock.Now
	}
	// Fewer shards than entries, and per-shard bounds that add up to
	// MaxEntries exactly, so that a small MaxEntries is still a bound.
	n := min(memoryShards, cfg.MaxEntries)
	m := &traitsMemory{ttl: cfg.TTL, now: now, seed: maphash.MakeSeed(), shards: make([]memShard, n)}
	m.epoch = m.now()
	for i := range m.shards {
		m.shards[i].idx = map[TraitsKey]*list.Element{}
		m.shards[i].bound = cfg.MaxEntries / n
		if i < cfg.MaxEntries%n {
			m.shards[i].bound++
		}
	}
	return m
}

type traitsMemory struct {
	ttl    time.Duration
	now    func() time.Time
	epoch  time.Time
	seed   maphash.Seed
	shards []memShard
}

type memShard struct {
	mu    sync.Mutex
	idx   map[TraitsKey]*list.Element
	lru   list.List // front = most recent; values are *memo
	bound int       // memos this shard may hold
}

// memo is what is remembered of one NAT, conclusion by conclusion, each with
// the time the memory learned it. The mapping is kept only when direct
// evidence established it: a cross-address source (peer, alt, STUN) for EIM
// and ADM, no NAT, or APDM (port dependence shows from one IP).
type memo struct {
	key         TraitsKey
	mapping     protocol.Mapping
	preserving  bool
	mappingAt   time.Duration
	filtering   protocol.Filtering // EIF or ADF only
	filteringAt time.Duration
	hairpin     protocol.Tri
	hairpinAt   time.Duration
	step        int16
	velocity    float32
	allocAt     time.Duration
	conflicts   uint8
}

// live returns the conclusions of mm learned less than ttl before now; the
// expired ones read as unknown.
func (mm *memo) live(now, ttl time.Duration) memo {
	v := memo{key: mm.key, conflicts: mm.conflicts}
	if mm.mapping != protocol.MapUnknown && now-mm.mappingAt < ttl {
		v.mapping, v.preserving, v.mappingAt = mm.mapping, mm.preserving, mm.mappingAt
	}
	if mm.filtering != protocol.FiltUnknown && now-mm.filteringAt < ttl {
		v.filtering, v.filteringAt = mm.filtering, mm.filteringAt
	}
	if mm.hairpin != protocol.TriUnknown && now-mm.hairpinAt < ttl {
		v.hairpin, v.hairpinAt = mm.hairpin, mm.hairpinAt
	}
	if mm.step != 0 && now-mm.allocAt < ttl {
		v.step, v.velocity, v.allocAt = mm.step, mm.velocity, mm.allocAt
	}
	return v
}

// empty reports whether the memo remembers nothing.
func (mm *memo) empty() bool {
	return mm.mapping == protocol.MapUnknown && mm.filtering == protocol.FiltUnknown &&
		mm.hairpin == protocol.TriUnknown && mm.step == 0
}

func (m *traitsMemory) shard(k TraitsKey) *memShard {
	var h maphash.Hash
	h.SetSeed(m.seed)
	// maphash.Hash writes never fail.
	_, _ = h.WriteString(k.ClientKey)
	_, _ = h.WriteString(string(k.Family))
	b := k.PublicIP.As16()
	_, _ = h.Write(b[:])
	return &m.shards[h.Sum64()%uint64(len(m.shards))]
}

func (m *traitsMemory) elapsed() time.Duration { return m.now().Sub(m.epoch) }

// getLocked returns the memo of k and its live conclusions, and drops the
// memo when every conclusion expired.
func (sh *memShard) getLocked(k TraitsKey, now, ttl time.Duration) (*memo, memo) {
	el, ok := sh.idx[k]
	if !ok {
		return nil, memo{}
	}
	mm := el.Value.(*memo)
	v := mm.live(now, ttl)
	if v.empty() {
		sh.lru.Remove(el)
		delete(sh.idx, k)
		return nil, memo{}
	}
	return mm, v
}

// mappingClass groups mappings: EIM and ADM keep the port across ports of
// one IP, APDM does not.
func mappingClass(m protocol.Mapping) int {
	switch m {
	case protocol.MapEIM, protocol.MapADM:
		return 1
	case protocol.MapAPDM:
		return 2
	default: // unknown
		return 0
	}
}

// consistent: the memo and the traits describe the same kind of NAT (the same
// mapping class and port preservation), or either knows no mapping.
func consistent(cur protocol.Traits, mm *memo) bool {
	if mm.mapping == protocol.MapUnknown || cur.Mapping == protocol.MapUnknown {
		return true
	}
	return mappingClass(cur.Mapping) == mappingClass(mm.mapping) && (cur.PortAlloc == protocol.AllocPreserving) == mm.preserving
}

// Apply implements TraitsMemory from the conclusions learned within the
// TTL.
func (m *traitsMemory) Apply(k TraitsKey, cur protocol.Traits) protocol.Traits {
	if !k.PublicIP.IsValid() {
		return cur
	}
	now := m.elapsed() // the Clock is the caller's: never called under the lock
	sh := m.shard(k)
	sh.mu.Lock()
	mm, snap := sh.getLocked(k, now, m.ttl)
	sh.mu.Unlock()
	if mm == nil || !consistent(cur, &snap) {
		return cur
	}
	single := cur.Mapping == protocol.MapEIM && cur.MappingConf == protocol.ConfMedium && !cur.CrossIP
	switch {
	case single && snap.mapping == protocol.MapEIM:
		cur.MappingConf, cur.CrossIP = protocol.ConfHigh, true // raise one level
	case single && snap.mapping == protocol.MapADM:
		cur.Mapping = protocol.MapADM // refine: a prior in the absence of direct evidence, still Medium
	}
	if cur.Mapping == protocol.MapAPDM && cur.PortAlloc == protocol.AllocSequential && cur.PortVelocity == 0 &&
		snap.velocity != 0 && snap.step != 0 && (snap.step > 0) == (cur.PortStep > 0) {
		cur.PortVelocity = snap.velocity
	}
	if cur.Filtering == protocol.FiltNotPDF && (snap.filtering == protocol.FiltEIF || snap.filtering == protocol.FiltADF) {
		cur.Filtering, cur.FilteringConf = snap.filtering, protocol.ConfMedium
	}
	if cur.Hairpin == protocol.TriUnknown && snap.hairpin != protocol.TriUnknown {
		cur.Hairpin = snap.hairpin
	}
	return cur
}

// Observe implements TraitsMemory: an inconsistent observation counts a
// conflict and the second conflict deletes the memo; a consistent one
// stores, with the current time, every conclusion final establishes
// directly — new, changed or confirmed — and leaves the others to their own
// expiry. An observation that establishes nothing changes nothing but the
// LRU order.
func (m *traitsMemory) Observe(k TraitsKey, final protocol.Traits, _ bool) {
	if !k.PublicIP.IsValid() || !k.Family.Valid() {
		return
	}
	now := m.elapsed()
	sh := m.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	old, cur := sh.getLocked(k, now, m.ttl)
	if old != nil && !consistent(final, &cur) {
		old.conflicts++
		if old.conflicts >= maxMemoConflicts {
			sh.lru.Remove(sh.idx[k])
			delete(sh.idx, k)
		}
		return
	}
	n := memo{key: k}
	if old != nil {
		n = *old
	}
	measured := false
	if final.Mapping != protocol.MapUnknown && final.MappingConf >= protocol.ConfMedium &&
		(final.CrossIP || final.NoNAT == protocol.TriTrue || final.Mapping == protocol.MapAPDM) {
		n.mapping, n.preserving, n.mappingAt, measured = final.Mapping, final.PortAlloc == protocol.AllocPreserving, now, true
	}
	if (final.Filtering == protocol.FiltEIF || final.Filtering == protocol.FiltADF) && final.FilteringConf >= protocol.ConfMedium {
		n.filtering, n.filteringAt, measured = final.Filtering, now, true
	}
	if final.Hairpin != protocol.TriUnknown {
		n.hairpin, n.hairpinAt, measured = final.Hairpin, now, true
	}
	if final.Mapping == protocol.MapAPDM && final.PortAlloc == protocol.AllocSequential && final.PortStep != 0 {
		switch {
		case final.PortVelocity != 0:
			n.velocity = final.PortVelocity
		case cur.step != final.PortStep:
			n.velocity = 0 // a remembered velocity belongs to an expired or other allocation
		}
		n.step, n.allocAt, measured = final.PortStep, now, true
	}
	switch {
	case old != nil && measured:
		*old = n
		sh.lru.MoveToFront(sh.idx[k])
	case old != nil:
		sh.lru.MoveToFront(sh.idx[k])
	case measured:
		for sh.lru.Len() >= sh.bound {
			back := sh.lru.Back()
			if back == nil {
				break
			}
			delete(sh.idx, back.Value.(*memo).key)
			sh.lru.Remove(back)
		}
		sh.idx[k] = sh.lru.PushFront(&n)
	}
}

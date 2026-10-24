package coord

import (
	"bufio"
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// StrategyKey identifies a pair of NAT exits across sessions: an HMAC of the
// two canonical sides' IP prefixes and NAT class bits, so it carries no
// plaintext address.
type StrategyKey [16]byte

// String returns the key in hex.
func (k StrategyKey) String() string { return hex.EncodeToString(k[:]) }

// StrategySide is one canonical side of a StrategyKey: the verified public IP
// prefix (IPv4 /32, IPv6 /64) and the class bits of its traits.
type StrategySide struct {
	IPPrefix  netip.Prefix
	ClassBits uint32
}

// DeriveStrategyKey derives the key of the canonical pair (A, B) =
// HMAC-SHA256(salt, A.IPPrefix ‖ A.ClassBits ‖ B.IPPrefix ‖ B.ClassBits)[:16].
// A is the Planner's rule side, so the same pair of exits maps to the same key
// whichever client initiates.
func DeriveStrategyKey(salt []byte, a, b StrategySide) StrategyKey {
	mac := hmac.New(sha256.New, salt)
	for _, s := range [2]StrategySide{a, b} {
		ip := s.IPPrefix.Addr().AsSlice()
		var buf [1 + 16 + 1 + 4]byte
		buf[0] = byte(len(ip))
		n := 1 + copy(buf[1:], ip)
		buf[n] = byte(s.IPPrefix.Bits())
		binary.BigEndian.PutUint32(buf[n+1:], s.ClassBits)
		mac.Write(buf[:n+5])
	}
	var k StrategyKey
	copy(k[:], mac.Sum(nil))
	return k
}

// MemoryResult is the outcome of one round reported to a StrategyMemory.
type MemoryResult uint8

// Memory results.
const (
	// MemSuccess means the round's variant was confirmed (UDP handshake done).
	MemSuccess MemoryResult = iota + 1
	// MemFailure means the round ended unconfirmed with NoContact, OneWay or
	// Blocked.
	MemFailure
	// MemNeutral means no evidence either way (ConfirmLost, NoReport, aborted).
	MemNeutral
)

// StrategyMemory remembers which variants worked for a pair of exits.
// Implementations must be safe for concurrent use and must not block; the
// coordinator calls them outside every lock and inside a recover boundary,
// and a panicking memory is ignored for the rest of the session.
//
// Planning a session, the coordinator asks Recommend for the order of the
// primary ladder and then Score for what the memory knows: a first variant
// that scores positive is a memory hit (Result.MemoryHit) and, when the
// memory moved it ahead of the ladder's first, may lift the first round's
// class cap up to heavy (plan.RoundInput.MemoryPromoted); a reordering
// without a positive score is used as an order only. A pair whose one
// positive variant is the slow birthday while the interactive pdf_x_rnd
// rounds failed is reported as background_only in the summaries.
//
// The key has no transport dimension: the variants open the NATs for UDP,
// whatever upper-layer transport then runs over the path, so a success
// under one transport mode is evidence for every other. A transport that
// fails on a confirmed path (Coordinator.Memory) counts against the
// variant for the pair as a whole, a weak signal against the gain of a
// success.
type StrategyMemory interface {
	// Recommend returns the ladder reordered by preference, a permutation
	// of ladder; anything else keeps the ladder's order. The built-in
	// memory also lowers the first entry by RotatePenalty, which rotates
	// repeatedly failing variants away.
	Recommend(key StrategyKey, ladder []plan.VariantID) []plan.VariantID
	// Score is what the memory knows of variant v for key: positive when v
	// connected the pair before, negative when it failed and its failures
	// outweigh its successes, 0 for nothing either way. Only the sign is
	// read. It must not count as a use of the key.
	Score(key StrategyKey, v plan.VariantID) int
	// Report records the outcome of one round.
	Report(key StrategyKey, v plan.VariantID, r MemoryResult)
}

// NoMemory remembers nothing. It is both a StrategyMemory and a
// natprobe.TraitsMemory, so Config.Memory = NoMemory{} and
// Config.TraitsMemory = NoMemory{} turn the two memories off.
type NoMemory struct{}

// Recommend returns a copy of ladder.
func (NoMemory) Recommend(_ StrategyKey, ladder []plan.VariantID) []plan.VariantID {
	return slices.Clone(ladder)
}

// Score returns 0.
func (NoMemory) Score(StrategyKey, plan.VariantID) int { return 0 }

// Report does nothing.
func (NoMemory) Report(StrategyKey, plan.VariantID, MemoryResult) {}

// Apply returns current unchanged.
func (NoMemory) Apply(_ natprobe.TraitsKey, current protocol.Traits) protocol.Traits { return current }

// Observe does nothing.
func (NoMemory) Observe(natprobe.TraitsKey, protocol.Traits, bool) {}

// Recall remembers nothing.
func (NoMemory) Recall(natprobe.TraitsKey) (protocol.Traits, bool) { return protocol.Traits{}, false }

// StrategyMemoryConfig configures NewStrategyMemory. Zero fields take the
// defaults; negative gains and penalties count as zero.
type StrategyMemoryConfig struct {
	TTL            time.Duration // 72 h, clamped to [1 h, 30 d]
	MaxEntries     int           // 65536, evicted least recently used per shard
	Shards         int           // 16
	Salt           []byte        // key salt; nil draws a random one (keep it with exported data)
	SuccessGain    int8          // +2
	FailurePenalty int8          // 1
	RotatePenalty  int8          // 1
	ScoreMin       int8          // -10
	ScoreMax       int8          // +10
	ReportsPerMin  int           // 6 reports per key and minute; more are ignored
	// Clock is the time source of TTLs and report rates; nil means the
	// system clock.
	Clock clock.Clock
}

// Memory defaults.
const (
	memMaxVariants   = 32 // the catalogue has at most 32 variants
	memDefTTL        = 72 * time.Hour
	memMinTTL        = time.Hour
	memMaxTTL        = 30 * 24 * time.Hour
	memDefEntries    = 65536
	memDefShards     = 16
	memDefReports    = 6
	memSaltSize      = 32
	memExportVersion = 1
	memRecordSize    = 16 + memMaxVariants + 4
)

// memExportMagic starts an exported memory.
const memExportMagic = "HPSM"

// NewStrategyMemory returns the built-in StrategyMemory: a sharded LRU (one
// mutex, one map and one list per shard) with lazy TTL checks and no
// goroutine. The returned value also has the methods
//
//	Sweep(now time.Time, max int) int // drops expired entries, scanning at most max
//	Export(w io.Writer) error         // 16 B key + 32 B scores + 4 B last use per entry
//	Import(r io.Reader) error
//
// reached through a type assertion; the coordinator's housekeeping calls
// Sweep every 10 s.
func NewStrategyMemory(cfg StrategyMemoryConfig) StrategyMemory {
	m := &memory{cfg: cfg}
	if m.cfg.TTL == 0 {
		m.cfg.TTL = memDefTTL
	}
	m.cfg.TTL = clampDur(m.cfg.TTL, memMinTTL, memMaxTTL)
	if m.cfg.MaxEntries <= 0 {
		m.cfg.MaxEntries = memDefEntries
	}
	if m.cfg.Shards <= 0 {
		m.cfg.Shards = memDefShards
	}
	m.cfg.Shards = min(m.cfg.Shards, m.cfg.MaxEntries)
	if m.cfg.SuccessGain == 0 {
		m.cfg.SuccessGain = 2
	}
	if m.cfg.FailurePenalty == 0 {
		m.cfg.FailurePenalty = 1
	}
	if m.cfg.RotatePenalty == 0 {
		m.cfg.RotatePenalty = 1
	}
	m.cfg.SuccessGain, m.cfg.FailurePenalty, m.cfg.RotatePenalty = max(m.cfg.SuccessGain, 0), max(m.cfg.FailurePenalty, 0), max(m.cfg.RotatePenalty, 0)
	if m.cfg.ScoreMin == 0 {
		m.cfg.ScoreMin = -10
	}
	if m.cfg.ScoreMax == 0 {
		m.cfg.ScoreMax = 10
	}
	if m.cfg.ScoreMin > m.cfg.ScoreMax {
		m.cfg.ScoreMin, m.cfg.ScoreMax = m.cfg.ScoreMax, m.cfg.ScoreMin
	}
	if m.cfg.ReportsPerMin <= 0 {
		m.cfg.ReportsPerMin = memDefReports
	}
	if m.cfg.Clock == nil {
		m.cfg.Clock = clock.System{}
	}
	m.salt = slices.Clone(m.cfg.Salt)
	if len(m.salt) == 0 {
		m.salt = make([]byte, memSaltSize)
		_, _ = rand.Read(m.salt) // crypto/rand.Read never fails (Go 1.24+)
	}
	per := (m.cfg.MaxEntries + m.cfg.Shards - 1) / m.cfg.Shards
	m.shards = make([]memShard, m.cfg.Shards)
	for i := range m.shards {
		m.shards[i].m = make(map[StrategyKey]*memEntry)
		m.shards[i].cap = per
	}
	return m
}

// memory is the built-in StrategyMemory.
type memory struct {
	cfg    StrategyMemoryConfig
	salt   []byte
	shards []memShard
}

type memShard struct {
	mu         sync.Mutex
	m          map[StrategyKey]*memEntry
	head, tail *memEntry // head: most recently used
	cap        int
}

type memEntry struct {
	key        StrategyKey
	scores     [memMaxVariants]int8 // indexed by VariantID
	lastUsed   int64                // unix seconds
	window     int64                // minute of the report counter
	reports    int
	prev, next *memEntry
}

// shard picks k's shard from its first eight bytes: one byte would leave
// every shard past the 256th empty, and the memory short of MaxEntries.
func (m *memory) shard(k StrategyKey) *memShard {
	return &m.shards[binary.BigEndian.Uint64(k[:8])%uint64(len(m.shards))]
}

func (m *memory) expired(e *memEntry, now int64) bool {
	return now-e.lastUsed >= int64(m.cfg.TTL/time.Second)
}

// Recommend implements StrategyMemory: the ladder ordered by score, highest
// first, ties in ladder order; an unknown key keeps the ladder order. The
// first entry loses RotatePenalty.
func (m *memory) Recommend(key StrategyKey, ladder []plan.VariantID) []plan.VariantID {
	out := slices.Clone(ladder)
	if len(out) == 0 {
		return out
	}
	now := m.cfg.Clock.Now().Unix()
	sh := m.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.lookup(m, key, now, true)
	slices.SortStableFunc(out, func(a, b plan.VariantID) int { return int(e.score(b)) - int(e.score(a)) })
	e.add(out[0], -m.cfg.RotatePenalty, m.cfg.ScoreMin, m.cfg.ScoreMax)
	return out
}

// Report implements StrategyMemory, at most ReportsPerMin times per key and
// minute.
func (m *memory) Report(key StrategyKey, v plan.VariantID, r MemoryResult) {
	if r != MemSuccess && r != MemFailure {
		return
	}
	now := m.cfg.Clock.Now().Unix()
	sh := m.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.lookup(m, key, now, true)
	if minute := now / 60; e.window != minute {
		e.window, e.reports = minute, 0
	}
	if e.reports >= m.cfg.ReportsPerMin {
		return
	}
	e.reports++
	if r == MemSuccess {
		e.add(v, m.cfg.SuccessGain, m.cfg.ScoreMin, m.cfg.ScoreMax)
	} else {
		e.add(v, -m.cfg.FailurePenalty, m.cfg.ScoreMin, m.cfg.ScoreMax)
	}
}

// Score implements StrategyMemory: v's current score for key, read without
// touching the entry.
func (m *memory) Score(key StrategyKey, v plan.VariantID) int {
	now := m.cfg.Clock.Now().Unix()
	sh := m.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return int(sh.lookup(m, key, now, false).score(v))
}

// len counts the entries (Stats.MemoryEntries).
func (m *memory) len() int {
	n := 0
	for i := range m.shards {
		sh := &m.shards[i]
		sh.mu.Lock()
		n += len(sh.m)
		sh.mu.Unlock()
	}
	return n
}

// Sweep drops expired entries, scanning at most max entries from the least
// recently used end of the shards, and returns how many it dropped.
func (m *memory) Sweep(now time.Time, max int) int {
	removed, budget := 0, max
	for i := range m.shards {
		sh := &m.shards[i]
		sh.mu.Lock()
		for e := sh.tail; e != nil && budget > 0; budget-- {
			prev := e.prev
			if !m.expired(e, now.Unix()) {
				break // the list is ordered by last use
			}
			sh.remove(e)
			removed++
			e = prev
		}
		sh.mu.Unlock()
	}
	return removed
}

// Export writes every live entry, least recently used first.
func (m *memory) Export(w io.Writer) error {
	bw := bufio.NewWriter(w)
	var recs [][memRecordSize]byte
	now := m.cfg.Clock.Now().Unix()
	for i := range m.shards {
		sh := &m.shards[i]
		sh.mu.Lock()
		for e := sh.tail; e != nil; e = e.prev {
			if m.expired(e, now) {
				continue
			}
			var rec [memRecordSize]byte
			copy(rec[:16], e.key[:])
			for j, s := range e.scores {
				rec[16+j] = byte(s)
			}
			binary.BigEndian.PutUint32(rec[16+memMaxVariants:], uint32(e.lastUsed))
			recs = append(recs, rec)
		}
		sh.mu.Unlock()
	}
	var hdr [len(memExportMagic) + 1 + 4]byte
	copy(hdr[:], memExportMagic)
	hdr[len(memExportMagic)] = memExportVersion
	binary.BigEndian.PutUint32(hdr[len(memExportMagic)+1:], uint32(len(recs)))
	if _, err := bw.Write(hdr[:]); err != nil {
		return err
	}
	for i := range recs {
		if _, err := bw.Write(recs[i][:]); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// errMemoryFormat: Import met data that Export did not write.
var errMemoryFormat = errors.New("coord: not an exported strategy memory")

// Import adds the entries written by Export; expired entries are skipped and
// existing keys are replaced.
func (m *memory) Import(r io.Reader) error {
	br := bufio.NewReader(r)
	var hdr [len(memExportMagic) + 1 + 4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return fmt.Errorf("%w: %w", errMemoryFormat, err)
	}
	if string(hdr[:len(memExportMagic)]) != memExportMagic || hdr[len(memExportMagic)] != memExportVersion {
		return errMemoryFormat
	}
	n := binary.BigEndian.Uint32(hdr[len(memExportMagic)+1:])
	type rec struct {
		key    StrategyKey
		scores [memMaxVariants]int8
		last   int64
	}
	recs := make([]rec, 0, int(min(uint64(n), uint64(m.cfg.MaxEntries))))
	for range n {
		var b [memRecordSize]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return fmt.Errorf("%w: %w", errMemoryFormat, err)
		}
		var x rec
		copy(x.key[:], b[:16])
		for j := range x.scores {
			x.scores[j] = min(max(int8(b[16+j]), m.cfg.ScoreMin), m.cfg.ScoreMax)
		}
		x.last = int64(binary.BigEndian.Uint32(b[16+memMaxVariants:]))
		recs = append(recs, x)
	}
	// Oldest first, so that the lists stay ordered by last use.
	slices.SortStableFunc(recs, func(a, b rec) int { return cmp.Compare(a.last, b.last) })
	now := m.cfg.Clock.Now().Unix()
	for _, x := range recs {
		e := &memEntry{key: x.key, scores: x.scores, lastUsed: x.last}
		if m.expired(e, now) {
			continue
		}
		sh := m.shard(x.key)
		sh.mu.Lock()
		if old := sh.m[x.key]; old != nil {
			sh.remove(old)
		}
		sh.insert(e)
		sh.mu.Unlock()
	}
	return nil
}

// lookup returns key's entry, dropping an expired one. With use it is a use
// of the entry: a missing key gets a fresh entry (all scores 0), evicting the
// least recently used one when the shard is full, and the entry's last use
// becomes now, at the front of the list. Without use the entry is only read
// and a missing key yields an empty entry that is not stored. The list stays
// ordered by last use, which Sweep relies on.
func (sh *memShard) lookup(m *memory, key StrategyKey, now int64, use bool) *memEntry {
	e := sh.m[key]
	if e != nil && m.expired(e, now) {
		sh.remove(e)
		e = nil
	}
	switch {
	case !use:
		if e == nil {
			e = &memEntry{}
		}
		return e
	case e == nil:
		e = &memEntry{key: key, lastUsed: now}
		sh.insert(e)
	default:
		e.lastUsed = now
		sh.unlink(e)
		sh.pushFront(e)
	}
	return e
}

func (sh *memShard) insert(e *memEntry) {
	for len(sh.m) >= sh.cap && sh.tail != nil {
		sh.remove(sh.tail)
	}
	sh.m[e.key] = e
	sh.pushFront(e)
}

func (sh *memShard) remove(e *memEntry) {
	sh.unlink(e)
	delete(sh.m, e.key)
}

func (sh *memShard) pushFront(e *memEntry) {
	e.prev, e.next = nil, sh.head
	if sh.head != nil {
		sh.head.prev = e
	}
	sh.head = e
	if sh.tail == nil {
		sh.tail = e
	}
}

func (sh *memShard) unlink(e *memEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if sh.head == e {
		sh.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if sh.tail == e {
		sh.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

func (e *memEntry) score(v plan.VariantID) int8 {
	if int(v) >= memMaxVariants {
		return 0
	}
	return e.scores[v]
}

func (e *memEntry) add(v plan.VariantID, d, lo, hi int8) {
	if int(v) >= memMaxVariants {
		return
	}
	e.scores[v] = int8(min(max(int(e.scores[v])+int(d), int(lo)), int(hi)))
}

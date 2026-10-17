package coord

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

type memClock struct {
	clock.System // timers; the memory reads only Now
	mu           sync.Mutex
	now          time.Time
}

func (c *memClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *memClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newMem(cfg StrategyMemoryConfig) (*memory, *memClock) {
	clk := &memClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	cfg.Clock = clk
	return NewStrategyMemory(cfg).(*memory), clk
}

func TestStrategyMemoryScores(t *testing.T) {
	m, clk := newMem(StrategyMemoryConfig{Salt: []byte("salt")})
	key := StrategyKey{1}
	ladder := []VariantID{3, 4, 5}
	if got := m.Recommend(key, ladder); !slices.Equal(got, ladder) {
		t.Fatalf("unknown key: %v", got)
	}
	if m.score(key, 3) != -1 { // the first recommendation rotates
		t.Fatalf("rotation: %d", m.score(key, 3))
	}
	m.Report(key, 5, MemSuccess)
	m.Report(key, 4, MemFailure)
	m.Report(key, 4, MemNeutral)
	if got := m.Recommend(key, ladder); !slices.Equal(got, []VariantID{5, 3, 4}) {
		t.Fatalf("ordered: %v", got)
	}
	for range 10 {
		clk.advance(time.Minute)
		m.Report(key, 5, MemSuccess)
	}
	if m.score(key, 5) != 10 {
		t.Fatalf("ceiling: %d", m.score(key, 5))
	}
	for range 30 {
		clk.advance(time.Minute)
		m.Report(key, 3, MemFailure)
	}
	if m.score(key, 3) != -10 {
		t.Fatalf("floor: %d", m.score(key, 3))
	}
	// At most 6 reports per key and minute.
	k2 := StrategyKey{2}
	for range 9 {
		m.Report(k2, 1, MemSuccess)
	}
	if m.score(k2, 1) != 10 { // 6 × 2, capped at 10
		t.Fatalf("rate limit: %d", m.score(k2, 1))
	}
	k3 := StrategyKey{3}
	for range 9 {
		m.Report(k3, 1, MemFailure)
	}
	if m.score(k3, 1) != -6 {
		t.Fatalf("rate limit: %d", m.score(k3, 1))
	}
	// Variants beyond the score array have no memory.
	m.Report(key, 40, MemSuccess)
	if m.score(key, 40) != 0 {
		t.Fatal("variant 40 scored")
	}
	if m.Recommend(key, nil) != nil && len(m.Recommend(key, nil)) != 0 {
		t.Fatal("empty ladder")
	}
}

func TestStrategyMemoryTTLAndSweep(t *testing.T) {
	m, clk := newMem(StrategyMemoryConfig{TTL: time.Minute}) // clamped to 1 h
	for i := range 5 {
		m.Report(StrategyKey{byte(i)}, 1, MemSuccess)
	}
	if m.len() != 5 {
		t.Fatalf("len %d", m.len())
	}
	clk.advance(30 * time.Minute)
	m.Report(StrategyKey{0}, 1, MemSuccess) // refreshed
	clk.advance(31 * time.Minute)
	if m.score(StrategyKey{1}, 1) != 0 {
		t.Fatal("expired entry still scored")
	}
	if n := m.Sweep(clk.Now(), 1024); n != 3 || m.len() != 1 { // key 1 was dropped by the lookup above
		t.Fatalf("sweep removed %d, len %d", n, m.len())
	}
	if m.score(StrategyKey{0}, 1) != 4 {
		t.Fatalf("live entry %d", m.score(StrategyKey{0}, 1))
	}
}

func TestStrategyMemoryEviction(t *testing.T) {
	m, _ := newMem(StrategyMemoryConfig{MaxEntries: 4, Shards: 1})
	for i := range 6 {
		m.Report(StrategyKey{byte(i)}, 1, MemSuccess)
	}
	if m.len() != 4 || m.score(StrategyKey{0}, 1) != 0 || m.score(StrategyKey{5}, 1) != 2 {
		t.Fatalf("len %d", m.len())
	}
}

func TestStrategyMemoryExportImport(t *testing.T) {
	m, clk := newMem(StrategyMemoryConfig{Salt: []byte("s")})
	for i := range 20 {
		m.Report(StrategyKey{byte(i)}, VariantID(i%5+1), MemSuccess)
		clk.advance(time.Second)
	}
	var buf bytes.Buffer
	if err := m.Export(&buf); err != nil {
		t.Fatal(err)
	}
	m2, clk2 := newMem(StrategyMemoryConfig{Salt: []byte("s")})
	clk2.advance(20 * time.Second)
	if err := m2.Import(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		if m2.score(StrategyKey{byte(i)}, VariantID(i%5+1)) != 2 {
			t.Fatalf("entry %d lost", i)
		}
	}
	if err := m2.Import(bytes.NewReader([]byte("nope"))); err == nil {
		t.Fatal("bad data imported")
	}
	if err := m2.Import(bytes.NewReader(buf.Bytes()[:30])); err == nil {
		t.Fatal("truncated data imported")
	}
	bad := append([]byte(nil), buf.Bytes()...)
	bad[4] = 9
	if err := m2.Import(bytes.NewReader(bad)); err == nil {
		t.Fatal("unknown version imported")
	}
	// Expired entries are neither exported nor imported.
	clk.advance(100 * time.Hour)
	var empty bytes.Buffer
	if err := m.Export(&empty); err != nil || empty.Len() != 9 {
		t.Fatalf("export of expired entries: %d bytes, %v", empty.Len(), err)
	}
	m3, clk3 := newMem(StrategyMemoryConfig{})
	clk3.advance(100 * time.Hour)
	if err := m3.Import(bytes.NewReader(buf.Bytes())); err != nil || m3.len() != 0 {
		t.Fatalf("expired import: %d, %v", m3.len(), err)
	}
}

func TestDeriveStrategyKey(t *testing.T) {
	a := StrategySide{IPPrefix: netip.MustParsePrefix("203.0.113.10/32"), ClassBits: 7}
	b := StrategySide{IPPrefix: netip.MustParsePrefix("2001:db8::/64"), ClassBits: 9}
	k := DeriveStrategyKey([]byte("salt"), a, b)
	if k != DeriveStrategyKey([]byte("salt"), a, b) || k == DeriveStrategyKey([]byte("salt"), b, a) ||
		k == DeriveStrategyKey([]byte("pepper"), a, b) {
		t.Fatal("key derivation")
	}
	if len(k.String()) != 32 {
		t.Fatalf("hex %q", k.String())
	}
	var nm NoMemory
	if got := nm.Recommend(k, []VariantID{1, 2}); !slices.Equal(got, []VariantID{1, 2}) {
		t.Fatal("NoMemory order")
	}
	nm.Report(k, 1, MemSuccess)
	tr := protocol.Traits{Mapping: protocol.MapEIM}
	if nm.Apply(natprobe.TraitsKey{}, tr) != tr {
		t.Fatal("NoMemory Apply")
	}
	nm.Observe(natprobe.TraitsKey{}, tr, true)
}

// TestMemoryFeedback: the confirmed round's variant gains, unconfirmed
// NoContact rounds lose, aborted sessions report nothing, and the same pair
// of exits gets the same key whichever side initiates.
func TestMemoryFeedback(t *testing.T) {
	m, _ := newMem(StrategyMemoryConfig{})
	r := newRig(t, func(c *Config) { c.Memory = m })
	run := func(swap bool, rounds int, confirm bool) Result {
		t.Helper()
		p := r.pair(SessionOptions{})
		fams := [2]simclient.Family{fam(0, simclient.OpenTraits), fam(1, simclient.OpenTraits)}
		if swap {
			fams[0], fams[1] = fams[1], fams[0]
			fams[0].Local, fams[1].Local = localI, localR
		}
		p.report(0, fams[0])
		p.report(1, fams[1])
		var sums [2]*protocol.ProbeSummary
		for i := range 2 {
			sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
		}
		for i := range 2 {
			send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 1))
		}
		for i := range 2 {
			expect[protocol.PunchGo](t, p.cl[i])
		}
		k := uint8(1)
		for ; int(k) < rounds; k++ {
			p.endRound(k, [2]simclient.Outcome{fired(5), fired(5)})
		}
		if confirm {
			p.confirm(0, k)
			p.confirm(1, k)
			p.succeed(0, k)
			p.succeed(1, k)
		} else {
			p.s.Abort(protocol.ReasonCanceled, "")
		}
		return r.wait(p.s)
	}
	res := run(false, 2, true)
	key := res.StrategyKey
	if key == "" || res.Rounds[0].Class != RoundNoContact || res.Winner.Round != 2 {
		t.Fatalf("result %+v", res)
	}
	var k StrategyKey
	kb, _ := hex.DecodeString(key)
	copy(k[:], kb)
	if m.score(k, res.Rounds[1].Variant) != 2 || m.score(k, res.Rounds[0].Variant) != -2 {
		t.Fatalf("scores %d %d", m.score(k, res.Rounds[1].Variant), m.score(k, res.Rounds[0].Variant))
	}
	res2 := run(true, 1, false)
	if res2.StrategyKey != key {
		t.Fatalf("swapped sides got key %s, want %s", res2.StrategyKey, key)
	}
	if !res2.MemoryHit {
		t.Fatal("the proven variant was not recommended first")
	}
}

// panicMemory panics in Recommend: the session goes on without memory.
type panicMemory struct{ NoMemory }

func (panicMemory) Recommend(StrategyKey, []VariantID) []VariantID { panic("memory") }

func TestMemoryPanicIgnored(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Memory = panicMemory{} })
	p := r.pair(SessionOptions{})
	p.summaries()
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
	if r.c.Stats().Panics == 0 {
		t.Fatal("panic not counted")
	}
}

// TestStrategySalt: keys for a custom memory use Config.StrategySalt, so
// coordinators that share the memory and the salt derive the same keys;
// without it each Coordinator draws its own; the built-in memory keeps its
// own salt.
func TestStrategySalt(t *testing.T) {
	salt := []byte("one salt for every coordinator")
	mk := func(cfg Config) *Coordinator {
		cfg.NoObserver = true // relay-only: no registry needed
		c, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	a, b := mk(Config{Memory: NoMemory{}, StrategySalt: salt}), mk(Config{Memory: NoMemory{}, StrategySalt: salt})
	if !bytes.Equal(a.salt, salt) || !bytes.Equal(b.salt, salt) {
		t.Fatal("the shared salt is not used")
	}
	c, d := mk(Config{Memory: NoMemory{}}), mk(Config{Memory: NoMemory{}})
	if len(c.salt) != memSaltSize || bytes.Equal(c.salt, d.salt) {
		t.Fatal("no random salt per coordinator")
	}
	own := []byte("the memory's own")
	if e := mk(Config{Memory: NewStrategyMemory(StrategyMemoryConfig{Salt: own}), StrategySalt: salt}); !bytes.Equal(e.salt, own) {
		t.Fatal("the built-in memory's salt was replaced")
	}
}

// TestStrategyMemoryShards: more than 256 shards all hold entries: the
// memory keeps MaxEntries keys.
func TestStrategyMemoryShards(t *testing.T) {
	const n = 512
	m, _ := newMem(StrategyMemoryConfig{MaxEntries: n, Shards: n})
	for i := range n {
		var k StrategyKey
		binary.BigEndian.PutUint64(k[:8], uint64(i))
		m.Report(k, 1, MemSuccess)
	}
	if got := m.len(); got != n {
		t.Fatalf("%d entries kept of %d", got, n)
	}
}

// TestStrategyMemorySweepOrder: the list stays ordered by last use, so a
// sweep from its old end finds every expired entry. Reading a score is no
// use; a report over the rate is one.
func TestStrategyMemorySweepOrder(t *testing.T) {
	m, clk := newMem(StrategyMemoryConfig{TTL: time.Hour, Shards: 1, ReportsPerMin: 1})
	a, b := StrategyKey{1}, StrategyKey{2}
	m.Report(a, 1, MemSuccess)
	clk.advance(30 * time.Minute)
	m.Report(b, 1, MemSuccess)
	m.score(a, 1)
	clk.advance(31 * time.Minute)
	if n := m.Sweep(clk.Now(), 1024); n != 1 || m.len() != 1 || m.score(b, 1) != 2 {
		t.Fatalf("score read: sweep removed %d, %d left; want the expired entry gone", n, m.len())
	}

	m, clk = newMem(StrategyMemoryConfig{TTL: time.Hour, Shards: 1, ReportsPerMin: 1})
	m.Report(a, 1, MemSuccess)
	clk.advance(30 * time.Second)
	m.Report(b, 1, MemSuccess)
	clk.advance(10 * time.Second)
	m.Report(a, 1, MemSuccess) // over the rate: no score, but a use
	clk.advance(time.Hour - 5*time.Second)
	if n := m.Sweep(clk.Now(), 1024); n != 1 || m.len() != 1 || m.score(a, 1) != 2 {
		t.Fatalf("report over the rate: sweep removed %d, %d left; want the entry it used kept", n, m.len())
	}
}

// reversingMemory recommends the ladder reversed, in place.
type reversingMemory struct{ NoMemory }

func (reversingMemory) Recommend(_ StrategyKey, ladder []VariantID) []VariantID {
	slices.Reverse(ladder)
	return ladder
}

// TestMemoryGetsLadderCopy: a memory that reorders the ladder it is given
// reorders the session's order, not the classification's ladder.
func TestMemoryGetsLadderCopy(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Memory = reversingMemory{} })
	p := r.pair(SessionOptions{})
	p.summaries()
	p.s.mu.Lock()
	ladder, order := slices.Clone(p.s.st.cls.Ladder), slices.Clone(p.s.st.order)
	p.s.mu.Unlock()
	slices.Reverse(order)
	if len(ladder) < 2 || !slices.Equal(ladder, order) {
		t.Fatalf("ladder %v, order reversed %v", ladder, order)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

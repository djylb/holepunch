package natprobe

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/protocol"
)

func eimMedium() protocol.Traits {
	return protocol.Traits{Family: protocol.FamilyUDP4, Mapping: protocol.MapEIM, MappingConf: protocol.ConfMedium,
		PortAlloc: protocol.AllocPreserving, PortAllocConf: protocol.ConfHigh, Filtering: protocol.FiltNotPDF, FilteringConf: protocol.ConfHigh, Samples: 3}
}

func mkey(ip string) TraitsKey {
	return TraitsKey{ClientKey: "c1", Family: protocol.FamilyUDP4, PublicIP: netip.MustParseAddr(ip)}
}

func TestMemoryRules(t *testing.T) {
	clk := newManualClock()
	mem := NewTraitsMemory(TraitsMemoryConfig{Clock: clk})
	k := mkey("203.0.113.5")
	if got := mem.Apply(k, eimMedium()); got != eimMedium() {
		t.Fatal("an empty memory changed the traits")
	}
	// a peer-verified EIM with EIF filtering and no hairpin
	final := eimMedium()
	final.MappingConf, final.CrossIP, final.Filtering, final.FilteringConf, final.Hairpin = protocol.ConfHigh, true, protocol.FiltEIF, protocol.ConfHigh, protocol.TriFalse
	mem.Observe(k, final, true)
	got := mem.Apply(k, eimMedium())
	if got.MappingConf != protocol.ConfHigh || !got.CrossIP || got.Filtering != protocol.FiltEIF || got.FilteringConf != protocol.ConfMedium || got.Hairpin != protocol.TriFalse {
		t.Fatalf("applied %+v", got)
	}
	// direct evidence is never overturned: PDF stays PDF, a known hairpin stays
	cur := eimMedium()
	cur.Filtering, cur.Hairpin = protocol.FiltPDF, protocol.TriTrue
	if got := mem.Apply(k, cur); got.Filtering != protocol.FiltPDF || got.Hairpin != protocol.TriTrue || got.MappingConf != protocol.ConfHigh {
		t.Fatalf("overturned %+v", got)
	}
	// another client key or another public IP: nothing applies
	if got := mem.Apply(TraitsKey{ClientKey: "c2", Family: protocol.FamilyUDP4, PublicIP: k.PublicIP}, eimMedium()); got != eimMedium() {
		t.Fatal("other client")
	}
	if got := mem.Apply(mkey("203.0.113.6"), eimMedium()); got != eimMedium() {
		t.Fatal("other public IP")
	}
	if got := mem.Apply(TraitsKey{}, eimMedium()); got != eimMedium() {
		t.Fatal("zero key")
	}
	// a later observation updates the memo
	mem.Observe(k, final, false)
	// the TTL
	clk.Advance(25 * time.Hour)
	if got := mem.Apply(k, eimMedium()); got != eimMedium() {
		t.Fatal("an expired memo applied")
	}
}

func TestMemoryADMRefinesSingleIPEIM(t *testing.T) {
	mem := NewTraitsMemory(TraitsMemoryConfig{})
	k := mkey("203.0.113.5")
	final := eimMedium()
	final.Mapping, final.MappingConf, final.CrossIP = protocol.MapADM, protocol.ConfHigh, true
	mem.Observe(k, final, false)
	got := mem.Apply(k, eimMedium())
	if got.Mapping != protocol.MapADM || got.MappingConf != protocol.ConfMedium {
		t.Fatalf("applied %+v", got)
	}
	// an EIM already raised by direct cross-IP evidence is left alone
	cur := eimMedium()
	cur.MappingConf, cur.CrossIP = protocol.ConfHigh, true
	if got := mem.Apply(k, cur); got.Mapping != protocol.MapEIM {
		t.Fatalf("direct evidence overturned: %+v", got)
	}
}

func TestMemorySequentialVelocity(t *testing.T) {
	mem := NewTraitsMemory(TraitsMemoryConfig{})
	k := mkey("203.0.113.5")
	seq := protocol.Traits{Family: protocol.FamilyUDP4, Mapping: protocol.MapAPDM, MappingConf: protocol.ConfHigh,
		PortAlloc: protocol.AllocSequential, PortAllocConf: protocol.ConfHigh, PortStep: 2, PortVelocity: 40}
	mem.Observe(k, seq, true)
	cur := seq
	cur.PortVelocity = 0
	if got := mem.Apply(k, cur); got.PortVelocity != 40 {
		t.Fatalf("velocity not filled: %+v", got)
	}
	cur.PortStep = -2 // the opposite direction: not applied
	if got := mem.Apply(k, cur); got.PortVelocity != 0 {
		t.Fatalf("velocity of the other direction: %+v", got)
	}
	cur.PortStep, cur.PortVelocity = 2, 7 // measured: kept
	if got := mem.Apply(k, cur); got.PortVelocity != 7 {
		t.Fatal("the measured velocity was replaced")
	}
	// an observation without a velocity keeps the remembered one
	seq.PortVelocity = 0
	mem.Observe(k, seq, true)
	cur.PortVelocity = 0
	if got := mem.Apply(k, cur); got.PortVelocity != 40 {
		t.Fatalf("velocity forgotten: %+v", got)
	}
}

// Two inconsistent observations delete the memo.
func TestMemoryConflicts(t *testing.T) {
	mem := NewTraitsMemory(TraitsMemoryConfig{})
	k := mkey("203.0.113.5")
	final := eimMedium()
	final.MappingConf, final.CrossIP = protocol.ConfHigh, true
	mem.Observe(k, final, true)
	apdm := protocol.Traits{Family: protocol.FamilyUDP4, Mapping: protocol.MapAPDM, MappingConf: protocol.ConfHigh, PortAlloc: protocol.AllocRandom}
	mem.Observe(k, apdm, false)
	if got := mem.Apply(k, eimMedium()); got.MappingConf != protocol.ConfHigh {
		t.Fatal("one conflict already deleted the memo")
	}
	// an inconsistent current classification gets nothing
	if got := mem.Apply(k, apdm); got != apdm {
		t.Fatalf("applied to an inconsistent NAT: %+v", got)
	}
	mem.Observe(k, apdm, false)
	if got := mem.Apply(k, eimMedium()); got.MappingConf != protocol.ConfMedium {
		t.Fatal("two conflicts did not delete the memo")
	}
	// nothing worth remembering makes no memo
	mem.Observe(k, protocol.Traits{Family: protocol.FamilyUDP4}, true)
	mem.Observe(TraitsKey{}, final, true)
	mem.Observe(TraitsKey{PublicIP: k.PublicIP, Family: "udp9"}, final, true)
	if n := mem.(*traitsMemory).len(); n != 0 {
		t.Fatalf("%d memos", n)
	}
}

func (m *traitsMemory) len() int {
	n := 0
	for i := range m.shards {
		m.shards[i].mu.Lock()
		n += m.shards[i].lru.Len()
		m.shards[i].mu.Unlock()
	}
	return n
}

func TestMemoryLRUBound(t *testing.T) {
	mem := NewTraitsMemory(TraitsMemoryConfig{MaxEntries: 64})
	final := eimMedium()
	final.Hairpin = protocol.TriTrue
	for i := range 1000 {
		mem.Observe(mkey(fmt.Sprintf("198.51.%d.%d", i/250, i%250+1)), final, true)
	}
	if n := mem.(*traitsMemory).len(); n > 64 {
		t.Fatalf("%d memos > 64", n)
	}
	// the most recent ones survive
	if got := mem.Apply(mkey("198.51.3.250"), eimMedium()); got.Hairpin != protocol.TriTrue {
		t.Fatal("a recent memo was evicted")
	}
}

func TestMemoryConcurrent(t *testing.T) {
	mem := NewTraitsMemory(TraitsMemoryConfig{MaxEntries: 256})
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 500 {
				k := mkey(fmt.Sprintf("198.51.100.%d", (g*31+i)%200+1))
				f := eimMedium()
				f.Hairpin = protocol.TriTrue
				mem.Observe(k, f, i%2 == 0)
				_ = mem.Apply(k, eimMedium())
			}
		})
	}
	wg.Wait()
}

// An observation that carries nothing worth remembering does not
// renew the memo: 100 h after the only cross-IP verification, a single-IP
// EIM is no longer raised (TTL 24 h).
func TestMemoryNotRenewedWithoutEvidence(t *testing.T) {
	clk := newManualClock()
	mem := NewTraitsMemory(TraitsMemoryConfig{Clock: clk})
	k := mkey("203.0.113.5")
	final := eimMedium()
	final.MappingConf, final.CrossIP = protocol.ConfHigh, true
	mem.Observe(k, final, true)
	for range 5 {
		clk.Advance(20 * time.Hour)
		mem.Observe(k, protocol.Traits{Family: protocol.FamilyUDP4}, false) // measured nothing
		mem.Observe(k, eimMedium(), true)                                   // single-IP evidence only
	}
	if got := mem.Apply(k, eimMedium()); got.MappingConf == protocol.ConfHigh || got.CrossIP {
		t.Fatalf("a 100 h old verification still raises the mapping: %+v", got)
	}
}

// Apply's output never renews a conclusion. Apply only
// reads: a memo consulted every hour still expires 24 h after its last
// measurement. And in the coordinator's cycle — Apply raises the session's
// single-IP EIM in its summary, Observe gets the session's direct
// measurement, never Apply's output — sessions every 20 h that measure only
// one server IP are raised once and then fall back to Medium.
func TestMemoryNoSelfRenewal(t *testing.T) {
	single := protocol.Traits{Family: protocol.FamilyUDP4, Mapping: protocol.MapEIM, MappingConf: protocol.ConfMedium, Samples: 3}
	verified := single
	verified.MappingConf, verified.CrossIP = protocol.ConfHigh, true

	clk := newManualClock()
	mem := NewTraitsMemory(TraitsMemoryConfig{Clock: clk})
	k := mkey("203.0.113.5")
	mem.Observe(k, verified, true) // the only cross-IP verification
	for h := 1; h <= 30; h++ {
		clk.Advance(time.Hour)
		raised := mem.Apply(k, single).MappingConf == protocol.ConfHigh
		if raised != (h < 24) {
			t.Fatalf("Apply only, %d h after the verification: raised %v", h, raised)
		}
	}

	clk = newManualClock()
	mem = NewTraitsMemory(TraitsMemoryConfig{Clock: clk})
	mem.Observe(k, verified, true)
	var raised []int
	for i := 1; i <= 10; i++ {
		clk.Advance(20 * time.Hour)
		summary := mem.Apply(k, single) // what the session's summary carries
		if summary.MappingConf == protocol.ConfHigh {
			raised = append(raised, i)
			if !summary.CrossIP {
				t.Fatalf("session %d: a raise without CrossIP: %+v", i, summary)
			}
		}
		mem.Observe(k, single, true) // the direct measurement, not the summary
	}
	if len(raised) != 1 || raised[0] != 1 {
		t.Fatalf("sessions raised: %v, want only the one 20 h after the verification", raised)
	}
}

// A direct measurement that agrees with a remembered conclusion
// renews it, conclusion by conclusion; one that does not establish a
// conclusion leaves its expiry alone.
func TestMemoryDirectMeasurementRenews(t *testing.T) {
	clk := newManualClock()
	mem := NewTraitsMemory(TraitsMemoryConfig{Clock: clk})
	k := mkey("203.0.113.5")
	verified := eimMedium()
	verified.MappingConf, verified.CrossIP = protocol.ConfHigh, true
	verified.Filtering, verified.FilteringConf, verified.Hairpin = protocol.FiltEIF, protocol.ConfHigh, protocol.TriTrue
	mem.Observe(k, verified, true)
	clk.Advance(20 * time.Hour)
	again := verified
	again.Hairpin = protocol.TriUnknown // this session's measurement: cross-IP EIM and EIF, no hairpin test
	mem.Observe(k, again, true)
	clk.Advance(20 * time.Hour) // 40 h after the first, 20 h after the renewal
	got := mem.Apply(k, eimMedium())
	if got.MappingConf != protocol.ConfHigh || !got.CrossIP || got.Filtering != protocol.FiltEIF {
		t.Fatalf("the renewed conclusions expired: %+v", got)
	}
	if got.Hairpin != protocol.TriUnknown {
		t.Fatalf("the hairpin, measured 40 h ago, was renewed: %+v", got)
	}
	clk.Advance(5 * time.Hour)
	if got := mem.Apply(k, eimMedium()); got.MappingConf != protocol.ConfMedium {
		t.Fatalf("25 h after the renewal: %+v", got)
	}

	// The sequential allocation renews too; a measured velocity replaces the
	// remembered one, a missing one keeps it.
	seq := protocol.Traits{Family: protocol.FamilyUDP4, Mapping: protocol.MapAPDM, MappingConf: protocol.ConfHigh,
		PortAlloc: protocol.AllocSequential, PortAllocConf: protocol.ConfHigh, PortStep: 2, PortVelocity: 40}
	k2 := mkey("203.0.113.6")
	mem.Observe(k2, seq, true)
	clk.Advance(20 * time.Hour)
	seq.PortVelocity = 0
	mem.Observe(k2, seq, true)
	clk.Advance(20 * time.Hour)
	if got := mem.Apply(k2, seq); got.PortVelocity != 40 {
		t.Fatalf("the renewed allocation lost its velocity: %+v", got)
	}
}

// Each conclusion expires on its own: a hairpin learned later outlives the
// mapping learned earlier, and a contradicting observation replaces a
// conclusion at once.
func TestMemoryPerConclusionExpiry(t *testing.T) {
	clk := newManualClock()
	mem := NewTraitsMemory(TraitsMemoryConfig{Clock: clk})
	k := mkey("203.0.113.5")
	verified := eimMedium()
	verified.MappingConf, verified.CrossIP = protocol.ConfHigh, true
	mem.Observe(k, verified, true)
	clk.Advance(20 * time.Hour)
	hp := protocol.Traits{Family: protocol.FamilyUDP4, Hairpin: protocol.TriTrue}
	mem.Observe(k, hp, true)
	clk.Advance(10 * time.Hour)
	got := mem.Apply(k, eimMedium())
	if got.MappingConf != protocol.ConfMedium || got.Hairpin != protocol.TriTrue {
		t.Fatalf("30 h: %+v, want the mapping expired and the hairpin kept", got)
	}
	hp.Hairpin = protocol.TriFalse
	mem.Observe(k, hp, true)
	if got := mem.Apply(k, eimMedium()); got.Hairpin != protocol.TriFalse {
		t.Fatalf("a contradicting hairpin was not learned: %+v", got)
	}
	clk.Advance(25 * time.Hour)
	if n := mem.(*traitsMemory).len(); n != 1 {
		t.Fatalf("%d memos", n)
	}
	mem.Apply(k, eimMedium()) // lazily drops the fully expired memo
	if n := mem.(*traitsMemory).len(); n != 0 {
		t.Fatalf("%d memos after every conclusion expired", n)
	}
}

// A MaxEntries below the shard count is still a bound.
func TestMemorySmallMaxEntries(t *testing.T) {
	for _, maxE := range []int{1, 4, 15, 17} {
		mem := NewTraitsMemory(TraitsMemoryConfig{MaxEntries: maxE})
		final := eimMedium()
		final.Hairpin = protocol.TriTrue
		for i := range 1000 {
			mem.Observe(mkey(fmt.Sprintf("198.51.%d.%d", i/250, i%250+1)), final, true)
		}
		if n := mem.(*traitsMemory).len(); n > maxE || n == 0 {
			t.Fatalf("MaxEntries %d: %d memos", maxE, n)
		}
	}
}

// A sequential allocation learned again after its memo expired does not
// inherit the expired velocity; one measured again replaces it.
func TestMemoryAllocationRelearned(t *testing.T) {
	clk := newManualClock()
	mem := NewTraitsMemory(TraitsMemoryConfig{Clock: clk})
	k := mkey("203.0.113.5")
	seq := protocol.Traits{Family: protocol.FamilyUDP4, Mapping: protocol.MapAPDM, MappingConf: protocol.ConfHigh,
		PortAlloc: protocol.AllocSequential, PortAllocConf: protocol.ConfHigh, PortStep: 2, PortVelocity: 40, Hairpin: protocol.TriTrue}
	mem.Observe(k, seq, true)
	clk.Advance(20 * time.Hour)
	mem.Observe(k, protocol.Traits{Family: protocol.FamilyUDP4, Hairpin: protocol.TriFalse}, true) // keeps the memo alive
	clk.Advance(5 * time.Hour)                                                                     // the allocation expired
	seq.PortVelocity = 0
	mem.Observe(k, seq, true)
	cur := seq
	if got := mem.Apply(k, cur); got.PortVelocity != 0 {
		t.Fatalf("an expired velocity came back: %+v", got)
	}
	seq.PortVelocity = 25
	mem.Observe(k, seq, true)
	if got := mem.Apply(k, cur); got.PortVelocity != 25 {
		t.Fatalf("a new velocity was not learned: %+v", got)
	}
}

// The memory's Clock is the caller's code: Apply reads it before taking a
// shard lock, so a Clock that panics once leaves no lock held.
func TestMemoryClockPanicHoldsNoLock(t *testing.T) {
	var panicking atomic.Bool
	mem := NewTraitsMemory(TraitsMemoryConfig{Clock: panicClock{panicking: &panicking}})
	k := mkey("203.0.113.5")
	final := eimMedium()
	final.Hairpin = protocol.TriTrue
	mem.Observe(k, final, true)
	panicking.Store(true)
	for _, call := range []func(){func() { mem.Apply(k, eimMedium()) }, func() { mem.Observe(k, final, true) }} {
		func() {
			defer func() { _ = recover() }()
			call()
		}()
	}
	panicking.Store(false)
	done := make(chan protocol.Traits, 1)
	go func() {
		mem.Observe(k, final, true)
		done <- mem.Apply(k, eimMedium())
	}()
	select {
	case got := <-done:
		if got.Hairpin != protocol.TriTrue {
			t.Fatalf("applied %+v", got)
		}
	case <-time.After(waitBound(t)):
		t.Fatal("a shard lock stayed held after the Clock panicked")
	}
}

// panicClock is the system clock, whose Now panics while panicking is set.
type panicClock struct {
	clock.System
	panicking *atomic.Bool
}

func (c panicClock) Now() time.Time {
	if c.panicking.Load() {
		panic("clock")
	}
	return time.Now()
}

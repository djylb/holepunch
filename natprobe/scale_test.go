package natprobe

import (
	"math"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/nat"
)

// The sandwich ring grows with the events queued, not with the bound: a
// session that queues a few events under a large bound holds a small ring,
// and the events keep their order across the growth and the wrap.
func TestSandwichQueueGrowsOnDemand(t *testing.T) {
	var q sandwichQueue
	for i := range 3 {
		if ok, _ := q.offer(nat.SandwichEvent{Round: uint8(i)}, 1<<20); !ok {
			t.Fatal("refused")
		}
	}
	if len(q.ring) > 8 {
		t.Fatalf("ring of %d slots for 3 events", len(q.ring))
	}
	var got []uint8
	q.attach(func(ev nat.SandwichEvent) { got = append(got, ev.Round) })
	q.sink = nil // queue again without delivery, across a wrapped head
	for i := range 20 {
		q.offer(nat.SandwichEvent{Round: uint8(10 + i)}, 1<<20)
	}
	q.attach(func(ev nat.SandwichEvent) { got = append(got, ev.Round) })
	if len(got) != 23 {
		t.Fatalf("delivered %d", len(got))
	}
	for i, r := range got {
		if want := uint8(i); i >= 3 {
			want = uint8(10 + i - 3)
			if r != want {
				t.Fatalf("event %d is round %d, want %d", i, r, want)
			}
		} else if r != want {
			t.Fatalf("event %d is round %d", i, r)
		}
	}
}

// A positive bound is exact even when it is not a power of two; a negative
// one is unbounded.
func TestSandwichQueueBound(t *testing.T) {
	for _, tc := range []struct{ capacity, offers, want int }{{5, 9, 5}, {1, 3, 1}, {-1, 3000, 3000}} {
		var q sandwichQueue
		n := 0
		for range tc.offers {
			if ok, _ := q.offer(nat.SandwichEvent{}, tc.capacity); ok {
				n++
			}
		}
		if n != tc.want || q.n != tc.want {
			t.Fatalf("capacity %d: queued %d (n %d), want %d", tc.capacity, n, q.n, tc.want)
		}
	}
}

// SlotsPerRole above the former hard cap is honoured.
func TestSlotsPerRoleConfigurable(t *testing.T) {
	var rs roleState
	rng := rand.New(rand.NewChaCha8([32]byte{}))
	src := netip.MustParseAddrPort("192.0.2.1:1000")
	for i := range 100 {
		if s := rs.upsert(uint8(i), 0, 0, src, 1, 0, 100, rng); s == nil {
			t.Fatalf("slot %d refused under a bound of 100", i)
		}
	}
	if s := rs.upsert(200, 0, 0, src, 1, 0, 100, rng); s != nil {
		t.Fatal("slot past the bound accepted")
	}
}

// The source limiter allocates nothing up front for its bound: a large
// table costs what a small one does until sources arrive.
func TestSourceLimiterLazy(t *testing.T) {
	small := testing.AllocsPerRun(5, func() { benchSink = newSourceLimiter(Rate{PerSec: 1, Burst: 1}, srcShards) })
	large := testing.AllocsPerRun(5, func() { benchSink = newSourceLimiter(Rate{PerSec: 1, Burst: 1}, 1<<24) })
	if large > small {
		t.Fatalf("construction allocates %v at size 16, %v at 1<<24", small, large)
	}
	l := newSourceLimiter(Rate{PerSec: 1, Burst: 1}, 1<<24)
	for i := range 1000 {
		l.allow(addrN(i), int64(time.Hour))
	}
	held := 0
	for i := range l.shards {
		held += cap(l.shards[i].nodes)
	}
	if held > 4*1000 {
		t.Fatalf("%d nodes held for 1000 sources", held)
	}
}

// SourceTableSize has no upper bound.
func TestSourceTableSizeUnbounded(t *testing.T) {
	cfg := ServerConfig{Registry: NewRegistry(RegistryConfig{}), Groups: loGroup(), SourceTableSize: math.MaxInt}
	if _, err := normalize(cfg); err != nil {
		t.Fatal(err)
	}
}

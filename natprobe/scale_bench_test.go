package natprobe

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
)

// benchSink keeps constructed values on the heap.
var benchSink any

// scaleSizes are the table sizes of the small and the large end.
var scaleSizes = []int{16, 1 << 20}

// addrN returns the n-th distinct IPv4 prefix.
func addrN(n int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
}

// Constructing a source limiter, and one packet of a known source in a
// table of n sources.
func BenchmarkSourceLimiter(b *testing.B) {
	for _, n := range scaleSizes {
		b.Run(fmt.Sprint("new/n=", n), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				benchSink = newSourceLimiter(Rate{PerSec: 1e9, Burst: 1e9}, n)
			}
		})
		b.Run(fmt.Sprint("allow/n=", n), func(b *testing.B) {
			l := newSourceLimiter(Rate{PerSec: 1e9, Burst: 1e9}, n)
			addrs := make([]netip.Addr, n)
			for i := range addrs {
				addrs[i] = addrN(i)
				l.allow(addrs[i], 0)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				l.allow(addrs[i%n], int64(i))
			}
		})
	}
}

// Constructing a traits memory, and one Observe+Apply in a memory of n NATs.
func BenchmarkTraitsMemoryScale(b *testing.B) {
	for _, n := range scaleSizes {
		b.Run(fmt.Sprint("new/n=", n), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				benchSink = NewTraitsMemory(TraitsMemoryConfig{MaxEntries: n})
			}
		})
		b.Run(fmt.Sprint("observe/n=", n), func(b *testing.B) {
			m := NewTraitsMemory(TraitsMemoryConfig{MaxEntries: n})
			keys := make([]TraitsKey, n)
			for i := range keys {
				keys[i] = TraitsKey{ClientKey: "c", Family: protocol.FamilyUDP4, PublicIP: addrN(i)}
				m.Observe(keys[i], eimMedium(), true)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				k := keys[i%n]
				m.Observe(k, eimMedium(), true)
				_ = m.Apply(k, protocol.Traits{})
			}
		})
	}
}

// A session's sandwich queue: the memory a burst of 8 events takes with a
// large configured bound, and the steady-state offer with a sink attached.
func BenchmarkSandwichQueue(b *testing.B) {
	for _, capacity := range []int{8, 1 << 16} {
		b.Run(fmt.Sprint("burst8/cap=", capacity), func(b *testing.B) {
			b.ReportAllocs()
			ev := nat.SandwichEvent{At: time.Unix(1, 0)}
			for range b.N {
				var q sandwichQueue
				for range 8 {
					q.offer(ev, capacity)
				}
			}
		})
	}
	b.Run("offer+deliver", func(b *testing.B) {
		var q sandwichQueue
		q.attach(func(nat.SandwichEvent) {})
		ev := nat.SandwichEvent{At: time.Unix(1, 0)}
		b.ReportAllocs()
		for range b.N {
			q.offer(ev, 8)
		}
	})
}

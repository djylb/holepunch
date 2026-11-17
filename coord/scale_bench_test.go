package coord

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// Constructing a strategy memory, and one Report in a memory of n keys.
func BenchmarkStrategyMemoryScale(b *testing.B) {
	for _, n := range []int{16, 1 << 20} {
		b.Run(fmt.Sprint("new/n=", n), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				_ = NewStrategyMemory(StrategyMemoryConfig{MaxEntries: n, Salt: []byte("s")})
			}
		})
		b.Run(fmt.Sprint("report/n=", n), func(b *testing.B) {
			m := NewStrategyMemory(StrategyMemoryConfig{MaxEntries: n, Salt: []byte("s")})
			keys := make([]StrategyKey, n)
			for i := range keys {
				binary.BigEndian.PutUint64(keys[i][:], uint64(i)*0x9E3779B97F4A7C15)
				m.Report(keys[i], 1, MemSuccess)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				m.Report(keys[i%n], 1, MemSuccess)
			}
		})
	}
}

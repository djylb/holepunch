package plan

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand/v2"
)

// substream derives an independent deterministic ChaCha8 stream from the
// 8-byte spray seed (udpwire.SpraySeed output) and a domain tag plus integer
// indices (each stage derives an independent sub-stream by (stage, target,
// i)). An expansion is thus a pure function of
// (spray seed, stage params): both peers that know the same seed reproduce the
// same sequence, and a different session (token/route), round, role or stage
// produces a different one.
//
// The 8-byte seed is stretched to the 32-byte ChaCha8 key with SHA-256 over
// seed || tag || indices. This is a key-stretch of an already-derived value,
// not a new protocol KDF; the KDFs live only in udpwire.
func substream(seed [8]byte, tag string, idx ...int) *rand.ChaCha8 {
	h := sha256.New()
	h.Write(seed[:])
	h.Write([]byte(tag))
	var buf [8]byte
	for _, v := range idx {
		binary.BigEndian.PutUint64(buf[:], uint64(int64(v)))
		h.Write(buf[:])
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return rand.NewChaCha8(key)
}

// uniformU16 returns a value uniform in [lo, hi] (inclusive) from r.
func uniformU16(r *rand.ChaCha8, lo, hi uint16) uint16 {
	if hi <= lo {
		return lo
	}
	span := uint32(hi) - uint32(lo) + 1
	return lo + uint16(r.Uint64()%uint64(span))
}

// unitFloat returns a value uniform in [0.5, 1.0] from r (the u_i of the Direct
// repeat-offset formula).
func unitFloat(r *rand.ChaCha8) float64 {
	frac := float64(r.Uint64()>>11) / float64(uint64(1)<<53) // 53-bit fraction in [0,1)
	return 0.5 + 0.5*frac
}

// shuffleU16 applies a Fisher-Yates permutation driven by r, in place.
func shuffleU16(r *rand.ChaCha8, s []uint16) {
	for i := len(s) - 1; i > 0; i-- {
		j := int(r.Uint64() % uint64(i+1))
		s[i], s[j] = s[j], s[i]
	}
}

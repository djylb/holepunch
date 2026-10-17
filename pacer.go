package holepunch

import (
	"crypto/sha256"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/udpwire"
)

// jitterLabel separates the runtime's jitter stream from the codec's pacer
// stream, which already draws b0 and packet lengths from PacerSeed: two
// consumers of one stream would move in lockstep and form a linkable pattern.
const jitterLabel = "holepunch/1 jitter"

// pacer is the session's deterministic jitter: the timing of initiated
// packets and keepalive probes and the ports of extra sockets. It is seeded
// per session and role, so two sessions never share a rhythm while a session
// replays identically from its keys. Safe for concurrent use.
type pacer struct {
	mu  sync.Mutex
	rng *rand.Rand
}

func newPacer(token [32]byte, route [udpwire.RouteSize]byte, role udpwire.Role) *pacer {
	ps := udpwire.PacerSeed(token, route, role)
	seed := sha256.Sum256(append([]byte(jitterLabel), ps[:]...))
	return &pacer{rng: rand.New(rand.NewChaCha8(seed))}
}

// spread returns d scaled by a factor drawn uniformly from [1-frac, 1+frac].
func (p *pacer) spread(d time.Duration, frac float64) time.Duration {
	p.mu.Lock()
	u := p.rng.Float64()
	p.mu.Unlock()
	return time.Duration(float64(d) * (1 - frac + 2*frac*u))
}

// portIn returns a port drawn uniformly from [lo, hi).
func (p *pacer) portIn(lo, hi int) uint16 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return uint16(lo + p.rng.IntN(hi-lo))
}

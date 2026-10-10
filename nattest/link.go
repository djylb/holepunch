package nattest

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// LinkConfig describes the impairments of a link. A link is bidirectional
// and every field applies to each direction on its own; the rate limiter
// keeps one token bucket per direction. The zero value is a perfect link with
// the default MTU.
type LinkConfig struct {
	// Loss is the probability that a packet is dropped.
	Loss float64
	// Reorder is the probability that a packet is held back by an extra
	// Delay+Jitter+1ms, so that later packets overtake it.
	Reorder float64
	// Duplicate is the probability that a packet is delivered twice; the copy
	// draws its own jitter.
	Duplicate float64

	// Delay is the one-way base delay.
	Delay time.Duration
	// Jitter adds a uniform offset in [-Jitter, +Jitter]; the total delay
	// never goes below zero.
	Jitter time.Duration

	// RatePPS limits each direction with a token bucket of burst
	// max(1, RatePPS/10); 0 means unlimited.
	RatePPS int
	// MTU is the IP MTU: packets whose UDP payload plus IP and UDP headers
	// exceed it are dropped, as with the DF bit set. 0 means 1500.
	MTU int
}

const (
	defaultMTU   = 1500
	ipv4UDPHeads = 20 + 8
	ipv6UDPHeads = 40 + 8
)

func (c LinkConfig) mtu() int {
	if c.MTU <= 0 {
		return defaultMTU
	}
	return c.MTU
}

// perfect reports whether the link only enforces its MTU, which lets packets
// skip the impairment state and its lock.
func (c LinkConfig) perfect() bool {
	return c.Loss <= 0 && c.Reorder <= 0 && c.Duplicate <= 0 && c.Delay <= 0 && c.Jitter <= 0 && c.RatePPS <= 0
}

// direction of a packet on a link.
const (
	dirUp   = 0 // towards the core
	dirDown = 1 // away from the core
)

// link applies a LinkConfig. Its drops are counted on the device it belongs
// to (a NAT's uplink or the core).
type link struct {
	cfg     atomic.Pointer[LinkConfig]
	drops   *dropCounters
	rng     *rand.Rand
	tokens  [2]float64
	last    [2]time.Duration
	mu      sync.Mutex // guards the random source and the token buckets
	perfect atomic.Bool
	primed  [2]bool
}

func newLink(cfg LinkConfig, drops *dropCounters, rng *rand.Rand) *link {
	l := &link{drops: drops, rng: rng}
	l.set(cfg)
	return l
}

func (l *link) set(cfg LinkConfig) {
	l.mu.Lock()
	l.primed = [2]bool{}
	l.mu.Unlock()
	l.cfg.Store(&cfg)
	l.perfect.Store(cfg.perfect())
}

// verdict is what a link does with one packet.
type verdict struct {
	delay    time.Duration
	dupDelay time.Duration
	dup      bool
	drop     dropReason
}

// pass applies the link to a packet with a UDP payload of size bytes.
func (l *link) pass(now time.Duration, size int, v6 bool, dir int) verdict {
	cfg := l.cfg.Load()
	heads := ipv4UDPHeads
	if v6 {
		heads = ipv6UDPHeads
	}
	if size+heads > cfg.mtu() {
		l.drops.add(dropMTU)
		return verdict{drop: dropMTU}
	}
	if l.perfect.Load() {
		return verdict{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if cfg.RatePPS > 0 && !l.take(cfg.RatePPS, now, dir) {
		l.drops.add(dropRate)
		return verdict{drop: dropRate}
	}
	if cfg.Loss > 0 && l.rng.Float64() < cfg.Loss {
		l.drops.add(dropLoss)
		return verdict{drop: dropLoss}
	}
	v := verdict{delay: l.sampleDelay(cfg)}
	if cfg.Reorder > 0 && l.rng.Float64() < cfg.Reorder {
		v.delay += cfg.Delay + cfg.Jitter + time.Millisecond
	}
	if cfg.Duplicate > 0 && l.rng.Float64() < cfg.Duplicate {
		v.dup = true
		v.dupDelay = l.sampleDelay(cfg)
	}
	return v
}

// take removes a token from the bucket of dir; l.mu is held.
func (l *link) take(rate int, now time.Duration, dir int) bool {
	burst := float64(max(1, rate/10))
	if !l.primed[dir] {
		l.primed[dir] = true
		l.tokens[dir] = burst
		l.last[dir] = now
	}
	l.tokens[dir] = min(burst, l.tokens[dir]+float64(now-l.last[dir])*float64(rate)/float64(time.Second))
	l.last[dir] = now
	if l.tokens[dir] < 1 {
		return false
	}
	l.tokens[dir]--
	return true
}

func (l *link) sampleDelay(cfg *LinkConfig) time.Duration {
	d := cfg.Delay
	if cfg.Jitter > 0 {
		d += time.Duration(l.rng.Int64N(int64(2*cfg.Jitter)+1)) - cfg.Jitter
	}
	return max(d, 0)
}

package nattest

import "github.com/djylb/holepunch/clock"

// Option configures [NewNetwork].
type Option func(*options)

type options struct {
	seed     int64
	coreHops int
	coreLink LinkConfig
	eventLog int
	clock    clock.Clock
}

const (
	defaultSeed     = 1
	defaultCoreHops = 8
	defaultEventLog = 10000
)

// WithSeed sets the seed from which every random source of the network is
// derived: one independent generator per NAT, link, host and pipe. The
// default seed is 1.
func WithSeed(seed int64) Option { return func(o *options) { o.seed = seed } }

// WithCoreHops sets how many routers the public core counts as when IP TTLs
// are decremented (default 8). A packet entering the core needs a TTL above
// this value to leave it. Negative values are ignored.
func WithCoreHops(hops int) Option {
	return func(o *options) {
		if hops >= 0 {
			o.coreHops = hops
		}
	}
}

// WithCoreLink sets the impairments applied once to every packet that crosses
// the public core.
func WithCoreLink(l LinkConfig) Option { return func(o *options) { o.coreLink = l } }

// WithEventLog sets how many recent packet events [Network.Dump] keeps
// (default 10000; 0 disables the log). Negative values are ignored.
func WithEventLog(n int) Option {
	return func(o *options) {
		if n >= 0 {
			o.eventLog = n
		}
	}
}

// WithClock replaces the real clock. With a manual clock — a *clock.Fake, or
// any clock that also has the Fake's AdvanceTo(time.Time) int, such as a
// wrapper embedding one — the network is fully event-driven and starts no
// goroutine: delayed packets, pipe data and deadlines move only while the
// test advances the clock, on the advancing goroutine, so a single-goroutine
// test is reproducible packet by packet. Any other clock drives the
// scheduler goroutine. A nil clock is ignored.
func WithClock(c clock.Clock) Option {
	return func(o *options) {
		if c != nil {
			o.clock = c
		}
	}
}

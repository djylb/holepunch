package holepunch

import "github.com/djylb/holepunch/internal/clock"

// Clock is the time source of a session (Options.Clock). Every timeout,
// deadline and rate limit of the runtime is measured with it, so a test can
// drive the whole session with a fake clock. It is defined once, in
// internal/clock, and aliased here so that an implementation needs no adapter.
// Now must carry a monotonic reading when durations are derived from it, as
// time.Now does.
type Clock = clock.Clock

// Timer is a single-shot timer created by a Clock. C returns nil for timers
// created by AfterFunc; Stop and Reset follow the Go 1.23 semantics of
// package time.
type Timer = clock.Timer

// Package clock is the single definition of the time source used by the
// holepunch client runtime and by coord.
//
// Clock and Timer are declared here once; the root package and coord export
// them as type aliases so that a user-supplied clock needs no adapter and the
// interfaces cannot drift apart.
//
// Two implementations are provided:
//
//   - System wraps package time. It is what the library uses when the caller
//     does not inject a clock.
//   - Fake is a manually driven clock for unit tests. Timers fire only while a
//     test advances the clock (Advance, AdvanceTo, AdvanceNext), in order of
//     deadline and then creation, so every timeout path can be walked through
//     deterministically in far less than its real duration.
//
// # Concurrency
//
// Both implementations are safe for concurrent use. Fake runs AfterFunc
// callbacks synchronously on the goroutine that advances the clock and never
// holds its lock while doing so, so callbacks may create, stop and reset
// timers and read Now. A callback that panics is recovered and reported to the
// test as a failure through Fake's Reporter; the panic does not escape and the
// clock stays usable. For deterministic ordering a test should advance the
// clock from a single goroutine.
//
// Channel timers follow the Go 1.23 semantics of package time: Stop and Reset
// return true when the expiry has not been received yet and discard it, so no
// stale value is ever received after Stop or Reset returns.
//
// AfterFunc(d, nil) is a no-op timer in both implementations: it is scheduled,
// can be stopped and reset, and does nothing when it fires.
//
// # Resource ownership
//
// A Timer belongs to whoever created it. System timers are runtime timers
// with no goroutine of their own; Fake timers live in the Fake until they
// fire or are stopped. Neither implementation starts goroutines.
package clock

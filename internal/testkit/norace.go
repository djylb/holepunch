//go:build !race

package testkit

// RaceEnabled reports a build with the race detector, which slows every
// goroutine down: tests relax or skip their timing and allocation bounds.
const RaceEnabled = false

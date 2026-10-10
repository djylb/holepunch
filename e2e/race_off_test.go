//go:build !race

package e2e

// raceEnabled reports whether the race detector is on: time bounds are
// scaled.
const raceEnabled = false

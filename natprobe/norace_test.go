//go:build !race

package natprobe

// raceEnabled reports a -race build, whose timing assertions are relaxed.
const raceEnabled = false

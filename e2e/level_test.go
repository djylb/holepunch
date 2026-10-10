package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"
)

// level is the depth of a run: the pr level runs the must cells,
// the nightly level everything. HOLEPUNCH_E2E_LEVEL selects it; the default
// is pr, or nightly in a build with the e2e_nightly tag.
type level int

const (
	levelPR level = iota
	levelNightly
)

func (l level) String() string {
	if l == levelNightly {
		return "nightly"
	}
	return "pr"
}

// Runs per cell at each level (pr 3/3, nightly 20/20).
const (
	prRuns      = 3
	nightlyRuns = 20
)

// maxParallelCells bounds the cells running at once: more CPU contention
// distorts the time KPIs.
const maxParallelCells = 8

// raceFactor scales every time bound under the race detector.
const raceFactor = 3

// Environment variables of the suite.
const (
	envLevel = "HOLEPUNCH_E2E_LEVEL" // pr | nightly
	envRuns  = "HOLEPUNCH_E2E_RUNS"  // runs per cell, overriding the level's
	envCells = "HOLEPUNCH_E2E_CELLS" // regular expression over cell names
	envOut   = "HOLEPUNCH_E2E_OUT"   // output directory: kpi.json, reports, failure dumps
	envSeed  = "HOLEPUNCH_E2E_SEED"  // base seed (default 1)
)

// suiteConfig is the configuration of one test binary run, read from the
// build tags and the environment.
type suiteConfig struct {
	level level
	runs  int // runs per matrix cell
	cells *regexp.Regexp
	out   string // "" = no KPI output, failure dumps in the test's temporary directory
	seed  int64
}

// suite returns the configuration; it is read once.
var suite = sync.OnceValue(func() suiteConfig {
	c := suiteConfig{level: defaultLevel, seed: 1}
	switch os.Getenv(envLevel) {
	case "nightly":
		c.level = levelNightly
	case "pr":
		c.level = levelPR
	}
	c.runs = prRuns
	if c.level == levelNightly {
		c.runs = nightlyRuns
	}
	if v, err := strconv.Atoi(os.Getenv(envRuns)); err == nil && v > 0 {
		c.runs = v
	}
	if v := os.Getenv(envCells); v != "" {
		c.cells = regexp.MustCompile(v)
	}
	if v, err := strconv.ParseInt(os.Getenv(envSeed), 10, 64); err == nil {
		c.seed = v
	}
	c.out = os.Getenv(envOut)
	return c
})

// failureDir returns the directory of a test's failure dumps: below
// HOLEPUNCH_E2E_OUT when it is set, otherwise the test's temporary directory
// (removed with the test; the path is printed with each dump). Dumps never go
// into the source tree.
func failureDir(t testing.TB) string {
	if out := suite().out; out != "" {
		return filepath.Join(out, "failures")
	}
	return t.TempDir()
}

// selected reports whether a cell name passes HOLEPUNCH_E2E_CELLS.
func (c suiteConfig) selected(name string) bool {
	return c.cells == nil || c.cells.MatchString(name)
}

// scaled multiplies a time bound for the race detector.
func scaled(d time.Duration) time.Duration {
	if raceEnabled {
		return d * raceFactor
	}
	return d
}

// cellSlots limits the cells running at once.
var cellSlots = make(chan struct{}, maxParallelCells)

// acquireSlot blocks until a cell may run and returns its release.
func acquireSlot() func() {
	cellSlots <- struct{}{}
	return func() { <-cellSlots }
}

// writeOut writes a file below the output directory, creating directories.
func writeOut(dir, name string, data []byte) error {
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("e2e: output directory: %w", err)
	}
	return os.WriteFile(p, data, 0o644)
}

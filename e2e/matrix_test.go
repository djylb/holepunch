package e2e

import (
	"fmt"
	"hash/fnv"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/nattest"
)

// cellSeed derives a run's seed from the suite seed, the cell and the run.
func cellSeed(name string, run int) int64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return suite().seed*1_000_003 + int64(h.Sum32())*1000 + int64(run)
}

// runOnce runs a cell once in a fresh world and returns the measured run
// with its violations; it reports nothing to t itself. dumps writes the
// failure dump of a violating or unsuccessful run.
func runOnce(t testing.TB, c *cell, seed int64, abl ablation.Set, dumps bool) (*cellRun, []string) {
	wc := worldConfig{seed: seed}
	if c.world != nil {
		c.world(&wc)
	}
	w := newWorld(t, wc)
	sides := c.build(w)
	for _, s := range sides {
		s.net.record()
	}
	spec := sessionSpec{ablation: abl}
	if c.session != nil {
		c.session(&spec, w, sides)
	}
	cr := &cellRun{c: c, seed: seed, w: w, sides: sides}
	r, err := newRun(w, sides, spec)
	if err != nil {
		v := w.abandon(err)
		cr.m.Violations = v
		return cr, v
	}
	cr.r = r
	r.execute()
	cr.measure()
	v := cr.violations()
	v = append(v, cr.checkResources()...)
	if dumps && (len(v) > 0 || c.class != classFail && !cr.m.OK) {
		p, err := cr.dump(t, v, abl.String())
		switch {
		case err != nil:
			v = append(v, fmt.Sprintf("failure dump: %v", err))
		case len(v) == 0:
			// a dump of an unsuccessful run is evidence, not a violation
			cr.dumped = p
		default:
			v = append(v, "dump: "+p)
		}
	}
	if err := w.close(); err != nil {
		v = append(v, fmt.Sprintf("world close: %v", err))
	}
	cr.m.Violations = v
	return cr, v
}

// checkResources runs the resource assertions of a finished run: a failed
// client leaves no socket open, a successful one exactly its winner, whose
// socket then works without deadline and is never touched by the library;
// after Session.Close nothing is open and every port mapping was released.
func (cr *cellRun) checkResources() []string {
	var v []string
	r := cr.r
	want := map[*nattest.Host]int{}
	for i := range 2 {
		if r.out[i].ok() && !r.crashed[i] {
			want[cr.sides[i].host] += handedSockets(r.out[i].sess)
		}
	}
	if r.crashed[0] || r.crashed[1] {
		r.skipWinnerCheck = true
	}
	for i := range 2 {
		h := cr.sides[i].host
		if n := h.OpenSockets(); n != want[h] {
			v = append(v, fmt.Sprintf("%s: %d sockets open after Punch returned, want %d", roles[i], n, want[h]))
		}
	}
	if r.out[0].ok() && r.out[1].ok() && !r.crashed[0] && !r.crashed[1] {
		if err := r.checkHandover(); err != nil {
			v = append(v, err.Error())
		}
	}
	if err := r.closeSessions(); err != nil {
		v = append(v, err.Error())
	}
	for i := range 2 {
		if n := cr.sides[i].host.OpenSockets(); n != 0 {
			v = append(v, fmt.Sprintf("%s: %d sockets open after Session.Close", roles[i], n))
		}
		if m := cr.sides[i].mapper; m != nil {
			if maps, rel := m.maps.Load(), m.releases.Load(); maps != rel {
				v = append(v, fmt.Sprintf("%s: %d port mappings, %d released", roles[i], maps, rel))
			}
		}
	}
	return v
}

// evaluate applies the cell-level gates over the runs: the pass
// rate, the p95 time on success, the first successful round, the birthday
// model test and the first-send skew; it returns the gate's description and
// the problems found.
func evaluate(c *cell, k cellKPI) (string, []string) {
	var problems []string
	gate := c.class.String()
	if c.reportOnly {
		// Rate, time and round are reported in the KPI file only; the
		// per-run invariants were checked run by run.
		return gate + " report-only", nil
	}
	if rate := c.passRate(); rate >= 0 && c.class != classFail {
		gate += fmt.Sprintf(" pass≥%.0f%%", rate*100)
		if k.SuccessRate+1e-9 < rate {
			problems = append(problems, fmt.Sprintf("success %d/%d (%.0f%%), gate %.0f%%", k.Successes, k.Runs, k.SuccessRate*100, rate*100))
		}
	}
	if b := c.confirmBound(); b > 0 && k.ConfirmMs.N > 0 {
		gate += fmt.Sprintf(" p95≤%v", scaled(b))
		if p95 := time.Duration(k.ConfirmMs.P95 * float64(time.Millisecond)); p95 > scaled(b) {
			problems = append(problems, fmt.Sprintf("p95 confirm %v > %v", p95, scaled(b)))
		}
	}
	if c.maxMedianRound > 0 && k.ConfirmRound.N > 0 {
		gate += fmt.Sprintf(" median_round≤%d", c.maxMedianRound)
		if k.ConfirmRound.P50 > float64(c.maxMedianRound) {
			problems = append(problems, fmt.Sprintf("median first successful round %.0f > %d", k.ConfirmRound.P50, c.maxMedianRound))
		}
	}
	if c.base == classModel {
		f := c.modelFactor
		if f == 0 {
			f = 0.8
		}
		p0 := f * k.PModel
		gate += fmt.Sprintf(" binom(%.1f·P=%.3f)", f, p0)
		if p := binomialCDF(k.Successes, k.Runs, p0); p < modelAlpha {
			problems = append(problems, fmt.Sprintf("success %d/%d significantly below %.1f·P_model = %.3f (p = %.4f)", k.Successes, k.Runs, f, p0, p))
		}
	}
	if c.skewP90 > 0 && k.FirstSendSkewMs.N > 0 {
		gate += fmt.Sprintf(" skew_p90≤%v", scaled(c.skewP90))
		if p90 := time.Duration(k.FirstSendSkewMs.P90 * float64(time.Millisecond)); p90 > scaled(c.skewP90) {
			problems = append(problems, fmt.Sprintf("first-send skew p90 %v > %v", p90, scaled(c.skewP90)))
		}
	}
	return gate, problems
}

// modelAlpha is the significance of the model test (one-sided binomial).
const modelAlpha = 0.01

// runCell runs a cell the given number of times with every mechanism on,
// evaluates it, and writes its kpi.json below kpi/<kpiDir> of the output
// directory.
func runCell(t *testing.T, c *cell, runs int, kpiDir string) cellKPI {
	release := acquireSlot()
	defer release()
	start := time.Now()
	var crs []*cellRun
	var problems []string
	full := ablation.Set{}
	for i := range runs {
		seed := cellSeed(c.name, i)
		cr, v := runOnce(t, c, seed, full, true)
		crs = append(crs, cr)
		for _, s := range v {
			problems = append(problems, fmt.Sprintf("seed %d: %s", seed, s))
		}
		if cr.dumped != "" {
			t.Logf("seed %d: unsuccessful (%s), dump: %s", seed, cr.m.Code, cr.dumped)
		}
	}
	k := kpiOf(c, full.String(), crs, time.Since(start))
	gate, more := evaluate(c, k)
	k.Gate, k.Problems = gate, append(problems, more...)
	k.Pass = len(k.Problems) == 0
	if dir := suite().out; dir != "" {
		if err := writeKPI(dir+"/kpi/"+kpiDir, k); err != nil {
			t.Errorf("kpi: %v", err)
		}
	}
	return k
}

// matrixCells returns the cells of the configured level.
func matrixCells() []*cell {
	var out []*cell
	for _, c := range cells() {
		if suite().level == levelPR && c.class != classMust {
			continue
		}
		if !suite().selected(c.name) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// TestMatrix runs the e2e matrix: at the pr level the must cells
// three times each, at the nightly level all cells twenty times.
func TestMatrix(t *testing.T) {
	cs := matrixCells()
	if len(cs) == 0 {
		t.Skip("no cell selected")
	}
	runs := suite().runs
	t.Run("cells", func(t *testing.T) {
		for _, c := range cs {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				k := runCell(t, c, runs, suite().level.String())
				t.Logf("%s %s: %d/%d ok, confirm p50 %.0f ms p95 %.0f ms, packets max %.0f, rounds max %.0f [%s]",
					c.name, c.class, k.Successes, k.Runs, k.ConfirmMs.P50, k.ConfirmMs.P95, k.PacketsPerSide.Max, k.Rounds.Max, k.Gate)
				for _, p := range k.Problems {
					t.Error(p)
				}
			})
		}
	})
	goroutines.VerifyNone(t)
}

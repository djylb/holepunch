package e2e

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// The default-timeout comparison. The suite shortens the protocol timeouts —
// handshake 6 s, two rounds, BindTimeout 3 s — so that a cell takes seconds.
// That hides whatever only exists with the library's defaults (handshake 20 s,
// five rounds plus the rescue round, BindTimeout 15 s): every rung from the
// third on (seq_x_seq_r3, seq_x_rnd_r3, the third birthday round of pdf_x_rnd),
// the verdicts that must end a session before its rounds run out, and round
// windows that the remaining handshake no longer cuts short.
// TestDefaultTimeouts runs representative cells under both: the defaults gated
// by the cell's class exactly as in the matrix, the shortened timeouts next to
// them for the comparison only (TestMatrix gates those).

// Configurations of the comparison; a run is named cell@configuration.
const (
	timeoutsDefault = "default-timeouts"
	timeoutsE2E     = "e2e-timeouts"
)

// timeoutConfigs are the configurations in report order.
func timeoutConfigs() []string { return []string{timeoutsDefault, timeoutsE2E} }

// timeoutCell is a representative cell of the comparison and what the
// default timeouts reach in it that the shortened ones do not.
type timeoutCell struct {
	name string
	why  string
}

// timeoutCells returns the twelve representative cells; SEQ×SEQ, its noisy
// variant and SEQ×RND need the rounds past the second, the last two show
// the no-contact escalation, which needs a third round.
func timeoutCells() []timeoutCell {
	return []timeoutCell{
		{"v4/PRC-PRC", "an easy pair: only the deadlines differ"},
		{"v4/PRC-SYMSEQ", "pdf_x_seq past its second rung"},
		{"v4/SYMSEQ-SYMSEQ", "seq_x_seq_r3 and the rounds after it"},
		{"noise/SYMSEQ~5-SYMSEQ~5", "seq_x_seq under port noise, rounds 3–5"},
		{"v4/SYMSEQ-SYMRND", "seq_x_rnd: the verdict after the two cheap rounds, not the round limit"},
		{"v4/PRC-SYMRND", "the third birthday round of pdf_x_rnd (P_model ≈ 22%)"},
		{"impair/SYMSEQ-SYMSEQ", "loss and jitter over five rounds instead of two"},
		{"slowctl/PRC-SYMSEQ", "slow control links: the go delay D against the remaining handshake"},
		{"rebind/PRC-FC", "a mapping change recovered in a later round"},
		{"neg/symrnd-low-confidence", "the verdict, not the round limit, ends the ladder after two rounds"},
		{"pathdep/PRCSPLIT-PRCSPLIT", "path-dependent mapping: two easy rounds without contact, then fresh sockets"},
		{"multi/ADMRND-PRC", "an ADM side taken for EIM: after two rounds without contact a birthday instead of the easy rungs"},
	}
}

// timeoutVariant returns a copy of c under one configuration of the
// comparison, named c.name@config so that its seeds, kpi.json and failure
// dumps are its own. With the default timeouts the cell's own world
// configuration runs first and its timeouts are then replaced.
func timeoutVariant(c *cell, config string) *cell {
	v := *c
	v.name = c.name + "@" + config
	if config == timeoutsDefault {
		own := c.world
		v.world = func(wc *worldConfig) {
			if own != nil {
				own(wc)
			}
			wc.defaultTimeouts = true
		}
	}
	return &v
}

// TestDefaultTimeouts runs the default-timeout comparison at
// the nightly level: each representative cell with the library's default
// timeouts, gated by its class as in TestMatrix, and with the suite's
// shortened ones, reported next to it. The comparison goes to
// timeouts_report.md, the kpi.json files to kpi/timeouts.
func TestDefaultTimeouts(t *testing.T) {
	if suite().level != levelNightly {
		t.Skip("the default-timeout comparison runs at the nightly level")
	}
	byName := map[string]*cell{}
	for _, c := range cells() {
		byName[c.name] = c
	}
	var mu sync.Mutex
	got := map[string]cellKPI{}
	runs := suite().runs
	t.Run("cells", func(t *testing.T) {
		for _, tc := range timeoutCells() {
			base := byName[tc.name]
			if base == nil {
				t.Errorf("no matrix cell %s", tc.name)
				continue
			}
			for _, config := range timeoutConfigs() {
				c := timeoutVariant(base, config)
				if !suite().selected(c.name) {
					continue
				}
				t.Run(c.name, func(t *testing.T) {
					t.Parallel()
					k := runCell(t, c, runs, "timeouts")
					mu.Lock()
					got[c.name] = k
					mu.Unlock()
					t.Logf("%s %s: %d/%d ok, first successful round p50 %.0f, rounds max %.0f, confirm p95 %.0f ms [%s]",
						c.name, c.class, k.Successes, k.Runs, k.ConfirmRound.P50, k.Rounds.Max, k.ConfirmMs.P95, k.Gate)
					for _, p := range k.Problems {
						if config == timeoutsDefault {
							t.Error(p)
						} else {
							t.Logf("reported only, TestMatrix gates the e2e timeouts: %s", p)
						}
					}
				})
			}
		}
	})
	report := timeoutsReport(got, runs)
	if dir := suite().out; dir != "" {
		if err := writeOut(dir, "timeouts_report.md", []byte(report)); err != nil {
			t.Errorf("timeouts_report.md: %v", err)
		}
	} else {
		t.Log(report)
	}
	goleak.VerifyNone(t)
}

// maxReportedProblems bounds the problems the report lists per run set.
const maxReportedProblems = 5

// timeoutsReport renders timeouts_report.md: per representative cell the
// two configurations side by side, then the problems of the gated ones.
func timeoutsReport(got map[string]cellKPI, runs int) string {
	var b strings.Builder
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(&b, format, args...) }
	p("# Default-timeout comparison\n\n")
	p("Generated %s, %d runs per (cell, configuration), level %s.\n\n", time.Now().Format(time.RFC3339), runs, suite().level)
	p("- **%s**: the library's defaults — probe 2 s, handshake 20 s, transport 10 s, handover 2 s, BindTimeout 15 s, max_rounds 5 — gated by the cell's class as in the matrix.\n", timeoutsDefault)
	p("- **%s**: the suite's shortened timeouts — probe 1.5 s, handshake 6 s, transport 2 s, handover 1 s, BindTimeout 3 s, max_rounds 2 — reported only; TestMatrix gates them.\n\n", timeoutsE2E)
	p("| cell | what the defaults reach | timeouts | success | Δ vs e2e (pts) | first round | successful round p50/max | rounds p50/max | confirm p50/p95 ms | packets/side p50/max | failures | verdict |\n")
	p("|---|---|---|---:|---:|---:|---|---|---|---|---|---|\n")
	for _, tc := range timeoutCells() {
		e2e, haveE2E := got[tc.name+"@"+timeoutsE2E]
		for _, config := range timeoutConfigs() {
			k, ok := got[tc.name+"@"+config]
			if !ok {
				continue
			}
			delta := "—"
			if config == timeoutsDefault && haveE2E {
				delta = fmt.Sprintf("%+.0f", 100*(k.SuccessRate-e2e.SuccessRate))
			}
			first := 0
			for _, m := range k.RunsDetail {
				if m.OK && m.ConfirmRound == 1 {
					first++
				}
			}
			verdict := "PASS"
			switch {
			case !k.Pass && config == timeoutsDefault:
				verdict = "FAIL"
			case !k.Pass:
				verdict = "misses its gate (reported)"
			}
			p("| %s | %s | %s | %d/%d | %s | %d | %s | %s | %s | %s | %s | %s |\n", tc.name, tc.why, config, k.Successes, k.Runs, delta, first,
				pair50Max(k.ConfirmRound), pair50Max(k.Rounds), fmt.Sprintf("%.0f/%.0f", k.ConfirmMs.P50, k.ConfirmMs.P95),
				pair50Max(k.PacketsPerSide), histogram(k.FailureCodes), verdict)
		}
	}
	p("\nA cell whose gated configuration fails lists its first problems below; every problem is in the test log and in the cell's kpi.json.\n")
	for _, tc := range timeoutCells() {
		k, ok := got[tc.name+"@"+timeoutsDefault]
		if !ok || k.Pass {
			continue
		}
		p("\n### %s@%s — gate %s\n\n", tc.name, timeoutsDefault, k.Gate)
		for i, prob := range k.Problems {
			if i == maxReportedProblems {
				p("- … %d more\n", len(k.Problems)-i)
				break
			}
			p("- %s\n", prob)
		}
	}
	return b.String()
}

// pair50Max renders the median and the maximum of a sample, "—" when it is
// empty.
func pair50Max(q quantiles) string {
	if q.N == 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f/%.0f", q.P50, q.Max)
}

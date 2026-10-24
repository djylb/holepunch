package e2e

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// The eventual direct rate after background escalation, written to
// escalation_report.md and kpi/escalation: per hard IPv4 pair, sequences on one
// world — one coordinator, so one strategy memory —
//
//  1. an Interactive session, as the matrix runs it;
//  2. when it failed and the clients' Error.Advice is background_viable,
//     a Background session (the caller now relays and punches slowly);
//  3. when that one connected, another Interactive session, whose summary
//     must say background_only: the memory learned that only the slow
//     birthday connects the pair.
//
// The eventual direct rate is (Interactive successes + Background successes
// after an escalation) / sequences. It is a KPI next to the ablation's
// combination gate, not part of it,
// and gates nothing but the invariants every run asserts and the advice
// itself: a pair the advice sends to the relay must be one no mode connects.

// envEscalationRuns overrides the sequences per pair.
const envEscalationRuns = "HOLEPUNCH_E2E_ESCALATION_RUNS"

// escalationPairs are the IPv4 pairs whose Interactive ladder may fail:
// PDF × RND (background_viable) and SEQ × RND (relay_only).
func escalationPairs() [][2]profile {
	return [][2]profile{
		{v4Profile("PRC"), v4Profile("SYMRND")}, {v4Profile("SYMRND"), v4Profile("PRC")},
		{v4Profile("PUBFW"), v4Profile("SYMRND")}, {v4Profile("SYMRND"), v4Profile("PUBFW")},
		{v4Profile("SYMSEQ"), v4Profile("SYMRND")}, {v4Profile("SYMRND"), v4Profile("SYMSEQ")},
	}
}

// escalationStat sums the sequences of one pair.
type escalationStat struct {
	Cell               string         `json:"cell"`
	Group              string         `json:"group"`
	Class              string         `json:"class"`
	Ablation           string         `json:"ablation"`
	Runs               int            `json:"runs"`
	Successes          int            `json:"successes"` // eventually direct
	SuccessRate        float64        `json:"success_rate"`
	InteractiveOK      int            `json:"interactive_successes"`
	InteractiveRate    float64        `json:"interactive_rate"`
	Escalated          int            `json:"escalated"`
	BackgroundOK       int            `json:"background_successes"`
	EventualDirectRate float64        `json:"eventual_direct_rate"`
	Advice             map[string]int `json:"advice"`          // the Interactive failures' advice
	BackgroundOnly     [2]int         `json:"background_only"` // third sessions: [run, summary said background_only]
	BackgroundMs       quantiles      `json:"background_confirm_ms"`
	Pass               bool           `json:"pass"`
	Problems           []string       `json:"problems,omitempty"`
	Elapsed            string         `json:"elapsed"`
}

// TestBackgroundEscalation runs the sequences at the nightly level (or with
// HOLEPUNCH_E2E_ESCALATION_RUNS set). Selection by HOLEPUNCH_E2E_CELLS uses
// the names escalation/<v4 cell>.
func TestBackgroundEscalation(t *testing.T) {
	runs := 0
	if suite().level == levelNightly {
		runs = nightlyRuns
	}
	v, err := envCount(envEscalationRuns)
	if err != nil {
		t.Fatal(err)
	}
	if v > 0 {
		runs = v
	}
	if runs == 0 {
		t.Skip("the escalation runs at the nightly level or with " + envEscalationRuns)
	}
	var mu sync.Mutex
	var stats []escalationStat
	t.Run("pairs", func(t *testing.T) {
		for _, p := range escalationPairs() {
			name := "escalation/v4/" + p[0].name + "-" + p[1].name
			if !suite().selected(name) {
				continue
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				st := escalate(t, name, p, runs)
				mu.Lock()
				stats = append(stats, st)
				mu.Unlock()
				for _, pr := range st.Problems {
					t.Error(pr)
				}
			})
		}
	})
	slices.SortFunc(stats, func(a, b escalationStat) int { return strings.Compare(a.Cell, b.Cell) })
	report := escalationReport(stats, runs)
	if dir := suite().out; dir != "" {
		if err := writeOut(dir, "escalation_report.md", []byte(report)); err != nil {
			t.Errorf("escalation_report.md: %v", err)
		}
	} else {
		t.Log(report)
	}
	goroutines.VerifyNone(t)
}

// escalate runs the sequences of one pair.
func escalate(t *testing.T, name string, p [2]profile, runs int) escalationStat {
	release := acquireSlot()
	defer release()
	start := time.Now()
	st := escalationStat{Cell: name, Group: "escalation", Class: v4Class(p[0].name, p[1].name).String(), Ablation: "escalation",
		Runs: runs, Advice: map[string]int{}}
	var bgMs []float64
	problem := func(format string, args ...any) { st.Problems = append(st.Problems, fmt.Sprintf(format, args...)) }
	for k := range runs {
		w := newWorld(t, worldConfig{seed: cellSeed(name, k)})
		sides := [2]*side{w.behind([]nattest.NATConfig{p[0].cfg()}), w.behind([]nattest.NATConfig{p[1].cfg()})}
		session := func(bg bool) (*run, bool) {
			r, err := newRun(w, sides, sessionSpec{background: bg})
			if err != nil {
				problem("sequence %d: %v", k, err)
				return nil, false
			}
			r.execute()
			ok := r.out[0].ok() && r.out[1].ok()
			if err := r.closeSessions(); err != nil {
				problem("sequence %d: %v", k, err)
			}
			return r, ok
		}
		r, ok := session(false)
		switch {
		case r == nil:
		case ok:
			st.InteractiveOK++
		default:
			advice := escalationAdvice(r)
			st.Advice[string(advice)]++
			if want := wantAdvice(p); advice != want {
				problem("sequence %d: advice %q, want %q", k, advice, want)
			}
			if advice != protocol.AdviceBackgroundViable {
				break
			}
			st.Escalated++
			rb, okb := session(true)
			if rb == nil || !okb {
				break
			}
			st.BackgroundOK++
			bgMs = append(bgMs, ms(max(rb.out[0].dur(), rb.out[1].dur())))
			// The memory saw the slow birthday connect after the Interactive
			// ladder failed: the next summary says so.
			if r3, _ := session(false); r3 != nil {
				st.BackgroundOnly[0]++
				if s := view(r3.taps[0]).summary; s != nil && s.Plan.BackgroundOnly {
					st.BackgroundOnly[1]++
				}
			}
		}
		if err := w.close(); err != nil {
			problem("sequence %d: world close: %v", k, err)
		}
	}
	st.Successes = st.InteractiveOK + st.BackgroundOK
	if runs > 0 {
		st.SuccessRate = float64(st.Successes) / float64(runs)
		st.InteractiveRate = float64(st.InteractiveOK) / float64(runs)
	}
	st.EventualDirectRate = st.SuccessRate
	st.BackgroundMs = quant(bgMs)
	if st.BackgroundOnly[0] > 0 && st.BackgroundOnly[1] == 0 {
		problem("the strategy memory never surfaced background_only (%d chances)", st.BackgroundOnly[0])
	}
	st.Pass = len(st.Problems) == 0
	st.Elapsed = time.Since(start).Round(time.Millisecond).String()
	if dir := suite().out; dir != "" {
		if err := writeEscalationKPI(dir+"/kpi/escalation", st); err != nil {
			t.Errorf("kpi: %v", err)
		}
	}
	return st
}

// wantAdvice is the advice of a failed Interactive session of a pair:
// background_viable for PDF × RND, where the slow birthday connects;
// relay_only for SEQ(APDF) × RND, which natprobe measures.
func wantAdvice(p [2]profile) protocol.Advice {
	if p[0].combo == "PDF" || p[1].combo == "PDF" {
		return protocol.AdviceBackgroundViable
	}
	return protocol.AdviceRelayOnly
}

// escalationAdvice is the advice of a failed session: the clients', which
// both read it from their summaries; the initiator's when they differ.
func escalationAdvice(r *run) protocol.Advice {
	for i := range 2 {
		if e := r.out[i].herr; e != nil && e.Advice != "" {
			return e.Advice
		}
	}
	return ""
}

func writeEscalationKPI(dir string, st escalationStat) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	name := strings.NewReplacer("/", "__").Replace(st.Cell)
	return writeOut(dir, name+".kpi.json", b)
}

// escalationReport renders escalation_report.md.
func escalationReport(stats []escalationStat, runs int) string {
	var b strings.Builder
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(&b, format, args...) }
	p("# Eventual direct rate after background escalation\n\n")
	p("Generated %s, %d sequences per pair, level %s. A sequence is an Interactive session; on a failure whose advice is background_viable, a Background session on the same coordinator; after a Background success, a third (Interactive) session whose summary must carry background_only. The eventual direct rate is not part of the ablation's combination gate.\n\n",
		time.Now().Format(time.RFC3339), runs, suite().level)
	p("| pair | class | Interactive | advice of the failures | escalated | Background success | eventual direct rate | background_only surfaced | Background confirm p50/p95 ms |\n|---|---|---:|---|---:|---:|---:|---:|---|\n")
	for _, s := range stats {
		p("| %s | %s | %d/%d (%.0f%%) | %s | %d | %d/%d | **%.0f%%** | %d/%d | %.0f/%.0f |\n", strings.TrimPrefix(s.Cell, "escalation/"), s.Class,
			s.InteractiveOK, s.Runs, 100*s.InteractiveRate, histogram(s.Advice), s.Escalated, s.BackgroundOK, s.Escalated,
			100*s.EventualDirectRate, s.BackgroundOnly[1], s.BackgroundOnly[0], s.BackgroundMs.P50, s.BackgroundMs.P95)
	}
	return b.String()
}

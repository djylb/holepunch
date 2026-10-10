package e2e

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// The ablation, written to ablation_report.md:
//
//   - the combination gate over the 15 combinations of profile classes, each
//     the equal-weight mean of its ordered IPv4 cells, the 15 again weighted
//     equally: full ≥ Plain + 13 points. The equal-weight mean of
//     the 49 ordered cells is reported only;
//   - the "never worse than plain punching" gate: on every one of
//     the 49 ordered IPv4 cells and every deliberately misclassified cell,
//     full's successes are at least Plain's less two in twenty runs;
//   - the class gates beside it, on the same full runs: every
//     PDF×SEQ and SEQ×SEQ cell ≥ 90% (18/20 at the nightly level), and every
//     model cell — PDF×RND, SEQ×RND, RND×RND — not significantly below its
//     birthday model (the matrix's binomial test against 0.8·P_model);
//   - the per-mechanism table over representative cells. Where
//     the ablated mechanism only acts once round 1 has failed, the cell
//     makes round 1 fail: the ablation/ cells silence the ladder's first
//     rung or lose packets in one direction;
//   - the deliberately misclassified cells under the punch-time
//     corrections switched off one by one and together;
//   - the threshold table. A threshold that is not marked report
//     only fails the test when it is missed, as the combination gate does.

// combinationGate is the gain of full over Plain, in points, that the
// combination gate requires (SEQ×RND is structurally about 0, its ladder
// ending after the two cheap rounds, so the reachable gain is about +14).
const combinationGate = 13.0

// classGateRate is the class gate of the PDF×SEQ and SEQ×SEQ cells, 18 of
// 20 at the nightly level.
const classGateRate = 0.9

// plainSlack is how many fewer successes than Plain a cell's full runs may
// have: two in twenty, in proportion at other run counts, at least
// one.
func plainSlack(runs int) int { return max((runs+9)/10, 1) }

// envAblationRuns overrides the runs per (cell, configuration) of the ablation.
const envAblationRuns = "HOLEPUNCH_E2E_ABLATION_RUNS"

// noCorrection switches off every correction made while punching: the peer_seen
// relay with its third-observer traits and the peer_targets pushes
// (NoAssistRelay), the sandwich (NoSandwich), and the later rounds with the
// rescue round (NoRounds).
func noCorrection() ablation.Set {
	return ablation.Set{NoAssistRelay: true, NoSandwich: true, NoRounds: true}
}

// correctionConfigs are the configurations of the misclassified cells:
// the corrections off one by one and together, and Plain for the
// per-cell gate against plain punching.
func correctionConfigs() []ablation.Set {
	return []ablation.Set{{}, {NoSandwich: true}, {NoAssistRelay: true}, {NoRounds: true}, noCorrection(), ablation.Plain()}
}

// silentFirstRung is a representative cell whose first ladder rung cannot
// connect (silenceRung): round 1 always fails, round 2 runs the next rung.
func silentFirstRung(a, b profile) *cell {
	return &cell{name: "ablation/" + a.name + "-" + b.name + "+silent-rung1", group: "ablation", class: v4Class(a.name, b.name), reportOnly: true,
		hard: [2]bool{a.hard, b.hard}, build: single(a.cfg, b.cfg),
		session: func(s *sessionSpec, _ *world, sides [2]*side) {
			s.prepare = func(r *run) { silenceRung(r, sides, firstRung) }
		}}
}

// oneWay is a representative cell that loses share of the packets from
// the initiator to the responder (one-way loss).
func oneWay(a, b profile, share float64) *cell {
	return &cell{name: fmt.Sprintf("ablation/%s-%s+oneway%.0f", a.name, b.name, 100*share), group: "ablation", class: v4Class(a.name, b.name),
		reportOnly: true, hard: [2]bool{a.hard, b.hard}, build: single(a.cfg, b.cfg),
		session: func(s *sessionSpec, _ *world, sides [2]*side) {
			s.prepare = func(r *run) { oneWayLoss(sides, 0, 1, share, r.w.cfg.seed) }
		}}
}

// Representative cells by the mechanisms they carry.
const (
	repSeq          = "v4/PRC-SYMSEQ"                       // SinglePortProbe, NoPrediction
	repSeqFW        = "v4/PUBFW-SYMSEQ"                     // SinglePortProbe
	repSlow         = "slowctl/PRC-PRC"                     // NoRTTAlign
	repSeqSeq       = "ablation/SYMSEQ-SYMSEQ+silent-rung1" // NoRoleAssign: round 2 has a low-TTL receiver that sprays
	repOpenRnd      = "ablation/FC-SYMRND+silent-rung1"     // NoRoleAssign report only (a cone side that only pre-opens), NoRounds, NoMemory
	repPDFSeq       = "ablation/PRC-SYMSEQ+silent-rung1"    // NoRoleAssign report only (connects at the start of round 2), NoRounds, NoMemory: rung 2 after a lost rung 1
	repOneWay       = "ablation/FC-SYMSEQ+oneway60"         // NoAssistRelay, report only
	repNoise        = "noise/PRC-SYMSEQ~20"                 // NoSandwich, report only
	repRefresh      = "noise/SYMSEQ~20-SYMSEQ~20"           // NoRefresh, report only
	repScan         = "scan/PRC-SYMSEQ"                     // scan bans
	repNegVerdict   = "neg/symrnd-default"                  // NoEarlyAbort
	repNegFamily    = "neg/v4only-v6only"                   // NoEarlyAbort
	repNegBlackhole = "neg/probe-blackhole"                 // NoEarlyAbort
	// The misclassified cell of the NoAssistRelay and NoSandwich gates: the
	// burst after the probe is corrected within round 1 by the sandwich window
	// that peer_targets pushes, which NoSandwich does not open and
	// NoAssistRelay drops with the rest of punch_assist.
	repBurst = "misclass/PRC-SYMSEQ+burst400"
	// The cell of the misclassified kind that one server IP cannot detect:
	// NoCorrection on it is reported only.
	repADM = "multi/ADMRND-PRC"
	// The gate cell of NoRefresh, under full and NoRefresh only: at 20 ports
	// a second the pair orders' offsets catch most of the drift
	// without a refresh — some 60–75% of the runs connect — so the
	// refresh's value shows at 50, where hardly any do.
	repRefresh50 = "noise/SYMSEQ~50-SYMSEQ~50"
)

// ablationConstructs returns the constructed representative cells.
func ablationConstructs() []*cell {
	return []*cell{
		silentFirstRung(v4Profile("SYMSEQ"), v4Profile("SYMSEQ")),
		silentFirstRung(v4Profile("FC"), v4Profile("SYMRND")),
		silentFirstRung(v4Profile("PRC"), v4Profile("SYMSEQ")),
		oneWay(v4Profile("FC"), v4Profile("SYMSEQ"), 0.6),
	}
}

// repNames are the representative cells in report order.
func repNames() []string {
	return []string{repSeq, repSeqFW, repSlow, repSeqSeq, repOpenRnd, repPDFSeq, repOneWay, repNoise, repRefresh, repScan, repNegVerdict, repNegFamily, repNegBlackhole}
}

// memoryPair is a pair of networks of the memory mechanism: five
// consecutive sessions on one coordinator.
type memoryPair struct {
	name string
	a, b profile
	// silent silences the first rung in every session: only a later rung
	// connects, which the strategy memory can start from.
	silent bool
	// adm marks the address-dependent pair, reported only: one server IP
	// cannot tell address-dependent mapping from endpoint-independent, and
	// the traits memory has nothing to learn it from.
	adm bool
}

// memoryPairs returns the memory pairs.
func memoryPairs() []memoryPair {
	return []memoryPair{
		{name: "PRC-SYMSEQ+silent-rung1", a: v4Profile("PRC"), b: v4Profile("SYMSEQ"), silent: true},
		{name: "FC-SYMRND+silent-rung1", a: v4Profile("FC"), b: v4Profile("SYMRND"), silent: true},
		{name: "ADMRND-PRC", a: profile{name: "ADMRND", cfg: profADMRND, hard: true}, b: v4Profile("PRC"), adm: true},
	}
}

// ablationStat summarises one (cell, configuration) of the ablation.
type ablationStat struct {
	k          cellKPI
	firstRound float64 // successes in round 1, as a rate
	relayWait  quantiles
	// filtered is the mean over runs of the inbound packets both NATs
	// filtered, filteredNAT the same per side's NAT.
	filtered    float64
	filteredNAT [2]float64
	// measured is what natprobe measured in the first run, when recorded.
	measured [2]string
}

// ablationRun runs a cell under an ablation set, quietly (no gates, no dumps).
func ablationRun(t *testing.T, c *cell, abl ablation.Set, runs int) ablationStat {
	release := acquireSlot()
	defer release()
	start := time.Now()
	var crs []*cellRun
	var relay []float64
	var st ablationStat
	first := 0
	for i := range runs {
		cr, _ := runOnce(t, c, cellSeed(c.name, i), abl, false)
		crs = append(crs, cr)
		if cr.m.OK && cr.m.ConfirmRound == 1 {
			first++
		}
		if !cr.m.OK && cr.r != nil {
			relay = append(relay, max(cr.m.ConfirmMs[0], cr.m.ConfirmMs[1]))
		}
		for i, n := range cr.m.Filtered {
			st.filteredNAT[i] += float64(n) / float64(runs)
			st.filtered += float64(n) / float64(runs)
		}
		if i == 0 {
			st.measured = cr.m.Measured
		}
	}
	st.k, st.relayWait = kpiOf(c, abl.String(), crs, time.Since(start)), quant(relay)
	if runs > 0 {
		st.firstRound = float64(first) / float64(runs)
	}
	if dir := suite().out; dir != "" {
		if err := writeKPI(dir+"/kpi/ablation", st.k); err != nil {
			t.Errorf("kpi: %v", err)
		}
	}
	return st
}

// memRun is one session of a memory sequence.
type memRun struct {
	variant string // round 1's
	// mapping is the mapping of the initiator's first family as its
	// summary showed it (the traits memory may raise it), and adm
	// whether that was ADM with at least Medium confidence.
	mapping   string
	packets   int
	confirmMs float64
	ok        bool
	adm       bool
}

// ablationResults collects the runs of the ablation from parallel subtests.
type ablationResults struct {
	mu   sync.Mutex
	cell map[string]map[string]ablationStat // cell → ablation name → stat
	mem  map[string]map[string][]memRun
}

func (r *ablationResults) put(cell, abl string, st ablationStat) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cell[cell] == nil {
		r.cell[cell] = map[string]ablationStat{}
	}
	r.cell[cell][abl] = st
}

func (r *ablationResults) get(cell string, abl ablation.Set) (ablationStat, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.cell[cell][abl.String()]
	return st, ok
}

func (r *ablationResults) putMem(pair, abl string, seqs [][]memRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mem[pair] == nil {
		r.mem[pair] = map[string][]memRun{}
	}
	for _, s := range seqs {
		r.mem[pair][abl] = append(r.mem[pair][abl], s...)
	}
}

// ablationJob is one (cell, configuration) of the ablation.
type ablationJob struct {
	c   *cell
	abl ablation.Set
}

// ablationJobs lists the (cell, configuration) runs, each once: the 49 ordered
// IPv4 cells under full and Plain, the representative cells under full,
// the ten single ablations and Plain, the misclassified cells under the
// correction configurations and Plain, the NoRefresh gate cell under full
// and NoRefresh. A run is named cell@configuration;
// HOLEPUNCH_E2E_CELLS selects among those names.
func ablationJobs() (jobs []ablationJob, v4 []*cell, misclass []*cell) {
	byName := map[string]*cell{}
	for _, c := range append(cells(), ablationConstructs()...) {
		byName[c.name] = c
		if c.group == "v4" {
			v4 = append(v4, c)
		}
	}
	seen := map[string]bool{}
	add := func(c *cell, abl ablation.Set) {
		key := c.name + "@" + abl.String()
		if seen[key] || !suite().selected(key) {
			return
		}
		seen[key] = true
		jobs = append(jobs, ablationJob{c: c, abl: abl})
	}
	for _, c := range v4 {
		add(c, ablation.Set{})
		add(c, ablation.Plain())
	}
	all := append(append([]ablation.Set{{}}, ablation.Singles()...), ablation.Plain())
	for _, name := range repNames() {
		for _, abl := range all {
			add(byName[name], abl)
		}
	}
	for _, c := range byName {
		if c.group == "misclass" || c.name == repADM {
			misclass = append(misclass, c)
		}
	}
	slices.SortFunc(misclass, func(a, b *cell) int { return strings.Compare(a.name, b.name) })
	for _, c := range misclass {
		for _, abl := range correctionConfigs() {
			add(c, abl)
		}
	}
	add(byName[repRefresh50], ablation.Set{})
	add(byName[repRefresh50], ablation.Set{NoRefresh: true})
	return jobs, v4, misclass
}

// TestAblation runs the ablation at the nightly level (or with
// HOLEPUNCH_E2E_ABLATION_RUNS set), writes ablation_report.md, and fails when
// the combination gate or any threshold not marked report only fails.
// With HOLEPUNCH_E2E_CELLS narrowing the runs, the combination gate is
// reported as partial and not applied, and a threshold whose runs were not
// selected is not judged.
func TestAblation(t *testing.T) {
	runs := 0
	if suite().level == levelNightly {
		runs = nightlyRuns
	}
	if v, err := strconv.Atoi(os.Getenv(envAblationRuns)); err == nil && v > 0 {
		runs = v
	}
	if runs == 0 {
		t.Skip("the ablation runs at the nightly level or with " + envAblationRuns)
	}
	jobs, v4, misclass := ablationJobs()
	res := &ablationResults{cell: map[string]map[string]ablationStat{}, mem: map[string]map[string][]memRun{}}
	t.Run("runs", func(t *testing.T) {
		for _, j := range jobs {
			t.Run(j.c.name+"@"+j.abl.String(), func(t *testing.T) {
				t.Parallel()
				res.put(j.c.name, j.abl.String(), ablationRun(t, j.c, j.abl, runs))
			})
		}
		for _, p := range memoryPairs() {
			for _, abl := range []ablation.Set{{}, {NoMemory: true}} {
				name := "memory/" + p.name + "@" + abl.String()
				if !suite().selected(name) {
					continue
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					res.putMem(p.name, abl.String(), memorySequences(t, p, abl, max(runs/4, 2)))
				})
			}
		}
	})
	report, failed := ablationReport(res, v4, misclass, runs)
	if dir := suite().out; dir != "" {
		if err := writeOut(dir, "ablation_report.md", []byte(report)); err != nil {
			t.Errorf("ablation_report.md: %v", err)
		}
	} else {
		t.Log(report)
	}
	for _, f := range failed {
		t.Error(f)
	}
	goleak.VerifyNone(t)
}

// memoriesPerSequence is the length of a memory sequence.
const memoriesPerSequence = 5

// memorySequences runs n sequences of five sessions, each sequence on one
// world (one coordinator, so one strategy memory and one traits memory).
func memorySequences(t *testing.T, p memoryPair, abl ablation.Set, n int) [][]memRun {
	release := acquireSlot()
	defer release()
	var out [][]memRun
	for k := range n {
		w := newWorld(t, worldConfig{seed: cellSeed("memory/"+p.name, k)})
		sides := [2]*side{w.behind([]nattest.NATConfig{p.a.cfg()}), w.behind([]nattest.NATConfig{p.b.cfg()})}
		var seq []memRun
		for range memoriesPerSequence {
			spec := sessionSpec{ablation: abl}
			if p.silent {
				spec.prepare = func(r *run) { silenceRung(r, sides, firstRung) }
			}
			r, err := newRun(w, sides, spec)
			if err != nil {
				t.Errorf("memory %s: %v", p.name, err)
				break
			}
			r.execute()
			for _, s := range sides {
				s.nats[len(s.nats)-1].DropUpstream(nil)
			}
			m := memRun{ok: r.out[0].ok() && r.out[1].ok(),
				packets: r.out[0].diag.Counters.TxPackets + r.out[1].diag.Counters.TxPackets}
			m.confirmMs = ms(max(r.out[0].dur(), r.out[1].dur()))
			if s := view(r.taps[0]).summary; s != nil {
				m.variant = s.Plan.Round1.Variant
				if len(s.Self.Families) > 0 {
					tr := s.Self.Families[0].Traits
					m.mapping = fmt.Sprintf("%s/%s", tr.Mapping, tr.MappingConf)
					m.adm = tr.Mapping == protocol.MapADM && tr.MappingConf >= protocol.ConfMedium
				}
			}
			seq = append(seq, m)
			if err := r.closeSessions(); err != nil {
				t.Errorf("memory %s: %v", p.name, err)
			}
		}
		if err := w.close(); err != nil {
			t.Errorf("memory %s: %v", p.name, err)
		}
		out = append(out, seq)
	}
	return out
}

// combos returns the 15 combinations of profile classes: each
// unordered pair of profile classes with the ordered IPv4 cells in it.
func combos() (names []string, cellsOf map[string][]string) {
	rank := map[string]int{"OPEN": 0, "ADF": 1, "PDF": 2, "SEQ": 3, "RND": 4}
	cellsOf = map[string][]string{}
	for _, a := range v4Profiles {
		for _, b := range v4Profiles {
			x, y := a.combo, b.combo
			if rank[x] > rank[y] {
				x, y = y, x
			}
			k := x + "×" + y
			if cellsOf[k] == nil {
				names = append(names, k)
			}
			cellsOf[k] = append(cellsOf[k], "v4/"+a.name+"-"+b.name)
		}
	}
	slices.SortFunc(names, func(a, b string) int {
		ax, ay, _ := strings.Cut(a, "×")
		bx, by, _ := strings.Cut(b, "×")
		if c := rank[ax] - rank[bx]; c != 0 {
			return c
		}
		return rank[ay] - rank[by]
	})
	return names, cellsOf
}

// ablationReport renders ablation_report.md. It returns the report and the
// gates that failed: the combination gate when every cell it needs ran, and
// each threshold
// that is not report only and whose runs ran.
func ablationReport(res *ablationResults, v4 []*cell, misclass []*cell, runs int) (string, []string) {
	var b strings.Builder
	var failed []string
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(&b, format, args...) }
	full, plain := ablation.Set{}, ablation.Plain()
	get := func(cell string, a ablation.Set) ablationStat { st, _ := res.get(cell, a); return st }
	has := func(cell string, a ablation.Set) bool { _, ok := res.get(cell, a); return ok }
	pct := func(cell string, a ablation.Set) string {
		if !has(cell, a) {
			return "—"
		}
		return fmt.Sprintf("%.0f%%", 100*get(cell, a).k.SuccessRate)
	}
	p("# Ablation report\n\n")
	p("Generated %s, %d runs per (cell, configuration), level %s.\n\n", time.Now().Format(time.RFC3339), runs, suite().level)
	p("Scope: cone and restricted pairs connect with plain hole punching too; there the value of the three-party model is time and packets. SYMRND × SYMRND in the default tier is rejected early; with extreme + aggressive it stays a low-probability event.\n\n")

	// The combination gate over the 15 combinations.
	names, cellsOf := combos()
	complete := true
	var sumF, sumP float64
	p("## Combination gate: 15 combinations of profile classes, equal weights\n\n")
	p("Each combination is the equal-weight mean of its ordered IPv4 cells; the 15 combinations weigh the same.\n\n")
	p("| combination | cells | full | plain | Δ (pts) |\n|---|---:|---:|---:|---:|\n")
	for _, k := range names {
		var f, pl float64
		for _, c := range cellsOf[k] {
			complete = complete && has(c, full) && has(c, plain)
			f += get(c, full).k.SuccessRate
			pl += get(c, plain).k.SuccessRate
		}
		n := float64(len(cellsOf[k]))
		sumF += f / n
		sumP += pl / n
		p("| %s | %d | %.1f%% | %.1f%% | %+.1f |\n", k, len(cellsOf[k]), 100*f/n, 100*pl/n, 100*(f-pl)/n)
	}
	nc := float64(len(names))
	gate := 100 * (sumF - sumP) / nc
	verdict := "PASS"
	switch {
	case !complete:
		verdict = "PARTIAL (not every cell ran; not gated)"
	case gate < combinationGate-1e-6:
		verdict = "FAIL"
		failed = append(failed, fmt.Sprintf("combination gate: full − Plain = %.1f points over the 15 combinations, want ≥ %.0f", gate, combinationGate))
	}
	p("\n**full %.1f%%, plain %.1f%%, Δ = %+.1f points (gate ≥ +%.0f): %s**\n\n", 100*sumF/nc, 100*sumP/nc, gate, combinationGate, verdict)

	// The class gates beside the combination gate, on the full runs of the v4
	// cells.
	p("## Class gates\n\n")
	p("PDF×SEQ and SEQ×SEQ cells: full ≥ %.0f%%. Model cells (PDF×RND, SEQ×RND, RND×RND): not significantly below 0.8·P_model (one-sided binomial, α = %.2f), as the matrix gates them.\n\n", 100*classGateRate, modelAlpha)
	p("| cell | combination | gate | full | P_model | verdict |\n|---|---|---|---:|---:|---|\n")
	for _, k := range names {
		seqGate := k == "PDF×SEQ" || k == "SEQ×SEQ"
		model := k == "PDF×RND" || k == "SEQ×RND" || k == "RND×RND"
		if !seqGate && !model {
			continue
		}
		for _, c := range cellsOf[k] {
			st, ok := res.get(c, full)
			if !ok {
				p("| %s | %s | — | — | — | NOT RUN |\n", c, k)
				continue
			}
			rule, v := fmt.Sprintf("≥ %.0f%%", 100*classGateRate), "PASS"
			if seqGate && st.k.SuccessRate+1e-9 < classGateRate {
				v = "FAIL"
				failed = append(failed, fmt.Sprintf("class gate on %s (%s): full %d/%d, want ≥ %.0f%%", c, k, st.k.Successes, st.k.Runs, 100*classGateRate))
			}
			if model {
				p0 := 0.8 * st.k.PModel
				rule = fmt.Sprintf("binom(0.8·P = %.3f)", p0)
				if pv := binomialCDF(st.k.Successes, st.k.Runs, p0); pv < modelAlpha {
					v = fmt.Sprintf("FAIL (p = %.4f)", pv)
					failed = append(failed, fmt.Sprintf("class gate on %s (%s): %d/%d significantly below 0.8·P_model = %.3f (p = %.4f)",
						c, k, st.k.Successes, st.k.Runs, p0, pv))
				}
			}
			p("| %s | %s | %s | %d/%d | %.3f | %s |\n", c, k, rule, st.k.Successes, st.k.Runs, st.k.PModel, v)
		}
	}
	p("\n")

	// The 49 ordered cells, reported only.
	var cF, cP float64
	p("## The 49 ordered IPv4 cells, equal weights (reported only)\n\n| cell | class | full | plain | Δ (pts) |\n|---|---|---:|---:|---:|\n")
	for _, c := range v4 {
		f, pl := get(c.name, full), get(c.name, plain)
		cF += f.k.SuccessRate
		cP += pl.k.SuccessRate
		p("| %s | %s | %s | %s | %+.0f |\n", c.name, c.class, pct(c.name, full), pct(c.name, plain), 100*(f.k.SuccessRate-pl.k.SuccessRate))
	}
	n := float64(max(len(v4), 1))
	p("\nfull %.1f%%, plain %.1f%%, Δ = %+.1f points.\n\n", 100*cF/n, 100*cP/n, 100*(cF-cP)/n)

	// Never worse than plain punching, cell by cell.
	failed = append(failed, plainGate(&b, res, v4, misclass, runs)...)

	// Representative cells.
	configs := append(append([]ablation.Set{full}, ablation.Singles()...), plain)
	p("## Representative cells × {full, %d single ablations, plain}\n\n", len(ablation.Singles()))
	p("The ablation/ cells make round 1 fail: +silent-rung1 loses every packet between the peers while they run the first rung of their ladder; +oneway60 loses 60%% of the packets from the initiator to the responder.\n\n")
	for _, name := range repNames() {
		p("### %s\n\n| configuration | success | first round | confirm p50/p95 ms | packets/side p50 | skew p90 ms | filtered inbound/session | scan bans | failure wait p50 ms |\n|---|---:|---:|---|---:|---:|---:|---:|---:|\n", name)
		for _, a := range configs {
			st, ok := res.get(name, a)
			if !ok {
				continue
			}
			p("| %s | %.0f%% | %.0f%% | %.0f/%.0f | %.0f | %.0f | %.1f | %d | %.0f |\n", a, 100*st.k.SuccessRate, 100*st.firstRound,
				st.k.ConfirmMs.P50, st.k.ConfirmMs.P95, st.k.PacketsPerSide.P50, st.k.FirstSendSkewMs.P90, st.filtered,
				st.k.ScanBans, st.relayWait.P50)
		}
		p("\n")
	}

	// Memory sequences.
	noMem := ablation.Set{NoMemory: true}
	p("## Memory: five consecutive sessions per pair of networks\n\n| pair | configuration | session 1 packets | sessions 2–5 packets (mean) | ratio | session 1 confirm ms | sessions 2–5 confirm ms (mean) | success 1 / 2–5 | round-1 variants of sessions 2–5 | initiator mapping in summaries 1 / 2 |\n|---|---|---:|---:|---:|---:|---:|---|---|---|\n")
	memRatio := map[string]map[string]float64{}
	admSecond := map[string]int{} // pair → sessions 2 of full whose summary showed ADM (the ADM pair's threshold)
	for _, m := range memoryPairs() {
		for _, a := range []ablation.Set{full, noMem} {
			rs := res.mem[m.name][a.String()]
			var p1, pRest, c1, cRest, n1, nRest, ok1, okRest float64
			variants := map[string]int{}
			mapping := [2]map[string]int{{}, {}}
			for i, r := range rs {
				pos := i % memoriesPerSequence
				if pos <= 1 {
					mapping[pos][r.mapping]++
				}
				if pos == 1 && r.adm && a == full {
					admSecond[m.name]++
				}
				if pos == 0 {
					p1, c1, n1 = p1+float64(r.packets), c1+r.confirmMs, n1+1
					if r.ok {
						ok1++
					}
					continue
				}
				pRest, cRest, nRest = pRest+float64(r.packets), cRest+r.confirmMs, nRest+1
				if r.ok {
					okRest++
				}
				variants[r.variant]++
			}
			if n1 == 0 || nRest == 0 || p1 == 0 {
				continue
			}
			ratio := (pRest / nRest) / (p1 / n1)
			if memRatio[m.name] == nil {
				memRatio[m.name] = map[string]float64{}
			}
			memRatio[m.name][a.String()] = ratio
			p("| %s | %s | %.0f | %.0f | %.2f | %.0f | %.0f | %.0f%% / %.0f%% | %s | %s / %s |\n", m.name, a, p1/n1, pRest/nRest, ratio, c1/n1, cRest/nRest,
				100*ok1/n1, 100*okRest/nRest, histogram(variants), histogram(mapping[0]), histogram(mapping[1]))
		}
	}

	// Misclassified cells.
	p("\n## Deliberately misclassified cells\n\n")
	p("natprobe measures the NAT at probe time; the NAT then behaves otherwise. The punch-time corrections are switched off one by one and together (NoCorrection = NoAssistRelay+NoSandwich+NoRounds); *recovered* is full − NoCorrection.\n\n")
	p("| cell | real behaviour | natprobe measured (first run) | full | NoSandwich | NoAssistRelay | NoRounds | NoCorrection | plain | recovered (pts) |\n|---|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, c := range misclass {
		if !has(c.name, full) {
			continue
		}
		st := get(c.name, full)
		rec := "—"
		if has(c.name, noCorrection()) {
			rec = fmt.Sprintf("%+.0f", 100*(st.k.SuccessRate-get(c.name, noCorrection()).k.SuccessRate))
		}
		p("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", c.name, c.truth, strings.Join(st.measured[:], " × "),
			pct(c.name, full), pct(c.name, ablation.Set{NoSandwich: true}), pct(c.name, ablation.Set{NoAssistRelay: true}),
			pct(c.name, ablation.Set{NoRounds: true}), pct(c.name, noCorrection()), pct(c.name, plain), rec)
	}

	// Thresholds.
	p("\n## Thresholds\n\n")
	p("A gated threshold that is missed fails the test; a report-only one never does. NOT RUN: a configuration the threshold needs was not selected.\n\n")
	p("| mechanism | cell | threshold | measured | gate | verdict |\n|---|---|---|---|---|---|\n")
	ge := func(a, b float64) bool { return a >= b-1e-6 } // percentages from rates, without float noise
	ran := func(cell string, configs ...ablation.Set) bool {
		for _, a := range configs {
			if !has(cell, a) {
				return false
			}
		}
		return true
	}
	put := func(th threshold) {
		gate := "gate"
		if th.reportOnly {
			gate = "report only"
		}
		if !th.ran {
			p("| %s | %s | %s | — | %s | NOT RUN |\n", th.mech, th.cell, th.rule, gate)
			return
		}
		v := "PASS"
		switch {
		case th.reportOnly && th.ok:
			v = "reported"
		case th.reportOnly:
			v = "reported (not met)"
		case !th.ok:
			v = "FAIL"
			failed = append(failed, fmt.Sprintf("%s on %s: %s; measured %s", th.mech, th.cell, th.rule, th.measured))
		}
		p("| %s | %s | %s | %s | %s | %s |\n", th.mech, th.cell, th.rule, th.measured, gate, v)
	}

	spp := ablation.Set{SinglePortProbe: true}
	dSPP := 100 * (get(repSeq, full).k.SuccessRate - get(repSeq, spp).k.SuccessRate)
	put(threshold{mech: "SinglePortProbe", cell: repSeq, rule: "full − SinglePortProbe ≥ +60 pts", ran: ran(repSeq, full, spp),
		measured: fmt.Sprintf("%+.0f pts", dSPP), ok: ge(dSPP, 60)})

	rtt := ablation.Set{NoRTTAlign: true}
	fs, ns := get(repSlow, full).k.FirstSendSkewMs.P90, get(repSlow, rtt).k.FirstSendSkewMs.P90
	put(threshold{mech: "NoRTTAlign", cell: repSlow, rule: "skew p90 ≤ 30 ms, NoRTTAlign ≥ 150 ms", ran: ran(repSlow, full, rtt),
		measured: fmt.Sprintf("%.0f ms / %.0f ms", fs, ns), ok: fs <= 30 && ns >= 150})

	// Role assignment keeps the low-TTL receiver's packets off its peer's
	// NAT: the threshold is read on the NAT whose filtered inbound drops
	// most, the other one sees the same sprays either way. Where
	// the cone side sends a single packet anyway, the ratio is reported;
	// so is the PDF×SEQ cell, which connects at the start of round 2 and
	// leaves three or four filtered packets either way.
	role := ablation.Set{NoRoleAssign: true}
	for _, rc := range []struct {
		cell       string
		reportOnly bool
	}{{repSeqSeq, false}, {repPDFSeq, true}, {repOpenRnd, true}} {
		fs, ns := get(rc.cell, full), get(rc.cell, role)
		best := -1.0
		for i := range 2 {
			if ns.filteredNAT[i] > 0 && (best < 0 || fs.filteredNAT[i]/ns.filteredNAT[i] < best) {
				best = fs.filteredNAT[i] / ns.filteredNAT[i]
			}
		}
		put(threshold{mech: "NoRoleAssign", cell: rc.cell, rule: "filtered inbound at the low-TTL receiver's peer NAT: full ≤ 0.5 × NoRoleAssign",
			reportOnly: rc.reportOnly, ran: ran(rc.cell, full, role),
			measured: fmt.Sprintf("NATs %.1f/%.1f and %.1f/%.1f (ratio %.2f); session %.1f/%.1f", fs.filteredNAT[0], ns.filteredNAT[0],
				fs.filteredNAT[1], ns.filteredNAT[1], best, fs.filtered, ns.filtered),
			ok: best >= 0 && best <= 0.5})
	}
	sb := get(repScan, full).k.ScanBans
	put(threshold{mech: "scan bans", cell: repScan, rule: "ScanBans == 0 (full)", ran: ran(repScan, full), measured: fmt.Sprintf("%d", sb), ok: sb == 0})

	// NoAssistRelay on the misclassified burst. Under one-way loss the next
	// round hits without the relay too, so that cell is reported only.
	relay := ablation.Set{NoAssistRelay: true}
	dRelay := 100 * (get(repBurst, full).k.SuccessRate - get(repBurst, relay).k.SuccessRate)
	put(threshold{mech: "NoAssistRelay", cell: repBurst, rule: "full − NoAssistRelay ≥ +50 pts", ran: ran(repBurst, full, relay),
		measured: fmt.Sprintf("%+.0f pts (%s / %s)", dRelay, pct(repBurst, full), pct(repBurst, relay)), ok: ge(dRelay, 50)})
	ow, owr := get(repOneWay, full), get(repOneWay, relay)
	put(threshold{mech: "NoAssistRelay", cell: repOneWay, rule: "none: the next round hits without the relay too", reportOnly: true, ran: ran(repOneWay, full, relay),
		measured: fmt.Sprintf("success %.0f%% / %.0f%%, first round %.0f%% / %.0f%%, p95 %.0f / %.0f ms, packets p50 %.0f / %.0f",
			100*ow.k.SuccessRate, 100*owr.k.SuccessRate, 100*ow.firstRound, 100*owr.firstRound, ow.k.ConfirmMs.P95, owr.k.ConfirmMs.P95,
			ow.k.PacketsPerSide.P50, owr.k.PacketsPerSide.P50), ok: true})

	// NoSandwich on the misclassified burst: a quiet-looking PDF×SEQ connects
	// in round 1 without the sandwich too, so the noise cell is reported only.
	sw := ablation.Set{NoSandwich: true}
	dSandwich := 100 * (get(repBurst, full).k.SuccessRate - get(repBurst, sw).k.SuccessRate)
	put(threshold{mech: "NoSandwich", cell: repBurst, rule: "full − NoSandwich ≥ +50 pts", ran: ran(repBurst, full, sw),
		measured: fmt.Sprintf("%+.0f pts (%s / %s)", dSandwich, pct(repBurst, full), pct(repBurst, sw)), ok: ge(dSandwich, 50)})
	dFirst := 100 * (get(repNoise, full).firstRound - get(repNoise, sw).firstRound)
	put(threshold{mech: "NoSandwich", cell: repNoise, rule: "first-round success: full − NoSandwich ≥ +20 pts", reportOnly: true,
		ran: ran(repNoise, full, sw), measured: fmt.Sprintf("%+.0f pts", dFirst), ok: ge(dFirst, 20)})

	// NoRefresh: the anchor refresh before the fire, gated on the
	// heavier noise; at 20 ports a second the difference is reported.
	nrf := ablation.Set{NoRefresh: true}
	dRefresh := 100 * (get(repRefresh50, full).k.SuccessRate - get(repRefresh50, nrf).k.SuccessRate)
	put(threshold{mech: "NoRefresh", cell: repRefresh50, rule: "full − NoRefresh ≥ +30 pts", ran: ran(repRefresh50, full, nrf),
		measured: fmt.Sprintf("%+.0f pts (%s / %s)", dRefresh, pct(repRefresh50, full), pct(repRefresh50, nrf)), ok: ge(dRefresh, 30)})
	dRefreshLight := 100 * (get(repRefresh, full).k.SuccessRate - get(repRefresh, nrf).k.SuccessRate)
	put(threshold{mech: "NoRefresh", cell: repRefresh, rule: "full − NoRefresh ≥ +30 pts", reportOnly: true, ran: ran(repRefresh, full, nrf),
		measured: fmt.Sprintf("%+.0f pts (%s / %s)", dRefreshLight, pct(repRefresh, full), pct(repRefresh, nrf)), ok: ge(dRefreshLight, 30)})

	nr := ablation.Set{NoRounds: true}
	for _, c := range []string{repOpenRnd, repPDFSeq} {
		dRounds := 100 * (get(c, full).k.SuccessRate - get(c, nr).k.SuccessRate)
		put(threshold{mech: "NoRounds", cell: c, rule: "full − NoRounds ≥ +10 pts", ran: ran(c, full, nr), measured: fmt.Sprintf("%+.0f pts", dRounds), ok: ge(dRounds, 10)})
	}

	// NoMemory; the ADM pair is reported only.
	for _, m := range memoryPairs() {
		fr, okF := memRatio[m.name][full.String()]
		nm, okN := memRatio[m.name][noMem.String()]
		put(threshold{mech: "NoMemory", cell: "memory/" + m.name, rule: "sessions 2–5 packets ≤ 0.75 × session 1 (full); no such drop with NoMemory",
			reportOnly: m.adm, ran: okF && okN, measured: fmt.Sprintf("%.2f / %.2f", fr, nm), ok: fr > 0 && fr <= 0.75 && nm > 0.75})
		if m.adm {
			put(threshold{mech: "NoMemory, ADM pair", cell: "memory/" + m.name, rule: "summary 2 shows the initiator ADM, at least Medium",
				reportOnly: true, ran: okF, measured: fmt.Sprintf("%d of %d sequences", admSecond[m.name], len(res.mem[m.name][full.String()])/memoriesPerSequence),
				ok: admSecond[m.name] > 0})
		}
	}

	early := ablation.Set{NoEarlyAbort: true}
	for _, neg := range []string{repNegVerdict, repNegFamily, repNegBlackhole} {
		fw, nw := get(neg, full).relayWait.P50, get(neg, early).relayWait.P50
		put(threshold{mech: "NoEarlyAbort", cell: neg, rule: "wait before the relay ≤ 3 s (full); ≈ the stage deadline with NoEarlyAbort",
			ran: ran(neg, full, early), measured: fmt.Sprintf("%.0f / %.0f ms", fw, nw), ok: fw >= 0 && fw <= 3000})
	}

	// NoPrediction reports the success; the budget invariant holds all the
	// same.
	npred := ablation.Set{NoPrediction: true}
	np := get(repSeq, npred)
	put(threshold{mech: "NoPrediction", cell: repSeq, rule: "success reported; ScanBans == 0", ran: ran(repSeq, npred),
		measured: fmt.Sprintf("success %.0f%%, scan bans %d", 100*np.k.SuccessRate, np.k.ScanBans), ok: np.k.ScanBans == 0})

	// The corrections together, per load-changing cell; the cell
	// one server IP cannot classify is reported only.
	for _, c := range misclass {
		dc := 100 * (get(c.name, full).k.SuccessRate - get(c.name, noCorrection()).k.SuccessRate)
		put(threshold{mech: "Corrections (NoCorrection)", cell: c.name, rule: "full − NoCorrection ≥ +50 pts", reportOnly: c.name == repADM,
			ran: ran(c.name, full, noCorrection()), measured: fmt.Sprintf("%+.0f pts (%s / %s)", dc, pct(c.name, full), pct(c.name, noCorrection())),
			ok: ge(dc, 50)})
	}
	return b.String(), failed
}

// plainGate writes the per-cell comparison with plain punching:
// every ordered IPv4 cell and every misclassified cell whose full and
// Plain runs ran, full's successes against Plain's less plainSlack. It
// returns the cells that fail.
func plainGate(b *strings.Builder, res *ablationResults, v4, misclass []*cell, runs int) []string {
	var failed []string
	slack := plainSlack(runs)
	full, plain := ablation.Set{}, ablation.Plain()
	_, _ = fmt.Fprintf(b, "## Never worse than plain punching\n\n")
	_, _ = fmt.Fprintf(b, "Every ordered IPv4 cell and every deliberately misclassified cell: full successes ≥ Plain successes − %d (%d runs). A cell whose full or Plain runs did not run is NOT RUN.\n\n", slack, runs)
	_, _ = fmt.Fprintf(b, "| cell | full | plain | full − plain | verdict |\n|---|---:|---:|---:|---|\n")
	var worse, behind, judged int
	for _, c := range append(slices.Clone(v4), misclass...) {
		f, okF := res.get(c.name, full)
		pl, okP := res.get(c.name, plain)
		if !okF || !okP {
			_, _ = fmt.Fprintf(b, "| %s | — | — | — | NOT RUN |\n", c.name)
			continue
		}
		judged++
		d := f.k.Successes - pl.k.Successes
		v := "PASS"
		switch {
		case d < -slack:
			v = "FAIL"
			worse++
			failed = append(failed, fmt.Sprintf("never worse than plain on %s: full %d/%d, plain %d/%d", c.name, f.k.Successes, f.k.Runs, pl.k.Successes, pl.k.Runs))
		case d < 0:
			behind++
		}
		_, _ = fmt.Fprintf(b, "| %s | %d/%d | %d/%d | %+d | %s |\n", c.name, f.k.Successes, f.k.Runs, pl.k.Successes, pl.k.Runs, d, v)
	}
	_, _ = fmt.Fprintf(b, "\n%d cells judged: %d below Plain within the slack, %d beyond it.\n\n", judged, behind, worse)
	return failed
}

// threshold is one row of the threshold table.
type threshold struct {
	mech, cell, rule string
	measured         string
	// reportOnly rows never fail the test.
	reportOnly bool
	// ran is false when a configuration the row reads was not selected.
	ran bool
	ok  bool
}

// histogram renders counts as "a×3 b×1", sorted by name.
func histogram(m map[string]int) string {
	var parts []string
	for k, n := range m {
		if k == "" {
			k = "?"
		}
		parts = append(parts, fmt.Sprintf("%s×%d", k, n))
	}
	slices.Sort(parts)
	return strings.Join(parts, " ")
}

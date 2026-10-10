// Command kpiagg aggregates the kpi.json files of the e2e suite into
// Markdown: the per-cell table, a summary per group, and the two summary
// views of the 49 ordered IPv4 cells — the 15 combinations (unordered pairs
// of the classes OPEN, ADF, PDF, SEQ, RND) and the connectivity classes —
// and the combination gate view: the 15 combinations weighing the same, per
// ablation configuration found (full and plain in the ablation output) —
// and, from the escalation sequences, the eventual direct rate after
// background escalation.
// Optionally it compares with a baseline file of the same format as its
// -json output.
//
// Usage:
//
//	go run ./e2e/kpiagg -dir <HOLEPUNCH_E2E_OUT>/kpi/nightly [-json out.json] [-baseline e2e/testdata/kpi_baseline.json]
//
// It reads only the files it is given and writes only to standard output
// and the -json file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// kpi is the subset of a cell's kpi.json that the summaries use.
type kpi struct {
	Cell        string         `json:"cell"`
	Group       string         `json:"group"`
	Class       string         `json:"class"`
	Ablation    string         `json:"ablation"`
	Runs        int            `json:"runs"`
	Successes   int            `json:"successes"`
	SuccessRate float64        `json:"success_rate"`
	ConfirmMs   quantiles      `json:"confirm_ms"`
	Packets     quantiles      `json:"packets_per_side"`
	Rounds      quantiles      `json:"rounds"`
	Skew        quantiles      `json:"first_send_skew_ms"`
	Failures    map[string]int `json:"failure_codes"`
	Gate        string         `json:"gate"`
	Pass        bool           `json:"pass"`
	Problems    []string       `json:"problems"`
	// The escalation sequences (TestBackgroundEscalation); EventualDirectRate
	// is nil for a matrix cell.
	EventualDirectRate *float64 `json:"eventual_direct_rate"`
	InteractiveRate    float64  `json:"interactive_rate"`
	Escalated          int      `json:"escalated"`
	BackgroundOK       int      `json:"background_successes"`
}

type quantiles struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50"`
	P90 float64 `json:"p90"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
}

// baselineCell is one cell of a baseline file.
type baselineCell struct {
	SuccessRate float64 `json:"success_rate"`
	ConfirmP95  float64 `json:"confirm_ms_p95"`
	PacketsMax  float64 `json:"packets_max"`
}

// profileClass maps the NAT profiles to the classes of the 15
// combinations.
var profileClass = map[string]string{
	"PUB": "OPEN", "FC": "OPEN", "RC": "ADF", "PUBFW": "PDF", "PRC": "PDF", "SYMSEQ": "SEQ", "SYMRND": "RND",
}

// numCombos is the number of unordered class pairs: 5 classes, 15 pairs.
const numCombos = 15

// classOrder orders the classes from the easiest.
var classOrder = map[string]int{"OPEN": 0, "ADF": 1, "PDF": 2, "SEQ": 3, "RND": 4}

// combo returns the unordered class pair of an IPv4 cell, "" for others.
func combo(cell string) (string, string, bool) {
	name, ok := strings.CutPrefix(cell, "v4/")
	if !ok {
		return "", "", false
	}
	a, b, ok := strings.Cut(name, "-")
	if !ok {
		return "", "", false
	}
	ca, cb := profileClass[a], profileClass[b]
	if ca == "" || cb == "" {
		return "", "", false
	}
	if classOrder[ca] > classOrder[cb] {
		ca, cb = cb, ca
	}
	return ca, cb, true
}

// Connectivity classes of the unordered class pairs, from the easiest.
const (
	connOpen     = "any side public / EIM-EIF"
	connEIMPair  = "EIM(ADF/PDF) × EIM(ADF/PDF)"
	connPDFSeq   = "EIM-PDF × EDM-seq"
	connADFEDM   = "EIM-ADF × EDM"
	connSeqSeq   = "EDM-seq × EDM-seq"
	connPDFRand  = "EIM-PDF × EDM-rand"
	connRandRand = "EDM-rand × EDM-rand"
	connOther    = "other: EDM-seq × EDM-rand"
)

// connOrder is the report order of the connectivity classes.
var connOrder = []string{connOpen, connEIMPair, connPDFSeq, connADFEDM, connSeqSeq, connPDFRand, connRandRand, connOther}

// connClass returns the connectivity class of an unordered class pair
// (SEQ × RND is in none of the named ones).
func connClass(a, b string) string {
	switch {
	case a == "OPEN":
		return connOpen
	case (a == "ADF" || a == "PDF") && (b == "ADF" || b == "PDF"):
		return connEIMPair
	case a == "PDF" && b == "SEQ":
		return connPDFSeq
	case a == "ADF" && (b == "SEQ" || b == "RND"):
		return connADFEDM
	case a == "SEQ" && b == "SEQ":
		return connSeqSeq
	case a == "PDF" && b == "RND":
		return connPDFRand
	case a == "RND" && b == "RND":
		return connRandRand
	}
	return connOther
}

func main() {
	dir := flag.String("dir", "", "directory of *.kpi.json files (searched recursively)")
	jsonOut := flag.String("json", "", "write the per-cell summary as JSON (a baseline) to this file")
	baseline := flag.String("baseline", "", "baseline JSON to compare with")
	flag.Parse()
	if *dir == "" {
		_, _ = fmt.Fprintln(os.Stderr, "kpiagg: -dir is required")
		os.Exit(2)
	}
	var cells []kpi
	err := filepath.WalkDir(*dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".kpi.json") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var k kpi
		if err := json.Unmarshal(b, &k); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		cells = append(cells, k)
		return nil
	})
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "kpiagg:", err)
		os.Exit(1)
	}
	sort.Slice(cells, func(i, j int) bool {
		if cells[i].Ablation != cells[j].Ablation {
			return cells[i].Ablation < cells[j].Ablation
		}
		return cells[i].Cell < cells[j].Cell
	})
	var base map[string]baselineCell
	if *baseline != "" {
		b, err := os.ReadFile(*baseline)
		if err == nil {
			err = json.Unmarshal(b, &base)
		}
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "kpiagg: baseline:", err)
			os.Exit(1)
		}
	}
	render(os.Stdout, cells, base)
	if *jsonOut != "" {
		out := map[string]baselineCell{}
		for _, k := range cells {
			out[key(k)] = baselineCell{SuccessRate: k.SuccessRate, ConfirmP95: k.ConfirmMs.P95, PacketsMax: k.Packets.Max}
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "kpiagg:", err)
			os.Exit(1)
		}
	}
}

// key names a cell across files: the cell, with the ablation when it is
// not the full product.
func key(k kpi) string {
	if k.Ablation == "" || k.Ablation == "full" {
		return k.Cell
	}
	return k.Cell + "@" + k.Ablation
}

// agg sums the success rates of a group of cells.
type agg struct {
	n, pass int
	sum     float64
}

func render(w *os.File, cells []kpi, base map[string]baselineCell) {
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	p("# e2e KPI summary\n\n## Cells\n\n| cell | class | runs | success | confirm p50/p95 ms | packets/side p50/max | rounds max | skew p90 ms | failures | gate | pass |")
	if base != nil {
		p(" Δ success vs baseline |")
	}
	p("\n|---|---|---:|---:|---|---|---:|---:|---|---|---|")
	if base != nil {
		p("---:|")
	}
	p("\n")
	groups := map[string]*agg{}
	for _, k := range cells {
		var fails []string
		for c, n := range k.Failures {
			fails = append(fails, fmt.Sprintf("%s×%d", c, n))
		}
		sort.Strings(fails)
		pass := "yes"
		if !k.Pass {
			pass = "**no**"
		}
		p("| %s | %s | %d | %d/%d | %.0f/%.0f | %.0f/%.0f | %.0f | %.0f | %s | %s | %s |", key(k), k.Class, k.Runs, k.Successes, k.Runs,
			k.ConfirmMs.P50, k.ConfirmMs.P95, k.Packets.P50, k.Packets.Max, k.Rounds.Max, k.Skew.P90, strings.Join(fails, " "), k.Gate, pass)
		if base != nil {
			if b, ok := base[key(k)]; ok {
				p(" %+.0f pts |", 100*(k.SuccessRate-b.SuccessRate))
			} else {
				p(" — |")
			}
		}
		p("\n")
		g := k.Group
		if k.Ablation != "" && k.Ablation != "full" {
			g += "@" + k.Ablation
		}
		if groups[g] == nil {
			groups[g] = &agg{}
		}
		groups[g].n++
		groups[g].sum += k.SuccessRate
		if k.Pass {
			groups[g].pass++
		}
	}
	p("\n## Groups\n\n| group | cells | passed | mean success |\n|---|---:|---:|---:|\n")
	var names []string
	for g := range groups {
		names = append(names, g)
	}
	sort.Strings(names)
	for _, g := range names {
		a := groups[g]
		p("| %s | %d | %d | %.1f%% |\n", g, a.n, a.pass, 100*a.sum/float64(a.n))
	}

	// The summary views over the full product's IPv4 cells.
	combos := map[string]*agg{}
	classes := map[string]*agg{}
	// byAbl holds the 15 combinations of every configuration, for the
	// combination gate view.
	byAbl := map[string]map[string]*agg{}
	for _, k := range cells {
		a, b, ok := combo(k.Cell)
		if !ok {
			continue
		}
		abl := k.Ablation
		if abl == "" {
			abl = "full"
		}
		if byAbl[abl] == nil {
			byAbl[abl] = map[string]*agg{}
		}
		views := []struct {
			into map[string]*agg
			name string
		}{{byAbl[abl], a + "×" + b}}
		if abl == "full" {
			views = append(views, struct {
				into map[string]*agg
				name string
			}{combos, a + "×" + b}, struct {
				into map[string]*agg
				name string
			}{classes, connClass(a, b)})
		}
		for _, m := range views {
			if m.into[m.name] == nil {
				m.into[m.name] = &agg{}
			}
			m.into[m.name].n++
			m.into[m.name].sum += k.SuccessRate
		}
	}
	for _, view := range []struct {
		title string
		m     map[string]*agg
		order []string // nil: by name
	}{{"15 combinations, equal weights over the ordered cells", combos, nil}, {"Connectivity classes", classes, connOrder}} {
		if len(view.m) == 0 {
			continue
		}
		p("\n## %s\n\n| combination | cells | mean success |\n|---|---:|---:|\n", view.title)
		names = names[:0]
		for _, c := range view.order {
			if view.m[c] != nil {
				names = append(names, c)
			}
		}
		if view.order == nil {
			for c := range view.m {
				names = append(names, c)
			}
			sort.Strings(names)
		}
		for _, c := range names {
			a := view.m[c]
			p("| %s | %d | %.1f%% |\n", c, a.n, 100*a.sum/float64(a.n))
		}
	}
	renderEqualWeights(p, byAbl)
	renderEscalation(p, cells)
}

// renderEqualWeights is the combination gate view: each combination's mean,
// the combinations weighing the same; only configurations that cover all 15.
func renderEqualWeights(p func(string, ...any), byAbl map[string]map[string]*agg) {
	if len(byAbl) == 0 {
		return
	}
	p("\n## Combination gate view: the 15 combinations weighing the same, per configuration\n\n| configuration | mean success |\n|---|---:|\n")
	var names []string
	for abl, m := range byAbl {
		if len(m) == numCombos {
			names = append(names, abl)
		}
	}
	sort.Strings(names)
	for _, abl := range names {
		var sum float64
		for _, a := range byAbl[abl] {
			sum += a.sum / float64(a.n)
		}
		p("| %s | %.1f%% |\n", abl, 100*sum/numCombos)
	}
}

// renderEscalation is the eventual direct rate after background escalation: a
// KPI beside the combination gate, never part of it.
func renderEscalation(p func(string, ...any), cells []kpi) {
	var esc []kpi
	for _, k := range cells {
		if k.EventualDirectRate != nil {
			esc = append(esc, k)
		}
	}
	if len(esc) == 0 {
		return
	}
	p("\n## Eventual direct rate after background escalation (not part of the combination gate)\n\n| pair | sequences | Interactive | escalated | Background success | eventual direct rate |\n|---|---:|---:|---:|---:|---:|\n")
	var sumI, sumE float64
	for _, k := range esc {
		p("| %s | %d | %.0f%% | %d | %d | %.0f%% |\n", k.Cell, k.Runs, 100*k.InteractiveRate, k.Escalated, k.BackgroundOK, 100**k.EventualDirectRate)
		sumI += k.InteractiveRate
		sumE += *k.EventualDirectRate
	}
	n := float64(len(esc))
	p("| **mean** | | %.1f%% | | | **%.1f%%** |\n", 100*sumI/n, 100*sumE/n)
}

package plan

import (
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

var update = flag.Bool("update", false, "regenerate golden decision tables")

type goldenRound struct {
	Round    int                      `json:"round"`
	Variant  string                   `json:"variant"`
	Budget   protocol.BudgetClass     `json:"budget"`
	WindowMs int64                    `json:"window_ms"`
	Final    bool                     `json:"final,omitempty"`
	Rescue   bool                     `json:"rescue,omitempty"`
	Stop     protocol.Reason          `json:"stop,omitempty"`
	Sides    [2][]protocol.FamilySide `json:"sides"`
}

type goldenCase struct {
	Name      string        `json:"name"`
	PairClass string        `json:"pair_class"`
	SideA     protocol.Role `json:"side_a"`
	Rounds    []goldenRound `json:"rounds"`
}

// TestGoldenDecisionTable snapshots Classify -> Round over the pair
// classes, each round's outcome returning the decision's families with the
// mappings the coordinator would count. Run with -update to
// regenerate testdata/golden/*.json.
func TestGoldenDecisionTable(t *testing.T) {
	f := protocol.FamilyUDP4
	combos := []struct {
		name string
		a, b protocol.Traits
	}{
		{"easy", openTraits(f), openTraits(f)},
		{"open_x_edm", openTraits(f), seqTraits(f)},
		{"pdf_x_seq", pdfTraits(f), seqTraits(f)},
		{"pdf_x_rnd", pdfTraits(f), rndTraits(f)},
		{"seq_x_seq", seqTraits(f), seqTraits(f)},
		{"seq_x_rnd", seqTraits(f), rndTraits(f)},
		{"rnd_x_rnd", rndTraits(f), rndTraits(f)},
		{"pdf_x_pres", pdfTraits(f), presTraits(f)},
		{"pres_x_pres", presTraits(f), withObserved(presTraits(f), observedFor(f, 8))},
	}
	var p DefaultPlanner
	for _, c := range combos {
		t.Run(c.name, func(t *testing.T) {
			cl := p.Classify(classifyInput(c.a, c.b))
			gc := goldenCase{Name: c.name, PairClass: cl.PairClass, SideA: cl.SideA}
			var prev []RoundOutcome
			ledger := mappingLedger{}
			for round := 1; round <= 6; round++ {
				in := roundInput(cl, c.a, c.b, round, prev)
				in.AllowExtreme = true
				in.MaxRounds = 6
				in.Policy.Budget.Birthday = protocol.BirthdayAggressive
				in.HandshakeMs = 40000
				dec := p.Round(in)
				gc.Rounds = append(gc.Rounds, goldenRound{
					Round: round, Variant: dec.VariantName, Budget: dec.Budget,
					WindowMs: dec.Window.Milliseconds(), Final: dec.Final,
					Rescue: dec.Rescue, Stop: dec.Stop, Sides: dec.Sides,
				})
				if dec.Stop != "" {
					break
				}
				prev = append(prev, ledger.outcome(round, dec, RCNoContact))
				if dec.Final {
					break
				}
			}

			got, err := json.MarshalIndent(gc, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join("testdata", "golden", c.name+".json")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run with -update): %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("golden mismatch for %s; run: go test ./internal/plan -run TestGolden -update", c.name)
			}
		})
	}
}

// withObserved is t observed at a.
func withObserved(t protocol.Traits, a netip.AddrPort) protocol.Traits {
	t.Observed = a
	return t
}

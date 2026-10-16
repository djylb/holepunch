package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeKPI writes a kpi.json below root.
func writeKPI(t *testing.T, root, name string, k map[string]any) {
	t.Helper()
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func cellKPI(cell, ablation string, runs, ok int) map[string]any {
	return map[string]any{"cell": cell, "group": strings.Split(cell, "/")[0], "class": "must", "ablation": ablation,
		"runs": runs, "successes": ok, "success_rate": float64(ok) / float64(runs), "pass": true}
}

func runKPIAgg(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRender(t *testing.T) {
	dir := t.TempDir()
	writeKPI(t, dir, "nightly/v4__PRC-PRC.kpi.json", cellKPI("v4/PRC-PRC", "full", 20, 20))
	writeKPI(t, dir, "nightly/v4__PRC-SYMRND.kpi.json", cellKPI("v4/PRC-SYMRND", "full", 20, 5))
	writeKPI(t, dir, "nightly/notes.json", map[string]any{"ignored": true})
	jsonOut := filepath.Join(t.TempDir(), "base.json")
	code, out, stderr := runKPIAgg(t, "-dir", filepath.Join(dir, "nightly"), "-json", jsonOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"| v4/PRC-PRC | must | 20 | 20/20 |", "| v4/PRC-SYMRND | must | 20 | 5/20 |", "| PDF×RND | 1 | 25.0% |"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	b, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]baselineCell
	if err := json.Unmarshal(b, &base); err != nil || len(base) != 2 || base["v4/PRC-SYMRND"].SuccessRate != 0.25 {
		t.Fatalf("baseline %s: %v", b, err)
	}
	code, out, stderr = runKPIAgg(t, "-dir", filepath.Join(dir, "nightly"), "-baseline", jsonOut)
	if code != 0 || !strings.Contains(out, "| +0 pts |") {
		t.Fatalf("exit %d, stderr %q, output:\n%s", code, stderr, out)
	}
}

// TestRejectsBadInput checks that input which would skew the summary fails
// the run instead: duplicates, foreign JSON, no input at all.
func TestRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]map[string]any
		want  string
	}{
		{"duplicate cell", map[string]map[string]any{
			"nightly/a.kpi.json":  cellKPI("v4/PRC-PRC", "full", 20, 20),
			"ablation/a.kpi.json": cellKPI("v4/PRC-PRC", "", 20, 19),
		}, "are both v4/PRC-PRC"},
		{"same cell, other configurations", map[string]map[string]any{
			"ablation/a.kpi.json": cellKPI("v4/PRC-PRC", "full", 20, 20),
			"ablation/b.kpi.json": cellKPI("v4/PRC-PRC", "plain", 20, 19),
		}, ""},
		{"foreign json", map[string]map[string]any{"x.kpi.json": {"name": "other"}}, "not a kpi.json"},
		{"successes beyond runs", map[string]map[string]any{"x.kpi.json": cellKPI("v4/PRC-PRC", "full", 2, 3)}, "not a kpi.json"},
		{"nothing", nil, "no *.kpi.json file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, k := range tc.files {
				writeKPI(t, dir, name, k)
			}
			code, _, stderr := runKPIAgg(t, "-dir", dir)
			switch {
			case tc.want == "" && code != 0:
				t.Fatalf("exit %d: %s", code, stderr)
			case tc.want != "" && (code != 1 || !strings.Contains(stderr, tc.want)):
				t.Fatalf("exit %d, stderr %q; want 1 and %q", code, stderr, tc.want)
			}
		})
	}
}

func TestMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.kpi.json"), []byte(`{"cell": "v4/PRC-PRC", "runs": `), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runKPIAgg(t, "-dir", dir); code != 1 || !strings.Contains(stderr, "bad.kpi.json") {
		t.Fatalf("exit %d, stderr %q; want 1 naming the file", code, stderr)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"-bogus"}, {"-dir", ".", "extra"}} {
		if code, _, _ := runKPIAgg(t, args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
	if code, _, stderr := runKPIAgg(t, "-h"); code != 0 || !strings.Contains(stderr, "-dir") {
		t.Errorf("-h: exit %d, stderr %q; want 0 and the flags", code, stderr)
	}
}

// failingWriter fails every write, like a closed pipe.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestOutputError(t *testing.T) {
	dir := t.TempDir()
	writeKPI(t, dir, "a.kpi.json", cellKPI("v4/PRC-PRC", "full", 20, 20))
	var stderr bytes.Buffer
	if code := run([]string{"-dir", dir}, failingWriter{}, &stderr); code != 1 || !strings.Contains(stderr.String(), "broken pipe") {
		t.Fatalf("exit %d, stderr %q; want 1 and the write error", code, stderr.String())
	}
}

package main

import (
	"bytes"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// fixture is the module under testdata whose files carry `// want "rule"`
// markers on every line that must produce a diagnostic of that rule.
const fixture = "testdata/mod"

var wantMarker = regexp.MustCompile(`want "([a-z]+)"`)

// markers collects the want markers of every .go file under root (excluded
// files included, so that a marker in a file the checker skips shows up as
// a missing diagnostic) as "file:line: rule" → count.
func markers(t *testing.T, root string) map[string]int {
	t.Helper()
	out := map[string]int{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, g := range f.Comments {
			for _, c := range g.List {
				for _, m := range wantMarker.FindAllStringSubmatch(c.Text, -1) {
					out[fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), fset.Position(c.Pos()).Line, m[1])]++
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// lint runs the command in dir and parses its output into "file:line: rule"
// → count, keeping the full lines for failure messages.
func lint(t *testing.T, dir string, args ...string) (map[string]int, map[string]string, int, string) {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(abs, args, &stdout, &stderr)
	got := map[string]int{}
	lines := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 5)
		if len(parts) < 5 {
			t.Fatalf("malformed diagnostic %q", line)
		}
		key := fmt.Sprintf("%s:%s: %s", filepath.ToSlash(parts[0]), parts[1], strings.TrimSpace(parts[3]))
		got[key]++
		lines[key] = line
	}
	return got, lines, code, stderr.String()
}

// diff reports the markers without a diagnostic and the diagnostics without
// a marker.
func diff(want, got map[string]int, lines map[string]string) []string {
	var problems []string
	for k, n := range want {
		if got[k] != n {
			problems = append(problems, fmt.Sprintf("missing: %s (want %d, got %d)", k, n, got[k]))
		}
	}
	for k, n := range got {
		if want[k] != n {
			problems = append(problems, fmt.Sprintf("unexpected: %s", lines[k]))
		}
	}
	sort.Strings(problems)
	return problems
}

// TestFixture checks that diagnostics and markers match one to one, and that
// every rule is exercised.
func TestFixture(t *testing.T) {
	want := markers(t, fixture)
	got, lines, code, stderr := lint(t, fixture, "./...")
	if problems := diff(want, got, lines); len(problems) > 0 {
		t.Fatalf("fixture mismatch:\n%s\nstderr:\n%s", strings.Join(problems, "\n"), stderr)
	}
	if code != 1 {
		t.Fatalf("exit status %d with diagnostics, want 1", code)
	}
	for _, rule := range allRules() {
		found := false
		for k := range want {
			if strings.HasSuffix(k, " "+rule) {
				found = true
			}
		}
		if !found {
			t.Errorf("no fixture marker exercises rule %s", rule)
		}
	}
}

// TestPatternsSelectPackages checks package selection, and that facts from
// packages outside the selection (callback names, writes) still apply.
func TestPatternsSelectPackages(t *testing.T) {
	all := markers(t, fixture)
	under := func(prefix string) map[string]int {
		out := map[string]int{}
		for k, n := range all {
			if strings.HasPrefix(k, prefix) {
				out[k] = n
			}
		}
		return out
	}
	for _, tc := range []struct {
		args []string
		want map[string]int
	}{
		{[]string{"./internal/life"}, under("internal/life/")},
		{[]string{"./internal/..."}, under("internal/")},
		{[]string{"./coord"}, under("coord/")},
		{[]string{"./coord", "./internal/conf"}, union2(under("coord/"), under("internal/conf/"))},
		{[]string{"example.com/mod/natprobe"}, map[string]int{}},
	} {
		got, lines, code, stderr := lint(t, fixture, tc.args...)
		if problems := diff(tc.want, got, lines); len(problems) > 0 {
			t.Errorf("%v:\n%s\nstderr:\n%s", tc.args, strings.Join(problems, "\n"), stderr)
		}
		if wantCode := map[bool]int{true: 1, false: 0}[len(tc.want) > 0]; code != wantCode {
			t.Errorf("%v: exit status %d, want %d", tc.args, code, wantCode)
		}
	}
}

func union2(a, b map[string]int) map[string]int {
	out := map[string]int{}
	for k, n := range a {
		out[k] = n
	}
	for k, n := range b {
		out[k] = n
	}
	return out
}

func TestRunFromSubdirectory(t *testing.T) {
	got, _, code, stderr := lint(t, filepath.Join(fixture, "coord"), ".")
	if code != 1 || len(got) != 4 {
		t.Fatalf("exit %d, %d diagnostics from coord/, want 1 and 4; stderr: %s", code, len(got), stderr)
	}
	for k := range got {
		if !strings.HasPrefix(k, "coord.go:") {
			t.Fatalf("diagnostic path %q is not relative to the working directory", k)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		code   int
		stderr string
	}{
		{[]string{"../.."}, 2, "outside module"},
		{[]string{"./tools/gen"}, 2, "no library package"},
		{[]string{"./e2e"}, 2, "no library package"},
		{[]string{"./nested"}, 2, "no library package"},
		{[]string{"./missing/..."}, 0, `"./missing/..." matched no packages`},
		{[]string{"-bogus"}, 2, "usage"},
	} {
		_, _, code, stderr := lint(t, fixture, tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.stderr) {
			t.Errorf("%v: exit %d, stderr %q; want %d and %q", tc.args, code, stderr, tc.code, tc.stderr)
		}
	}
}

// TestBrokenPackage checks that a package that does not parse fails the run
// only when it is requested.
func TestBrokenPackage(t *testing.T) {
	root := t.TempDir()
	write := func(name, src string) {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/broken\n")
	write("good/good.go", "package good\n\nimport \"time\"\n\nfunc f() { time.Sleep(1) }\n")
	write("bad/bad.go", "package bad\n\nfunc {\n")

	got, _, code, stderr := lint(t, root, "./good")
	if code != 1 || len(got) != 1 || got["good/good.go:5: nosleep"] != 1 || !strings.Contains(stderr, "skipping") {
		t.Fatalf("./good: exit %d, %v, stderr %q; want the diagnostic and a warning about bad", code, got, stderr)
	}
	if _, _, code, _ := lint(t, root, "./bad"); code != 2 {
		t.Fatalf("./bad: exit %d, want 2", code)
	}
}

func TestProductionFiles(t *testing.T) {
	for line, want := range map[string]bool{
		"":                                  true,
		"//go:build linux":                  true,
		"//go:build !linux && !windows":     true,
		"//go:build holepunch_faultinject":  false,
		"//go:build !holepunch_faultinject": true,
		"//go:build holepunch_faultinject && linux":              false,
		"//go:build holepunch_faultinject || linux":              true,
		"//go:build ignore":                                      false,
		"//go:build linux && !linux":                             false,
		"//go:build purego || !purego":                           true,
		"//go:build (linux || darwin) && !holepunch_faultinject": true,
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "f.go", line+"\n\npackage p\n", parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		if got := production(f); got != want {
			t.Errorf("%q: production = %v, want %v", line, got, want)
		}
	}
}

func TestParseDirective(t *testing.T) {
	for text, want := range map[string][3]string{
		"//holepunch:callback":               {"callback", "", "ok"},
		"//holepunch:netimpl // why":         {"netimpl", "", "ok"},
		"//holepunch:netimpl\t// why":        {"netimpl", "", "ok"},
		"//holepunch:netimpl extra":          {"netimpl", "extra", "ok"},
		"//holepunch:":                       {"", "", "ok"},
		"// holepunch:callback":              {"", "", ""},
		"/*holepunch:callback*/":             {"", "", ""},
		"//holepunch:callback extra // note": {"callback", "extra // note", "ok"},
	} {
		name, rest, ok := parseDirective(text)
		if got := [3]string{name, rest, map[bool]string{true: "ok"}[ok]}; got != want {
			t.Errorf("parseDirective(%q) = %q, want %q", text, got, want)
		}
	}
}

// TestInfrastructureIsClean lints the packages that ship with this tool's
// own change, as `go run ./tools/lintcheck` does in CI.
func TestInfrastructureIsClean(t *testing.T) {
	var stdout, stderr bytes.Buffer
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	code := run(wd, []string{"../../clock/...", "../../internal/faultinject/...", "../../internal/leak/...", "../../internal/ablation/..."}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d:\n%s%s", code, stdout.String(), stderr.String())
	}
}

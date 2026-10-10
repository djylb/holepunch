package faultinject_test

import (
	"bufio"
	"bytes"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// callInstr matches a CALL instruction line of -gcflags=-S output and captures
// the callee, e.g. "(zerocost.go:9)\tCALL\tgithub.com/.../faultinject.Point(SB)".
var callInstr = regexp.MustCompile(`\)\s+CALL\s+(\S+)`)

// TestPointCompilesAway compiles testdata/zerocost with -gcflags=-S in both
// build modes. Without the tag the hot function must contain no call at all:
// Point was inlined and the guarded branch, errors.Is included, eliminated.
// With the tag it must call Point, which proves that the assertion looks at
// the right code.
func TestPointCompilesAway(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go command not found: %v", err)
	}
	for _, tc := range []struct {
		name     string
		tags     []string
		wantCall bool
	}{
		{name: "default", wantCall: false},
		{name: "tagged", tags: []string{"-tags", "holepunch_faultinject"}, wantCall: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"build", "-gcflags=-S"}, tc.tags...)
			args = append(args, "./testdata/zerocost")
			out, err := exec.Command(gobin, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
			}
			calls := callsIn(t, out, "zerocost.Hot")
			hasPoint := false
			for _, c := range calls {
				hasPoint = hasPoint || strings.Contains(c, "faultinject.Point")
			}
			if hasPoint != tc.wantCall {
				t.Fatalf("call to faultinject.Point present = %v, want %v; calls: %v", hasPoint, tc.wantCall, calls)
			}
			if !tc.wantCall && len(calls) > 0 {
				t.Fatalf("the guarded branch was not eliminated; calls: %v", calls)
			}
		})
	}
}

// callsIn returns the callees of the CALL instructions in the assembly of the
// function whose symbol ends in fn.
func callsIn(t *testing.T, asm []byte, fn string) []string {
	t.Helper()
	var calls []string
	in, found := false, false
	sc := bufio.NewScanner(bytes.NewReader(asm))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line != "" && line[0] != '\t' && line[0] != ' ' {
			// A symbol header starts a new function.
			fields := strings.Fields(line)
			in = len(fields) > 1 && strings.HasSuffix(fields[0], fn) && fields[1] == "STEXT"
			found = found || in
			continue
		}
		if in {
			if m := callInstr.FindStringSubmatch(line); m != nil {
				calls = append(calls, m[1])
			}
		}
	}
	if !found {
		t.Fatalf("no assembly for %s in compiler output:\n%s", fn, asm)
	}
	return calls
}

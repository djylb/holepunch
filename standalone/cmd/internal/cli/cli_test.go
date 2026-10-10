package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"strings"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func TestStringList(t *testing.T) {
	var l StringList
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.Var(&l, "v", "")
	if err := fs.Parse([]string{"-v", "a", "-v", " ", "-v", " b "}); err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 || l[1] != "b" || l.String() != "a,b" {
		t.Fatalf("%q", l)
	}
}

func TestLoggerAndSignals(t *testing.T) {
	if !Logger(true).Enabled(context.Background(), -4) || Logger(false).Enabled(context.Background(), -4) {
		t.Fatal("debug level")
	}
	ctx, stop := SignalContext()
	stop()
	<-ctx.Done()
}

func TestStatus(t *testing.T) {
	var w bytes.Buffer
	if Status(&w, "cmd", nil) != 0 || Status(&w, "cmd", flag.ErrHelp) != 0 || w.Len() != 0 {
		t.Fatalf("nil and -h: %q", w.String())
	}
	if Status(&w, "cmd", errors.New("boom")) != 1 || w.String() != "cmd: boom\n" {
		t.Fatalf("error: %q", w.String())
	}
}

func TestDispatch(t *testing.T) {
	var got []string
	cmds := map[string]func([]string) error{
		"run":  func(args []string) error { got = args; return nil },
		"fail": func([]string) error { return errors.New("boom") },
	}
	for _, c := range []struct {
		args           []string
		status         int
		stdout, stderr string
	}{
		{nil, 2, "", "USAGE"},
		{[]string{"-h"}, 0, "USAGE", ""},
		{[]string{"--help"}, 0, "USAGE", ""},
		{[]string{"help"}, 0, "USAGE", ""},
		{[]string{"nope"}, 2, "", `cmd: unknown command "nope"`},
		{[]string{"run", "-x", "y"}, 0, "", ""},
		{[]string{"fail"}, 1, "", "cmd: boom"},
	} {
		var stdout, stderr bytes.Buffer
		status := dispatch(&stdout, &stderr, "cmd", "USAGE", c.args, cmds)
		if status != c.status || !strings.Contains(stdout.String(), c.stdout) || !strings.Contains(stderr.String(), c.stderr) ||
			(c.stdout == "" && stdout.Len() != 0) || (c.stderr == "" && stderr.Len() != 0) {
			t.Errorf("%q: status %d, stdout %q, stderr %q", c.args, status, stdout.String(), stderr.String())
		}
	}
	if len(got) != 2 || got[0] != "-x" {
		t.Fatalf("subcommand args %q", got)
	}
}

package cli

import (
	"context"
	"flag"
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

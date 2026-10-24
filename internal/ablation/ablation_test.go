package ablation_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/internal/goroutines"
)

func TestMain(m *testing.M) {
	goroutines.VerifyTestMain(m)
}

// specSwitches is the list of control-link switches, in order; allSwitches
// adds the transport and latency switches outside it.
var (
	specSwitches = []string{
		"SinglePortProbe", "NoRTTAlign", "NoRoleAssign", "NoAssistRelay", "NoSandwich",
		"NoRefresh", "NoRounds", "NoMemory", "NoEarlyAbort", "NoPrediction",
	}
	allSwitches = append(append([]string(nil), specSwitches...), "NoOpener", "NoEagerGo")
)

func TestSetMatchesSpec(t *testing.T) {
	typ := reflect.TypeFor[ablation.Set]()
	if typ.NumField() != len(allSwitches) {
		t.Fatalf("Set has %d fields, spec has %d switches", typ.NumField(), len(allSwitches))
	}
	for i, name := range allSwitches {
		f := typ.Field(i)
		if f.Name != name || f.Type.Kind() != reflect.Bool || !f.IsExported() {
			t.Fatalf("field %d is %s %s, want exported bool %s", i, f.Name, f.Type, name)
		}
	}
}

func TestPlainSetsEverySwitch(t *testing.T) {
	v := reflect.ValueOf(ablation.Plain())
	for i := range v.NumField() {
		if !v.Field(i).Bool() {
			t.Fatalf("Plain leaves %s unset", v.Type().Field(i).Name)
		}
	}
	if got := ablation.Plain().String(); got != "plain" {
		t.Fatalf("Plain().String() = %s", got)
	}
}

func TestSinglesSetExactlyOneSwitchEach(t *testing.T) {
	singles := ablation.Singles()
	if len(singles) != len(specSwitches) {
		t.Fatalf("%d singles, want %d", len(singles), len(specSwitches))
	}
	for i, s := range singles {
		v := reflect.ValueOf(s)
		for j := range v.NumField() {
			if v.Field(j).Bool() != (i == j) {
				t.Fatalf("single %d has %s = %v", i, specSwitches[j], v.Field(j).Bool())
			}
		}
		if s.String() != specSwitches[i] {
			t.Fatalf("single %d String = %q, want %q", i, s.String(), specSwitches[i])
		}
	}
}

func TestString(t *testing.T) {
	for s, want := range map[ablation.Set]string{
		{}:                               "full",
		ablation.Plain():                 "plain",
		{NoRounds: true, NoMemory: true}: "NoRounds+NoMemory",
		{SinglePortProbe: true}:          "SinglePortProbe",
		{NoOpener: true}:                 "NoOpener",
	} {
		if got := s.String(); got != want {
			t.Errorf("String = %q, want %q", got, want)
		}
	}
	every := ablation.Plain()
	every.NoOpener, every.NoEagerGo = false, false
	if got, want := every.String(), strings.Join(specSwitches, "+"); got != want {
		t.Errorf("String = %q, want %q", got, want)
	}
}

func TestContextRoundTrip(t *testing.T) {
	if got := ablation.From(context.Background()); got != (ablation.Set{}) {
		t.Fatalf("From(Background) = %v, want full", got)
	}
	// A context that is nil by mistake must not crash library code.
	var nilCtx context.Context
	if got := ablation.From(nilCtx); got != (ablation.Set{}) {
		t.Fatalf("From(nil) = %v", got)
	}
	s := ablation.Set{NoAssistRelay: true}
	ctx := ablation.With(context.Background(), s)
	if got := ablation.From(ctx); got != s {
		t.Fatalf("From = %v, want %v", got, s)
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	if got := ablation.From(child); got != s {
		t.Fatalf("derived context lost the set: %v", got)
	}
	if got := ablation.From(ablation.With(ctx, ablation.Plain())); got != ablation.Plain() {
		t.Fatalf("inner With did not override: %v", got)
	}
	if got := ablation.From(ablation.With(nilCtx, s)); got != s {
		t.Fatalf("With(nil) = %v", got)
	}
}

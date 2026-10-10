package life

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// stackMarkers are substrings that only appear in a goroutine stack dump.
var stackMarkers = []string{"goroutine ", "runtime/debug.Stack", ".go:", "panic.go"}

func capturePanic(t *testing.T, v any) *PanicError {
	t.Helper()
	err := Safe("cb:user", func() { panic(v) })
	var perr *PanicError
	if !errors.As(err, &perr) {
		t.Fatalf("Safe = %v, want *PanicError", err)
	}
	return perr
}

func TestSafeReturnsNilWithoutPanic(t *testing.T) {
	ran := false
	if err := Safe("x", func() { ran = true }); err != nil || !ran {
		t.Fatalf("Safe = %v, ran = %v", err, ran)
	}
}

func TestSafeRecoversRuntimeErrors(t *testing.T) {
	err := Safe("nil-map", func() {
		var m map[string]int
		m["x"] = 1
	})
	var perr *PanicError
	if !errors.As(err, &perr) || perr.Where() != "nil-map" {
		t.Fatalf("Safe = %v", err)
	}
}

func TestPanicErrorTextHasNoStack(t *testing.T) {
	perr := capturePanic(t, "secret-free value")
	if len(perr.Stack()) == 0 {
		t.Fatal("Stack is empty")
	}
	var textBuf, jsonBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&textBuf, nil)).Error("x", "err", perr, "any", any(perr))
	slog.New(slog.NewJSONHandler(&jsonBuf, nil)).Error("x", "err", perr)
	js, err := json.Marshal(perr)
	if err != nil {
		t.Fatal(err)
	}
	forms := map[string]string{
		"Error":       perr.Error(),
		"%v":          fmt.Sprintf("%v", perr),
		"%+v":         fmt.Sprintf("%+v", perr),
		"%#v":         fmt.Sprintf("%#v", perr),
		"%s":          fmt.Sprintf("%s", perr),
		"%q":          fmt.Sprintf("%q", perr),
		"%d":          fmt.Sprintf("%d", perr),
		"%x":          fmt.Sprintf("%x", perr),
		"value %v":    fmt.Sprintf("%v", *perr),
		"value %+v":   fmt.Sprintf("%+v", *perr),
		"wrapped %+v": fmt.Sprintf("%+v", fmt.Errorf("outer: %w", perr)),
		"join":        errors.Join(errors.New("a"), perr).Error(),
		"json":        string(js),
		"slog text":   textBuf.String(),
		"slog json":   jsonBuf.String(),
	}
	for name, s := range forms {
		for _, m := range stackMarkers {
			if strings.Contains(s, m) {
				t.Errorf("%s contains stack marker %q: %s", name, m, s)
			}
		}
	}
	if !strings.Contains(perr.Error(), "cb:user") || !strings.Contains(perr.Error(), "secret-free value") {
		t.Fatalf("Error() = %q", perr.Error())
	}
}

func TestPanicValueSummary(t *testing.T) {
	long := capturePanic(t, strings.Repeat("é", 500)).Error()
	if n := len(long); n > len("panic in cb:user: ")+maxPanicText+len("...") {
		t.Fatalf("Error length %d exceeds the summary bound", n)
	}
	if !strings.HasSuffix(long, "é...") {
		t.Fatalf("truncation must keep whole runes and mark the cut: %q", long[len(long)-8:])
	}
	if got := capturePanic(t, "first line\nsecond line").Error(); got != "panic in cb:user: first line..." {
		t.Fatalf("multi-line value = %q", got)
	}
	if got := capturePanic(t, string([]byte{'a', 0xff, 'b'})).Error(); !strings.HasSuffix(got, "a\uFFFDb") {
		t.Fatalf("invalid UTF-8 not repaired: %q", got)
	}
	if got := capturePanic(t, panickyStringer{}).Error(); !strings.Contains(got, "String exploded") {
		t.Fatalf("unprintable value = %q", got)
	}
}

type panickyStringer struct{}

func (panickyStringer) String() string { panic("String exploded") }

func TestPanicErrorJSONIsErrorText(t *testing.T) {
	perr := capturePanic(t, "v")
	js, err := json.Marshal(map[string]any{"err": perr})
	if err != nil {
		t.Fatal(err)
	}
	if string(js) != `{"err":"panic in cb:user: v"}` {
		t.Fatalf("json = %s", js)
	}
}

func TestPanicErrorStackIsACopy(t *testing.T) {
	perr := capturePanic(t, "v")
	s := perr.Stack()
	if len(s) == 0 || len(s) > maxPanicStack {
		t.Fatalf("stack length %d", len(s))
	}
	s[0] ^= 0xff
	if perr.Stack()[0] == s[0] {
		t.Fatal("Stack returned the internal buffer")
	}
}

func TestPanicErrorUnwrap(t *testing.T) {
	perr := capturePanic(t, fmt.Errorf("wrapped: %w", io.EOF))
	if !errors.Is(perr, io.EOF) {
		t.Fatal("errors.Is does not see the panic value")
	}
	// A panic(context.Canceled) looks like a cancellation to errors.Is; this is
	// why callers test for *PanicError first.
	perr = capturePanic(t, context.Canceled)
	if !errors.Is(perr, context.Canceled) {
		t.Fatal("errors.Is(panic(context.Canceled), context.Canceled) = false")
	}
	if capturePanic(t, 42).Unwrap() != nil {
		t.Fatal("non-error panic value unwrapped to an error")
	}
}

func TestPanicNilIsRecovered(t *testing.T) {
	err := Safe("nil", func() { panic(nil) })
	var perr *PanicError
	if !errors.As(err, &perr) {
		t.Fatalf("Safe(panic(nil)) = %v", err)
	}
}

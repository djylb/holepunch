package life

import (
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits on what a PanicError retains. The value summary travels in error
// strings (and from there into wire details), so it is short; the stack is
// for local logs only.
const (
	maxPanicText  = 200
	maxPanicStack = 4 << 10
)

// PanicError is a panic recovered by Group.Go or Safe.
//
// Every textual form of a PanicError — Error, any fmt verb including %#v and
// %d, encoding/json and other TextMarshaler users, log/slog, errors.Join —
// contains only the location and a short summary of the panic value. The
// stack trace is reachable only through Stack, so it cannot leak into wire
// frames or error details by accident.
type PanicError struct {
	where string
	value any
	text  string
	stack []byte
}

func newPanicError(where string, r any) *PanicError {
	return &PanicError{
		where: where,
		value: r,
		text:  summarize(r),
		stack: truncateBytes(debug.Stack(), maxPanicStack),
	}
}

// Error reports the location and a summary of the panic value, without the stack.
func (e PanicError) Error() string { return "panic in " + e.where + ": " + e.text }

// MarshalText makes encoding/json and similar encoders emit the Error text.
func (e PanicError) MarshalText() ([]byte, error) { return []byte(e.Error()), nil }

// Where names the goroutine or callback that panicked, as given to Go or Safe.
func (e PanicError) Where() string { return e.where }

// Stack returns a copy of the stack captured when the panic was recovered,
// truncated to 4 KiB. It is meant for local logs only.
func (e PanicError) Stack() []byte { return append([]byte(nil), e.stack...) }

// Unwrap returns the panic value when it is an error, so errors.Is and
// errors.As see through a panic(err). Code that maps causes to reasons must
// therefore test for *PanicError before testing for sentinel errors such as
// context.Canceled.
func (e PanicError) Unwrap() error {
	err, _ := e.value.(error)
	return err
}

// GoString keeps %#v free of the stack.
func (e PanicError) GoString() string {
	return "&life.PanicError{where:" + strconv.Quote(e.where) + ", value:" + strconv.Quote(e.text) + "}"
}

// Format implements fmt.Formatter so that no verb prints the struct fields
// (and with them the stack bytes).
func (e PanicError) Format(f fmt.State, verb rune) {
	switch {
	case verb == 'v' && f.Flag('#'):
		_, _ = f.Write([]byte(e.GoString()))
	case verb == 'q':
		_, _ = f.Write([]byte(strconv.Quote(e.Error())))
	default:
		_, _ = f.Write([]byte(e.Error()))
	}
}

// Safe calls fn and converts a panic into a *PanicError named where.
// It is the recover boundary for user callbacks, user implementations of
// interfaces, timer callbacks and individual cleanup steps. Safe never
// re-panics. Since fn runs user code, Safe must not be called with a mutex
// held.
//
//holepunch:callback
func Safe(where string, fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = newPanicError(where, r)
		}
	}()
	fn()
	return nil
}

// summarize renders the first line of the panic value, at most maxPanicText
// bytes of valid UTF-8, with "..." when something was cut.
func summarize(r any) (s string) {
	defer func() {
		// A value whose String or Error method panics must not escape the
		// boundary that is describing it.
		if recover() != nil {
			s = fmt.Sprintf("%T (unprintable)", r)
		}
	}()
	s = fmt.Sprint(r)
	cut := false
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s, cut = s[:i], true
	}
	if len(s) > maxPanicText {
		n := maxPanicText
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s, cut = s[:n], true
	}
	s = strings.ToValidUTF8(s, "\uFFFD")
	if cut {
		s += "..."
	}
	return s
}

func truncateBytes(b []byte, limit int) []byte {
	if len(b) > limit {
		return b[:limit]
	}
	return b
}

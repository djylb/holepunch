package trunc

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestString(t *testing.T) {
	cases := []struct {
		s    string
		n    int
		want string
	}{
		{"short", 8, "short"},
		{"exact", 5, "exact"},
		{"abcdef", 3, "abc"},
		{"ab€", 3, "ab"},          // € is 3 bytes: none of it fits
		{"ab€", 4, "ab"},          // two of its bytes would
		{"ab€", 5, "ab€"},         // all of it
		{"€€", 3, "€"},            // a whole rune at the limit
		{"x", 0, ""},              // nothing fits
		{"x", -1, ""},             // a negative limit is 0
		{"\xff\xfe", 1, ""},       // invalid bytes become one U+FFFD, which does not fit
		{"a\xffb", 8, "a\uFFFDb"}, // and are replaced although the text fits
	}
	for _, c := range cases {
		if got := String(c.s, c.n); got != c.want {
			t.Errorf("String(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
	long := strings.Repeat("日本", 100)
	for n := range 64 {
		got := String(long, n)
		if len(got) > n || !utf8.ValidString(got) || !strings.HasPrefix(long, got) || n-len(got) > 2 {
			t.Fatalf("String(long, %d) = %q", n, got)
		}
	}
}

// A truncated string stays within its limit after a round trip through
// JSON, which replaces invalid bytes with U+FFFD.
func TestStringJSONRoundTrip(t *testing.T) {
	for _, s := range []string{strings.Repeat("\x80", 300), "ok" + strings.Repeat("\xff€", 100), strings.Repeat("€", 100)} {
		cut := String(s, 256)
		b, err := json.Marshal(cut)
		if err != nil {
			t.Fatal(err)
		}
		var back string
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if len(back) > 256 || !utf8.ValidString(cut) {
			t.Fatalf("%q: %d bytes after a JSON round trip", cut, len(back))
		}
	}
}

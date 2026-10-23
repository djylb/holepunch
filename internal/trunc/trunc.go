// Package trunc cuts text to a byte limit on a rune boundary. It depends on
// the standard library only, so that every package of the module may use it.
package trunc

import (
	"strings"
	"unicode/utf8"
)

// String is s cut to at most n bytes without splitting a rune: the cut
// moves back to the start of the rune that would straddle the limit. Invalid
// UTF-8 is first replaced with U+FFFD, as a JSON encoder would replace it, so
// that the result keeps within n bytes after a round trip through JSON. s
// itself is returned when it is valid and fits.
func String(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	if len(s) <= n {
		return s
	}
	n = max(n, 0)
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

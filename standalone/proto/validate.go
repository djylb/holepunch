package proto

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

// Field limits. They keep every message far below MaxPayload.
const (
	MaxNameLen      = 64  // host and dialer IDs, session IDs, metadata keys
	MaxSecretLen    = 128 // auth tokens, credentials, tickets
	MaxMetadata     = 16  // metadata entries per map
	MaxMetaValueLen = 256
	MaxTextLen      = 256 // Fail.Message, Transport.Detail
	MaxTargets      = 32  // AccessPolicy.Targets
	MaxTargetLen    = 261 // "[" + 45-byte IPv6 literal or 253-byte name + "]:65535", rounded

	MinHeartbeatMs = 1000
	MaxHeartbeatMs = 300000
)

func invalid(field, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalid, field, fmt.Sprintf(format, args...))
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// ValidName reports whether s is a valid host or dialer ID:
// [A-Za-z0-9._-]{1,64}.
func ValidName(s string) bool {
	if s == "" || len(s) > MaxNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func checkName(field, s string, required bool) error {
	if s == "" && !required {
		return nil
	}
	if !ValidName(s) {
		return invalid(field, "want [A-Za-z0-9._-]{1,%d}", MaxNameLen)
	}
	return nil
}

// checkSessionID applies holepunch's session ID syntax, [A-Za-z0-9_-]{1,64}.
func checkSessionID(field, s string) error {
	if s == "" || len(s) > MaxNameLen {
		return invalid(field, "want 1..%d bytes", MaxNameLen)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isAlnum(c) && c != '_' && c != '-' {
			return invalid(field, "want [A-Za-z0-9_-]")
		}
	}
	return nil
}

// checkSecret accepts printable ASCII without spaces, at most MaxSecretLen
// bytes.
func checkSecret(field, s string, required bool) error {
	if s == "" {
		if required {
			return invalid(field, "missing")
		}
		return nil
	}
	if len(s) > MaxSecretLen {
		return invalid(field, "%d bytes > %d", len(s), MaxSecretLen)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return invalid(field, "want printable ASCII without spaces")
		}
	}
	return nil
}

func checkText(field, s string) error {
	if len(s) > MaxTextLen {
		return invalid(field, "%d bytes > %d", len(s), MaxTextLen)
	}
	return checkPrintable(field, s)
}

func checkPrintable(field, s string) error {
	if !utf8.ValidString(s) {
		return invalid(field, "not UTF-8")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return invalid(field, "control character")
		}
	}
	return nil
}

func checkMetadata(field string, m map[string]string) error {
	if len(m) > MaxMetadata {
		return invalid(field, "%d entries > %d", len(m), MaxMetadata)
	}
	for k, v := range m {
		if !ValidName(k) {
			return invalid(field, "key wants [A-Za-z0-9._-]{1,%d}", MaxNameLen)
		}
		if len(v) > MaxMetaValueLen {
			return invalid(field+"."+k, "%d bytes > %d", len(v), MaxMetaValueLen)
		}
		if err := checkPrintable(field+"."+k, v); err != nil {
			return err
		}
	}
	return nil
}

func checkHeartbeat(field string, ms uint32) error {
	if ms < MinHeartbeatMs || ms > MaxHeartbeatMs {
		return invalid(field, "%d outside [%d, %d]", ms, MinHeartbeatMs, MaxHeartbeatMs)
	}
	return nil
}

func checkCode(field string, c Code) error {
	s := string(c)
	if s == "" || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return invalid(field, "want [a-z][a-z0-9_]{0,31}")
	}
	for i := 1; i < len(s); i++ {
		if ch := s[i]; !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_') {
			return invalid(field, "want [a-z][a-z0-9_]{0,31}")
		}
	}
	return nil
}

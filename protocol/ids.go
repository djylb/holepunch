package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
)

// Token is the session token of punch_start: 32 random bytes, the input key
// material of the session's UDP key. On the wire it is
// base64url without padding. Its String and every fmt verb print a fixed
// placeholder, so a token cannot reach a log by accident; only MarshalText
// produces the wire form.
type Token [32]byte

// RouteID is the session route of punch_start.wire: 16 random bytes, the HKDF
// salt and natprobe's lookup key. On the wire it is base64url without
// padding; String shows only the first 4 hex digits.
type RouteID [16]byte

// NewToken returns a random token.
func NewToken() Token {
	var t Token
	_, _ = rand.Read(t[:]) // crypto/rand.Read never fails (Go 1.24+)
	return t
}

// NewRouteID returns a random route.
func NewRouteID() RouteID {
	var r RouteID
	_, _ = rand.Read(r[:])
	return r
}

// IsZero reports whether t is unset.
//
//goland:noinspection GoMixedReceiverTypes
func (t Token) IsZero() bool { return t == Token{} }

// String hides the token.
//
//goland:noinspection GoMixedReceiverTypes
func (Token) String() string { return "[token]" }

// GoString hides the token from %#v as well.
//
//goland:noinspection GoMixedReceiverTypes
func (Token) GoString() string { return "protocol.Token{…}" }

// Format hides the token from every fmt verb.
//
//goland:noinspection GoMixedReceiverTypes
func (t Token) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(t.String())) }

// LogValue hides the token from log/slog, which would otherwise use
// MarshalText.
//
//goland:noinspection GoMixedReceiverTypes
func (t Token) LogValue() slog.Value { return slog.StringValue(t.String()) }

// MarshalText returns the wire form: base64url without padding.
//
//goland:noinspection GoMixedReceiverTypes
func (t Token) MarshalText() ([]byte, error) { return encodeKey(t[:]), nil }

// UnmarshalText accepts exactly the canonical base64url of 32 bytes.
//
//goland:noinspection GoMixedReceiverTypes
func (t *Token) UnmarshalText(b []byte) error { return decodeKey("token", b, t[:]) }

// IsZero reports whether r is unset.
//
//goland:noinspection GoMixedReceiverTypes
func (r RouteID) IsZero() bool { return r == RouteID{} }

// String returns the loggable prefix of the route: its first 4 hex digits.
//
//goland:noinspection GoMixedReceiverTypes
func (r RouteID) String() string { return hex.EncodeToString(r[:2]) }

// GoString keeps %#v to the loggable prefix.
//
//goland:noinspection GoMixedReceiverTypes
func (r RouteID) GoString() string { return "protocol.RouteID{" + r.String() + "…}" }

// Format keeps every fmt verb to the loggable prefix.
//
//goland:noinspection GoMixedReceiverTypes
func (r RouteID) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(r.String())) }

// LogValue keeps log/slog to the loggable prefix.
//
//goland:noinspection GoMixedReceiverTypes
func (r RouteID) LogValue() slog.Value { return slog.StringValue(r.String()) }

// MarshalText returns the wire form: base64url without padding.
//
//goland:noinspection GoMixedReceiverTypes
func (r RouteID) MarshalText() ([]byte, error) { return encodeKey(r[:]), nil }

// UnmarshalText accepts exactly the canonical base64url of 16 bytes.
//
//goland:noinspection GoMixedReceiverTypes
func (r *RouteID) UnmarshalText(b []byte) error { return decodeKey("route_id", b, r[:]) }

func encodeKey(k []byte) []byte {
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(k)))
	base64.RawURLEncoding.Encode(out, k)
	return out
}

// decodeKey decodes strict (canonical) base64url without padding into dst,
// which it fills exactly. An empty string leaves dst zero: Validate reports
// the field as missing.
func decodeKey(what string, b, dst []byte) error {
	if len(b) == 0 {
		clear(dst)
		return nil
	}
	enc := base64.RawURLEncoding.Strict()
	if enc.DecodedLen(len(b)) != len(dst) {
		return fmt.Errorf("protocol: %s: want base64url of %d bytes, got %d characters", what, len(dst), len(b))
	}
	var tmp [32]byte
	n, err := enc.Decode(tmp[:], b)
	if err != nil || n != len(dst) {
		return fmt.Errorf("protocol: %s: not canonical base64url", what)
	}
	copy(dst, tmp[:n])
	return nil
}

// WireSpec is punch_start.wire: the session route and the session's random
// plaintext length range for client-to-client UDP packets.
type WireSpec struct {
	RouteID    RouteID `json:"route_id"`    // base64url of exactly 16 bytes
	PayloadMin uint16  `json:"payload_min"` // server: U[48, 160]; client clamps to [48, 1024]
	PayloadMax uint16  `json:"payload_max"` // server: PayloadMin + U[64, 256]; client clamps to [PayloadMin, 1024]
}

// Wire length limits.
const (
	minPayloadLen = 48
	maxPayloadLen = 1024
)

// Normalize returns w with the payload range clamped to [48, 1024] and max
// >= min, and whether a value changed.
func (w WireSpec) Normalize() (WireSpec, bool) {
	pmin := min(max(w.PayloadMin, minPayloadLen), maxPayloadLen)
	pmax := min(max(w.PayloadMax, pmin), maxPayloadLen)
	changed := pmin != w.PayloadMin || pmax != w.PayloadMax
	w.PayloadMin, w.PayloadMax = pmin, pmax
	return w, changed
}

// NewSessionID returns a random session id: base64url of 18 bytes, 24
// characters of [A-Za-z0-9_-].
func NewSessionID() string {
	var b [18]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// NewWireSpec returns a fresh wire spec: a random route, payload_min ∈
// U[48, 160] and payload_max = payload_min + U[64, 256].
func NewWireSpec() WireSpec {
	pmin := uint16(minPayloadLen + randomBelow(160-minPayloadLen+1))
	return WireSpec{
		RouteID:    NewRouteID(),
		PayloadMin: pmin,
		PayloadMax: min(pmin+uint16(64+randomBelow(256-64+1)), maxPayloadLen),
	}
}

// randomBelow is uniform in [0, n) for 0 < n <= 1<<16, by rejection sampling.
func randomBelow(n uint32) uint32 {
	limit := (1 << 32) / uint64(n) * uint64(n) // largest multiple of n not above 2^32
	var b [4]byte
	for {
		_, _ = rand.Read(b[:])
		if v := binary.BigEndian.Uint32(b[:]); uint64(v) < limit {
			return v % n
		}
	}
}

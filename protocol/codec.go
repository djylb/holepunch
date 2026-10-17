package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"unicode/utf8"
)

// ErrUnexpectedMessage is returned when the frame's type is not the one
// expected (Unmarshal), or not a message type at all (Decode).
var ErrUnexpectedMessage = errors.New("protocol: unexpected message")

// ValidationError is a message or argument that cannot be accepted. Reason is
// the code to report (protocol_violation, control_version_mismatch for version
// fields, invalid_argument for a caller's argument) and Detail the detail to
// send with it: a field path such as "plan.round1.sides[0].stages[2].kind", or
// role_mismatch / session_mismatch / round1_plan. Match it with errors.As and
// compare Reason. The text never contains field values that could be key
// material.
type ValidationError struct {
	Reason Reason
	Detail string
	Msg    string
}

// Error reports the reason, the field path and the problem.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("protocol: %s: %s: %s", e.Reason, e.Detail, e.Msg)
}

func violation(detail, format string, args ...any) error {
	return &ValidationError{Reason: ReasonProtocolViolation, Detail: detail, Msg: fmt.Sprintf(format, args...)}
}

// maxJSONDepth is the deepest object/array nesting a legal message has
// (probe_summary.plan.round1.sides[].stages[].targets[] is 8 levels).
const maxJSONDepth = 8

// Marshal validates m (a message value or pointer) and encodes it as the
// JSON payload of a frame of type m.MessageType(). JSON is written without
// HTML escaping. A payload above the type's cap (MessageType.MaxPayload) is
// refused with a *ValidationError, detail frame_too_large: an oversized or invalid outbound message is an implementation
// bug, and a relayed message whose re-encoding grew past the cap is dropped
// by the relay rather than sent.
func Marshal(m Message) ([]byte, error) {
	if m == nil || reflect.ValueOf(m).Kind() == reflect.Pointer && reflect.ValueOf(m).IsNil() {
		return nil, fmt.Errorf("%w: nil message", ErrUnexpectedMessage)
	}
	t := m.MessageType()
	var err error
	if o, ok := m.(interface{ validateOutbound() error }); ok {
		err = o.validateOutbound()
	} else {
		err = m.Validate()
	}
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("protocol: encode %s: %w", t, err)
	}
	payload := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if limit := t.MaxPayload(); len(payload) > limit {
		return nil, &ValidationError{Reason: ReasonProtocolViolation, Detail: "frame_too_large",
			Msg: fmt.Sprintf("%s payload %d > %d", t, len(payload), limit)}
	}
	return payload, nil
}

// Unmarshal decodes the payload of a frame of type t into the message type T
// (a value type such as PunchGo) and validates it. Another type t returns
// ErrUnexpectedMessage. A payload above the type's cap, or that is not a
// UTF-8 JSON object nested at most 8 levels, or that fails Validate, returns
// a *ValidationError. Unknown fields are ignored. Unmarshal does not clamp:
// the caller runs Normalize and reports whether a clamp happened.
func Unmarshal[T any, P interface {
	*T
	Message
}](t MessageType, payload []byte) (T, error) {
	var v T
	want := P(&v).MessageType()
	if t != want {
		return v, fmt.Errorf("%w: got %s, want %s", ErrUnexpectedMessage, t, want)
	}
	if limit := want.MaxPayload(); len(payload) > limit {
		return v, &ValidationError{Reason: ReasonProtocolViolation, Detail: "frame_too_large",
			Msg: fmt.Sprintf("%s payload %d > %d", want, len(payload), limit)}
	}
	if err := decodePayload(want, payload, &v); err != nil {
		return v, err
	}
	return v, P(&v).Validate()
}

// Decode decodes and validates the payload of a frame of type t, any of the
// twelve message types, and returns a pointer to the message (*PunchStart,
// *ProbeReport, ...), ready for Normalize. Type 0 and the reserved types
// return ErrUnexpectedMessage.
func Decode(t MessageType, payload []byte) (Message, error) {
	switch t {
	case MsgPunchStart:
		return decodeAs[PunchStart](t, payload)
	case MsgProbeReport:
		return decodeAs[ProbeReport](t, payload)
	case MsgProbeSummary:
		return decodeAs[ProbeSummary](t, payload)
	case MsgPunchReady:
		return decodeAs[PunchReady](t, payload)
	case MsgPunchGo:
		return decodeAs[PunchGo](t, payload)
	case MsgProgress:
		return decodeAs[Progress](t, payload)
	case MsgAssist:
		return decodeAs[Assist](t, payload)
	case MsgAbort:
		return decodeAs[Abort](t, payload)
	case MsgPing:
		return decodeAs[Ping](t, payload)
	case MsgPong:
		return decodeAs[Pong](t, payload)
	case MsgRoundResult:
		return decodeAs[RoundResult](t, payload)
	case MsgPunchResult:
		return decodeAs[PunchResult](t, payload)
	}
	return nil, fmt.Errorf("%w: %s", ErrUnexpectedMessage, t)
}

func decodeAs[T any, P interface {
	*T
	Message
}](t MessageType, payload []byte) (Message, error) {
	v, err := Unmarshal[T, P](t, payload)
	if err != nil {
		return nil, err
	}
	return P(&v), nil
}

// decodePayload enforces the JSON constraints of a payload of type t and
// decodes it into dst: an empty payload is {}; otherwise a UTF-8 JSON object
// whose nesting stays within maxJSONDepth and, in a client's message, whose
// bounded lists stay within their limits (scanPayload).
func decodePayload(t MessageType, p []byte, dst any) error {
	b := bytes.TrimLeft(p, " \t\r\n")
	if len(b) == 0 {
		return nil
	}
	if !utf8.Valid(p) {
		return violation("payload", "not UTF-8")
	}
	if b[0] != '{' {
		return violation("payload", "not a JSON object")
	}
	if err := scanPayload(t, p); err != nil {
		return err
	}
	if err := json.Unmarshal(p, dst); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && te.Field != "" {
			return violation(te.Field, "%v", err)
		}
		return violation("payload", "%v", err)
	}
	return nil
}

// maxScanKey is the longest object key, folded, that scanPayload keeps: no
// field name is longer.
const maxScanKey = 32

// scanFrame is an open object or array of the payload scanPayload reads.
type scanFrame struct {
	pathEnd int  // the length of the path with this container's key
	elems   int  // array: the elements begun so far
	limit   int  // array: the most elements its list may have; 0 = not a bounded list
	array   bool // an array, not an object
	keyed   bool // the value of an object key, the path's last component
	wantKey bool // object: the next string is a key
	open    bool // array: the next value begins an element
}

// scanPayload reads p, before it is decoded, for what decoding would
// otherwise allocate first and refuse afterwards: nesting deeper than
// maxJSONDepth, and a list of a client's message (listLimit) with more
// elements than Validate allows. A list of N tiny elements ("{}", "null")
// decodes into N values of up to hundreds of bytes each, so a probe_report
// at its 32 KiB cap could otherwise make the server allocate megabytes before
// Validate refused it. Brackets in strings do not count, and object keys
// select the lists as encoding/json selects struct fields, unescaped and
// case-insensitively. Every occurrence of a repeated key counts: decoding
// fills each one before the last replaces it. p need not be valid JSON:
// json.Unmarshal checks the syntax afterwards. scanPayload does not allocate
// unless it fails.
func scanPayload(t MessageType, p []byte) error {
	var (
		stack    [maxJSONDepth]scanFrame
		path     [maxJSONDepth * (maxScanKey + 1)]byte // the folded keys of the open containers, '.'-joined
		frames   = stack[:0]                           // the open containers, innermost last
		top      *scanFrame                            // the innermost; nil outside the root object
		pathLen  int
		start    int // the first byte of the string being read
		key, end int // the last key read: p[key:end]
	)
	inString, escaped := false, false
	for i, c := range p {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
				if top != nil && top.wantKey {
					top.wantKey = false
					key, end = start, i
				}
			}
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if top != nil && top.open && c != ']' {
			top.open = false
			top.elems++
			if top.limit > 0 && top.elems > top.limit {
				return violation(scanPath(frames, path[:]), "more than %d elements", top.limit)
			}
		}
		switch c {
		case '"':
			inString, start = true, i+1
		case ',':
			if top != nil {
				top.open, top.wantKey = top.array, !top.array
			}
		case '{', '[':
			if len(frames) == maxJSONDepth {
				return violation("payload", "nested deeper than %d levels", maxJSONDepth)
			}
			f := scanFrame{array: c == '[', wantKey: c == '{', open: c == '[', pathEnd: pathLen}
			if top != nil && !top.array {
				f.keyed = true
				if pathLen > 0 {
					path[pathLen] = '.'
					pathLen++
				}
				if n := foldKey(path[pathLen:pathLen+maxScanKey], p[key:end]); n >= 0 {
					pathLen += n
				} else {
					path[pathLen] = '?' // in no field name
					pathLen++
				}
				f.pathEnd = pathLen
				if f.array {
					f.limit = listLimit(t, path[:pathLen])
				}
			}
			frames = append(frames, f)
			top = &frames[len(frames)-1]
		case '}', ']':
			if top != nil {
				frames = frames[:len(frames)-1]
				pathLen, top = 0, nil
				if n := len(frames); n > 0 {
					top = &frames[n-1]
					pathLen = top.pathEnd
				}
			}
		}
	}
	return nil
}

// scanPath is the field path of the innermost container of stack, the
// form Validate reports: "families[0].sockets[1].rows".
func scanPath(stack []scanFrame, path []byte) string {
	var b []byte
	prev := 0
	for i, f := range stack {
		if f.keyed {
			b = append(b, path[prev:f.pathEnd]...) // with the '.' before it
		}
		if f.array && i < len(stack)-1 {
			b = fmt.Appendf(b, "[%d]", f.elems-1)
		}
		prev = f.pathEnd
	}
	return string(b)
}

// foldKey writes raw, the contents of a JSON string used as an object key,
// to dst as encoding/json compares keys with field names — unescaped and
// case-folded — and returns its length. It returns -1 for a key that can
// match no field name: longer than dst, or holding a character outside
// [a-z0-9_] once folded. Besides ASCII letters, only the Kelvin sign
// (U+212A, k) and the long s (U+017F, s) fold to such a character.
func foldKey(dst, raw []byte) int {
	n := 0
	for i := 0; i < len(raw); {
		var r rune
		switch c := raw[i]; {
		case c == '\\':
			if i+6 > len(raw) || raw[i+1] != 'u' {
				return -1 // \" \\ \/ \b \f \n \r \t are in no field name
			}
			for _, h := range raw[i+2 : i+6] {
				switch {
				case '0' <= h && h <= '9':
					r = r<<4 | rune(h-'0')
				case 'a' <= h && h <= 'f':
					r = r<<4 | rune(h-'a'+10)
				case 'A' <= h && h <= 'F':
					r = r<<4 | rune(h-'A'+10)
				default:
					return -1
				}
			}
			i += 6
		case c < utf8.RuneSelf:
			r = rune(c)
			i++
		default:
			var size int
			r, size = utf8.DecodeRune(raw[i:])
			i += size
		}
		switch {
		case 'A' <= r && r <= 'Z':
			r += 'a' - 'A'
		case r == 'K':
			r = 'k'
		case r == 'ſ':
			r = 's'
		}
		if n == len(dst) || !nameChar(r) {
			return -1
		}
		dst[n] = byte(r)
		n++
	}
	return n
}

// listLimit is the most elements Validate allows the list at path (the
// object keys from the payload's root, '.'-joined, list levels left out) of a
// message of type t, or 0 when path is no such list. It covers the messages
// a client sends, the input the server must not trust; a client trusts its
// server, whose plans also carry lists that are truncated rather than
// refused (Normalize).
func listLimit(t MessageType, path []byte) int {
	switch t {
	case MsgProbeReport:
		switch string(path) {
		case "control.features":
			return maxFeatures
		case "caps.families":
			return maxCapsFamilies
		case "caps.port_map":
			return maxPortMapMethods
		case "families":
			return maxReportFamilies
		case "families.sockets":
			return maxReportSockets
		case "families.sockets.rows":
			return maxReportRows
		case "families.filters":
			return maxReportFilters
		case "families.stun":
			return maxReportSTUNRows
		case "families.local_addrs":
			return maxLocalAddrs
		case "families.overlay":
			return maxOverlayAddrs
		}
	case MsgPunchReady:
		if string(path) == "families" {
			return maxSides
		}
	case MsgRoundResult:
		switch string(path) {
		case "families":
			return maxOutcomes
		case "families.seen_from":
			return maxSeenFrom
		}
	case MsgPunchResult:
		switch string(path) {
		case "extra_paths":
			return MaxPaths - 1
		case "traits":
			return maxTraitsUpdates
		case "warn":
			return maxWarn
		}
	}
	return 0
}

package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"unicode/utf8"

	"github.com/djylb/holepunch/controlwire"
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

// Marshal validates m (a message value or pointer) and encodes it as a frame
// of its type. JSON is written without HTML escaping. A payload above the
// type's cap is refused with controlwire.ErrFrameTooLarge: an oversized or
// invalid outbound message is an implementation bug,
// and a relayed message whose re-encoding grew past the cap is dropped by
// the relay rather than sent.
func Marshal(m Message) (controlwire.Frame, error) {
	if m == nil || reflect.ValueOf(m).Kind() == reflect.Pointer && reflect.ValueOf(m).IsNil() {
		return controlwire.Frame{}, fmt.Errorf("%w: nil message", ErrUnexpectedMessage)
	}
	t := m.MessageType()
	var err error
	if o, ok := m.(interface{ validateOutbound() error }); ok {
		err = o.validateOutbound()
	} else {
		err = m.Validate()
	}
	if err != nil {
		return controlwire.Frame{}, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return controlwire.Frame{}, fmt.Errorf("protocol: encode %s: %w", t, err)
	}
	payload := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if limit := t.MaxPayload(); len(payload) > limit {
		return controlwire.Frame{}, fmt.Errorf("%w: %s payload %d > %d", controlwire.ErrFrameTooLarge, t, len(payload), limit)
	}
	return controlwire.Frame{Type: controlwire.Type(t), Payload: payload}, nil
}

// Unmarshal decodes a frame into the message type T (a value type such as
// PunchGo) and validates it. A frame of another type returns
// ErrUnexpectedMessage. A payload above the type's cap, or that is not a
// UTF-8 JSON object nested at most 8 levels, or that fails Validate, returns a
// *ValidationError. Unknown fields are ignored. Unmarshal does not clamp:
// the caller runs Normalize and reports whether a clamp happened.
func Unmarshal[T any, P interface {
	*T
	Message
}](f controlwire.Frame) (T, error) {
	var v T
	want := P(&v).MessageType()
	if MessageType(f.Type) != want {
		return v, fmt.Errorf("%w: got %s, want %s", ErrUnexpectedMessage, MessageType(f.Type), want)
	}
	if limit := want.MaxPayload(); len(f.Payload) > limit {
		return v, &ValidationError{Reason: ReasonProtocolViolation, Detail: "frame_too_large",
			Msg: fmt.Sprintf("%s payload %d > %d", want, len(f.Payload), limit)}
	}
	if err := decodePayload(f.Payload, &v); err != nil {
		return v, err
	}
	return v, P(&v).Validate()
}

// Decode decodes and validates a frame of any of the twelve message types and
// returns a pointer to the message (*PunchStart, *ProbeReport, ...), ready
// for Normalize. Type 0 and the reserved types return ErrUnexpectedMessage.
func Decode(f controlwire.Frame) (Message, error) {
	switch MessageType(f.Type) {
	case MsgPunchStart:
		return decodeAs[PunchStart](f)
	case MsgProbeReport:
		return decodeAs[ProbeReport](f)
	case MsgProbeSummary:
		return decodeAs[ProbeSummary](f)
	case MsgPunchReady:
		return decodeAs[PunchReady](f)
	case MsgPunchGo:
		return decodeAs[PunchGo](f)
	case MsgProgress:
		return decodeAs[Progress](f)
	case MsgAssist:
		return decodeAs[Assist](f)
	case MsgAbort:
		return decodeAs[Abort](f)
	case MsgPing:
		return decodeAs[Ping](f)
	case MsgPong:
		return decodeAs[Pong](f)
	case MsgRoundResult:
		return decodeAs[RoundResult](f)
	case MsgPunchResult:
		return decodeAs[PunchResult](f)
	}
	return nil, fmt.Errorf("%w: %s", ErrUnexpectedMessage, MessageType(f.Type))
}

func decodeAs[T any, P interface {
	*T
	Message
}](f controlwire.Frame) (Message, error) {
	v, err := Unmarshal[T, P](f)
	if err != nil {
		return nil, err
	}
	return P(&v), nil
}

// decodePayload enforces the JSON constraints of a control payload: an
// empty payload is {}; otherwise a UTF-8 JSON object whose nesting stays
// within maxJSONDepth.
func decodePayload(p []byte, dst any) error {
	if len(bytes.TrimSpace(p)) == 0 {
		return nil
	}
	if !utf8.Valid(p) {
		return violation("payload", "not UTF-8")
	}
	if b := bytes.TrimLeft(p, " \t\r\n"); b[0] != '{' {
		return violation("payload", "not a JSON object")
	}
	if depth := jsonDepth(p); depth > maxJSONDepth {
		return violation("payload", "nesting depth %d > %d", depth, maxJSONDepth)
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

// jsonDepth is the maximum object/array nesting of p, ignoring brackets in
// strings. It does not validate p.
func jsonDepth(p []byte) int {
	depth, deepest, inString, escaped := 0, 0, false, false
	for _, c := range p {
		switch {
		case inString:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			depth++
			deepest = max(deepest, depth)
		case c == '}' || c == ']':
			depth--
		}
	}
	return deepest
}

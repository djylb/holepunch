package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch/controlwire"
)

// TestWireExamples decodes every JSON example in testdata/examples — one or
// more per message type and the frames of a sample session, with the session
// id written out in full — checks that it validates without clamps,
// and that re-encoding keeps every value the example sets (a misspelled JSON
// tag would drop it).
func TestWireExamples(t *testing.T) {
	raw, err := os.ReadFile("testdata/examples/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest []struct {
		File   string `json:"file"`
		Type   string `json:"type"` // wire name of the message type
		Source string `json:"source"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	seen := map[MessageType]bool{}
	for _, e := range manifest {
		t.Run(e.File, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("testdata/examples", e.File))
			if err != nil {
				t.Fatal(err)
			}
			payload = bytes.TrimSpace(payload)
			m, err := Decode(controlwire.Frame{Type: controlwire.Type(messageTypeNamed(t, e.Type)), Payload: payload})
			if err != nil {
				t.Fatalf("%s: Decode: %v", e.Source, err)
			}
			seen[m.MessageType()] = true
			if normalize(t, m) {
				t.Errorf("%s: the example needed clamping", e.Source)
			}
			if a, ok := m.(*Assist); ok && a.From != "" {
				if err := a.ValidateRelayed(); err != nil {
					t.Errorf("%s: relayed assist: %v", e.Source, err)
				}
			}
			f, err := Marshal(m)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var want, got any
			if err := json.Unmarshal(payload, &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(f.Payload, &got); err != nil {
				t.Fatal(err)
			}
			if path, ok := jsonSubset(want, got, ""); !ok {
				t.Errorf("%s: re-encoding lost or changed %s\nexample: %s\nencoded: %s", e.Source, path, payload, f.Payload)
			}
		})
	}
	for _, typ := range allMessageTypes() {
		if !seen[typ] {
			t.Errorf("no 01 example decoded for %s", typ)
		}
	}
}

// jsonSubset reports whether every value set in want appears unchanged in got.
// A field missing from got is accepted only when want's value is a zero value
// (an omitempty field).
func jsonSubset(want, got any, path string) (string, bool) {
	switch w := want.(type) {
	case map[string]any:
		g, _ := got.(map[string]any)
		for k, wv := range w {
			gv, ok := g[k]
			if !ok {
				if isZeroJSON(wv) {
					continue
				}
				return path + "." + k, false
			}
			if p, ok := jsonSubset(wv, gv, path+"."+k); !ok {
				return p, false
			}
		}
		return "", true
	case []any:
		g, _ := got.([]any)
		if len(g) != len(w) {
			return path, false
		}
		for i := range w {
			if p, ok := jsonSubset(w[i], g[i], fmt.Sprintf("%s[%d]", path, i)); !ok {
				return p, false
			}
		}
		return "", true
	}
	return path, reflect.DeepEqual(want, got)
}

func isZeroJSON(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case float64:
		return x == 0
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// normalize runs the message's Normalize and stores the result through m
// when m is a pointer, as Decode returns them (a value is normalized as a
// copy), and reports whether a clamp changed a value.
func normalize(t testing.TB, m Message) bool {
	t.Helper()
	v := reflect.ValueOf(m)
	if v.Kind() != reflect.Pointer {
		p := reflect.New(v.Type())
		p.Elem().Set(v)
		v = p
	}
	fn := v.Elem().MethodByName("Normalize")
	if !fn.IsValid() {
		t.Fatalf("%T has no Normalize", m)
	}
	out := fn.Call(nil)
	v.Elem().Set(out[0])
	return out[1].Bool()
}

// deref returns the message value behind a pointer returned by Decode.
func deref(m Message) Message { return reflect.ValueOf(m).Elem().Interface().(Message) }

// TestRoundTripAllMessages: every field of every message survives
// Marshal → Unmarshal.
func TestRoundTripAllMessages(t *testing.T) {
	for _, m := range sampleMessages() {
		f, err := Marshal(m)
		if err != nil {
			t.Fatalf("%s: Marshal: %v", m.MessageType(), err)
		}
		if f.Type != controlwire.Type(m.MessageType()) || len(f.Payload) > m.MessageType().MaxPayload() {
			t.Fatalf("%s: frame type %d, %d bytes", m.MessageType(), f.Type, len(f.Payload))
		}
		got, err := Decode(f)
		if err != nil {
			t.Fatalf("%s: Decode: %v\n%s", m.MessageType(), err, f.Payload)
		}
		if !reflect.DeepEqual(deref(got), m) {
			t.Fatalf("%s: round trip differs\nwant %+v\ngot  %+v\njson %s", m.MessageType(), m, got, f.Payload)
		}
		// Pointers marshal too.
		p := reflect.New(reflect.TypeOf(m))
		p.Elem().Set(reflect.ValueOf(m))
		if g, err := Marshal(p.Interface().(Message)); err != nil || !bytes.Equal(g.Payload, f.Payload) {
			t.Fatalf("%s: Marshal(pointer) = %v", m.MessageType(), err)
		}
	}
}

func TestUnmarshalTyped(t *testing.T) {
	f, err := Marshal(Ping{Seq: 3})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := Unmarshal[Ping](f); err != nil || p.Seq != 3 {
		t.Fatalf("Unmarshal[Ping] = %v, %v", p, err)
	}
	if _, err := Unmarshal[Pong](f); !errors.Is(err, ErrUnexpectedMessage) {
		t.Fatalf("Unmarshal[Pong](ping) = %v, want ErrUnexpectedMessage", err)
	}
	var nilStart *PunchStart
	if _, err := Marshal(nilStart); !errors.Is(err, ErrUnexpectedMessage) {
		t.Fatalf("Marshal(typed nil) = %v", err)
	}
	if _, err := Marshal(nil); !errors.Is(err, ErrUnexpectedMessage) {
		t.Fatalf("Marshal(nil) = %v", err)
	}
	if _, err := Marshal(Ping{Seq: 0}); !isViolation(err) {
		t.Fatalf("Marshal(invalid) = %v", err)
	}
	big := f
	big.Payload = make([]byte, MsgPing.MaxPayload()+1)
	var verr *ValidationError
	if _, err := Unmarshal[Ping](big); !errors.As(err, &verr) || verr.Detail != "frame_too_large" {
		t.Fatalf("oversized payload: %v", err)
	}
}

func TestDecodePayloadRules(t *testing.T) {
	deep := `{"seq":1,"x":` + strings.Repeat("[", 8) + strings.Repeat("]", 8) + `}`
	errViolation := errors.New("a protocol_violation") // matched by isViolation
	for _, tc := range []struct {
		name    string
		typ     MessageType
		payload string
		err     error
	}{
		{"empty_is_object", MsgPing, "", errViolation}, // {} then seq 0 fails Validate
		{"unknown_fields_ignored", MsgPing, `{"seq":1,"future":{"a":[1,2]}}`, nil},
		{"array", MsgPing, `[1]`, errViolation},
		{"null", MsgPing, `null`, errViolation},
		{"number", MsgPing, ` 7`, errViolation},
		{"bad_utf8", MsgPing, "{\"seq\":1,\"x\":\"\xff\"}", errViolation},
		{"depth_8_ok", MsgPing, `{"seq":1,"x":` + strings.Repeat("[", 7) + strings.Repeat("]", 7) + `}`, nil},
		{"depth_9", MsgPing, deep, errViolation},
		{"brackets_in_strings", MsgPing, `{"seq":1,"x":"[[[[[[[[[[[["}`, nil},
		{"overflow_uint8", MsgPing, `{"seq":300}`, errViolation},
		{"negative_unsigned", MsgPong, `{"seq":1,"hold_us":-1}`, errViolation},
		{"wrong_json_type", MsgPunchGo, `{"session_id":1}`, errViolation},
		// A round-1 go may carry an anchor update; the client checks
		// it against the summary.
		{"go_round1_plan", MsgPunchGo, `{"session_id":"a","round":1,"window_ms":9,"plan":{"round":1,"variant":"v","budget":"light","window_ms":9,"sides":[{"family":"udp4","role":"both","sockets":1,"stages":[{"kind":"direct","targets":["1.2.3.4:5"]}]}]}}`, nil},
		{"go_round1_bad_plan", MsgPunchGo, `{"session_id":"a","round":1,"window_ms":9,"plan":{"round":2,"variant":"v","budget":"light","window_ms":9,"sides":[{"family":"udp4","role":"both","sockets":1,"stages":[{"kind":"direct","targets":["1.2.3.4:5"]}]}]}}`, errViolation},
		{"go_round2_plan", MsgPunchGo, `{"session_id":"a","round":2,"window_ms":9,"plan":{"round":2,"variant":"v","budget":"light","window_ms":9,"sides":[{"family":"udp4","role":"both","sockets":1,"stages":[{"kind":"direct","targets":["1.2.3.4:5"]}]}]}}`, nil},
		{"bad_enum_text", MsgProbeSummary, `{"self":{"families":[{"family":"udp4","traits":{"mapping":"cone"}}]}}`, errViolation},
		{"first_reserved", MsgPunchResult + 1, `{}`, ErrUnexpectedMessage},
		{"last_reserved", math.MaxUint8, `{}`, ErrUnexpectedMessage},
		{"zero", 0, `{}`, ErrUnexpectedMessage},
	} {
		_, err := Decode(controlwire.Frame{Type: controlwire.Type(tc.typ), Payload: []byte(tc.payload)})
		match := errors.Is(err, tc.err)
		if errors.Is(tc.err, errViolation) {
			match = isViolation(err)
		}
		if (tc.err == nil) != (err == nil) || (tc.err != nil && !match) {
			t.Errorf("%s: Decode = %v, want %v", tc.name, err, tc.err)
		}
	}
}

func TestMarshalLimitsAndEscaping(t *testing.T) {
	p := Progress{SessionID: testSession, Role: RoleInitiator, Stage: "fire", Detail: "<a&b>"}
	p.Counters, p.Meta = map[string]uint32{}, map[string]string{}
	for i := 0; i < 16; i++ {
		p.Counters[fmt.Sprintf("c%063d", i)] = 4294967295
	}
	for i := 0; i < 15; i++ {
		p.Meta[fmt.Sprintf("m%03d", i)] = strings.Repeat("v", 64)
	}
	if _, err := Marshal(p); !errors.Is(err, controlwire.ErrFrameTooLarge) {
		t.Fatalf("2 KiB+ progress: %v, want ErrFrameTooLarge", err)
	}
	p.Counters, p.Meta = nil, nil
	f, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(f.Payload, []byte(`"detail":"<a&b>"`)) || bytes.HasSuffix(f.Payload, []byte("\n")) {
		t.Fatalf("payload %s: want no HTML escaping and no trailing newline", f.Payload)
	}
}

func TestCheckOrigin(t *testing.T) {
	for _, m := range sampleMessages() {
		if err := CheckOrigin(m, testSession, ""); err != nil {
			t.Errorf("%s: CheckOrigin(client side) = %v", m.MessageType(), err)
		}
	}
	report := sampleMessages()[3].(ProbeReport)
	if err := CheckOrigin(&report, testSession, RoleInitiator); err != nil {
		t.Fatalf("pointer: %v", err)
	}
	if err := CheckOrigin(report, testSession, RoleInitiator); err != nil {
		t.Fatal(err)
	}
	var verr *ValidationError
	if err := CheckOrigin(report, testSession, RoleResponder); !errors.As(err, &verr) || verr.Detail != "role_mismatch" {
		t.Fatalf("role mismatch: %v", err)
	}
	if err := CheckOrigin(report, "other", RoleInitiator); !errors.As(err, &verr) || verr.Detail != "session_mismatch" {
		t.Fatalf("session mismatch: %v", err)
	}
	if r, d, ok := WireReason(CheckOrigin(report, "other", "")); !ok || r != ReasonProtocolViolation || d != "session_mismatch" {
		t.Fatalf("WireReason = %s, %s, %v", r, d, ok)
	}
	if err := CheckOrigin(Ping{Seq: 1}, "other", RoleInitiator); err != nil {
		t.Fatalf("ping is link-level: %v", err)
	}
	assist := Assist{SessionID: testSession, Kind: AssistPeerSeen}
	if err := CheckOrigin(assist, testSession, RoleInitiator); !errors.As(err, &verr) || verr.Detail != "role_mismatch" {
		t.Fatalf("assist without role on a server link: %v", err)
	}
}

func TestLogValueRedacts(t *testing.T) {
	msgs := sampleMessages()
	start, report, summary := msgs[0].(PunchStart), msgs[3].(ProbeReport), msgs[4].(ProbeSummary)
	tokenText, _ := start.Token.MarshalText()
	routeText, _ := start.Wire.RouteID.MarshalText()
	secrets := []string{string(tokenText), string(routeText), fmt.Sprintf("%x", start.Token[:]),
		fmt.Sprintf("%x", start.Wire.RouteID[:]), report.Transport.Data, summary.Transport.PeerData}
	var jsonBuf, textBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&jsonBuf, nil)).Info("x", "start", start, "report", report, "summary", summary,
		"token", start.Token, "route", start.Wire.RouteID, "wire", start.Wire)
	slog.New(slog.NewTextHandler(&textBuf, nil)).Info("x", "start", start, "token", start.Token, "wire", start.Wire)
	outputs := map[string]string{
		"slog json": jsonBuf.String(),
		"slog text": textBuf.String(),
		"%v":        fmt.Sprintf("%v", start),
		"%+v":       fmt.Sprintf("%+v", start),
		"%#v":       fmt.Sprintf("%#v", start),
		"%s token":  fmt.Sprintf("%s %x %q", start.Token, start.Token, start.Token),
		"%x route":  fmt.Sprintf("%x %d", start.Wire.RouteID, start.Wire.RouteID),
	}
	for name, out := range outputs {
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Fatalf("%s contains %q:\n%s", name, secret, out)
			}
		}
	}
	prefix := fmt.Sprintf("%x", start.Wire.RouteID[:2])
	if !strings.Contains(jsonBuf.String(), `"route":"`+prefix+`"`) || !strings.Contains(jsonBuf.String(), testSession) {
		t.Fatalf("log output lacks the route prefix or session:\n%s", jsonBuf.String())
	}
}

func TestTokenAndRouteText(t *testing.T) {
	var tok Token
	for _, bad := range []string{"short", strings.Repeat("A", 42), strings.Repeat("A", 44), "T3v1x0q5bJ8mH1YVt0rG2cN4cPq7Lw9yZr6sQ1eA2kN", strings.Repeat("+", 43)} {
		if err := tok.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("token %q accepted", bad)
		}
	}
	if err := tok.UnmarshalText(nil); err != nil || !tok.IsZero() {
		t.Fatalf("empty token: %v", err)
	}
	var r RouteID
	if err := r.UnmarshalText([]byte("m9xZyQ2k1W0pS7aR3tU5vh")); err == nil {
		t.Error("non-canonical route accepted")
	}
	// A missing or empty token is reported by Validate as missing.
	start := sampleMessages()[0].(PunchStart)
	start.Token = Token{}
	var verr *ValidationError
	if err := start.Validate(); !errors.As(err, &verr) || verr.Detail != "token" {
		t.Fatalf("zero token: %v", err)
	}
}

func TestPongFor(t *testing.T) {
	read := time.Unix(1791234567, 0)
	p := PongFor(Ping{Seq: 4}, read, read.Add(41*time.Microsecond))
	if p.Seq != 4 || p.HoldUs != 41 || p.ClientUnixMs != 1791234567000 {
		t.Fatalf("PongFor = %+v", p)
	}
	if p := PongFor(Ping{Seq: 1}, read, read.Add(-time.Second)); p.HoldUs != 0 {
		t.Fatalf("negative hold = %d", p.HoldUs)
	}
}

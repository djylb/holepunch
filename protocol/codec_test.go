package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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

// clientLists are the bounded lists of the messages a client sends: the
// path to each ("[]" after a list that leads to it) and its limit.
func clientLists() []struct {
	typ  MessageType
	path string
	max  int
} {
	return []struct {
		typ  MessageType
		path string
		max  int
	}{
		{MsgProbeReport, "control.features", maxFeatures},
		{MsgProbeReport, "caps.families", maxCapsFamilies},
		{MsgProbeReport, "caps.port_map", maxPortMapMethods},
		{MsgProbeReport, "families", maxReportFamilies},
		{MsgProbeReport, "families[].sockets", maxReportSockets},
		{MsgProbeReport, "families[].sockets[].rows", maxReportRows},
		{MsgProbeReport, "families[].filters", maxReportFilters},
		{MsgProbeReport, "families[].stun", maxReportSTUNRows},
		{MsgProbeReport, "families[].local_addrs", maxLocalAddrs},
		{MsgProbeReport, "families[].overlay", maxOverlayAddrs},
		{MsgPunchReady, "families", maxSides},
		{MsgRoundResult, "families", maxOutcomes},
		{MsgRoundResult, "families[].seen_from", maxSeenFrom},
		{MsgPunchResult, "extra_paths", MaxPaths - 1},
		{MsgPunchResult, "traits", maxTraitsUpdates},
		{MsgPunchResult, "warn", maxWarn},
	}
}

// nestedList is a payload whose list at path (as in clientLists) holds n
// null elements: "a[].b" gives {"a":[{"b":[null,null]}]}.
func nestedList(path string, n int) string {
	var open, closing []string
	for _, k := range strings.Split(path, ".") {
		if name, ok := strings.CutSuffix(k, "[]"); ok {
			open, closing = append(open, `{"`+name+`":[`), append([]string{"]}"}, closing...)
		} else {
			open, closing = append(open, `{"`+k+`":`), append([]string{"}"}, closing...)
		}
	}
	open[len(open)-1] += "["
	closing[0] = "]}"
	return strings.Join(open, "") + strings.TrimSuffix(strings.Repeat("null,", n), ",") + strings.Join(closing, "")
}

// TestDecodeBoundsClientLists: a client's list longer than Validate allows
// is refused before it is decoded, so a frame of tiny elements ("null", "{}")
// cannot make the server allocate many times its size, whatever the case or
// escaping of the keys; a list at its limit, an unknown list and the lists
// of server messages (truncated, not refused) are left to decoding.
func TestDecodeBoundsClientLists(t *testing.T) {
	for _, l := range clientLists() {
		detail := strings.ReplaceAll(l.path, "[]", "[0]")
		at := nestedList(l.path, l.max)
		if err := scanPayload(l.typ, []byte(at)); err != nil {
			t.Errorf("%s %s at its limit: %v", l.typ, detail, err)
		}
		over := nestedList(l.path, (l.typ.MaxPayload()-len(nestedList(l.path, 0)))/len("null,"))
		var verr *ValidationError
		if _, err := Decode(controlwire.Frame{Type: controlwire.Type(l.typ), Payload: []byte(over)}); !errors.As(err, &verr) ||
			verr.Reason != ReasonProtocolViolation || verr.Detail != detail {
			t.Errorf("%s %s over its limit: %v, want detail %q", l.typ, detail, err, detail)
		}
		frame := controlwire.Frame{Type: controlwire.Type(l.typ), Payload: []byte(over)}
		if alloc := allocBytes(func() { _, _ = Decode(frame) }); alloc > 4<<10 {
			t.Errorf("%s %s: decoding a %d-byte frame allocated %d bytes", l.typ, detail, len(over), alloc)
		}
	}
	for _, tc := range []struct {
		name    string
		typ     MessageType
		payload string
		detail  string // "" = the scan lets it through
	}{
		{"case_folded", MsgPunchResult, `{"WARN":[1,2,3,4,5,6,7,8,9]}`, "warn"},
		{"escaped", MsgPunchResult, `{"w\u0061rn":[1,2,3,4,5,6,7,8,9]}`, "warn"},
		// Each occurrence of a repeated key is decoded before the last one
		// replaces it, so each must be within the limit.
		{"repeated_key_over_first", MsgPunchResult, `{"warn":[1,2,3,4,5,6,7,8,9],"warn":[]}`, "warn"},
		{"repeated_key_within", MsgPunchResult, `{"warn":[1,2,3,4,5,6,7,8],"Warn":[1,2,3,4,5,6,7,8]}`, ""},
		{"long_s_and_kelvin", MsgProbeReport, `{"families":[{"ſockets":[{"rows":[]}]},{"ſOCKETS":[{"rows":[]}],"local_addrs":[]}],"Keep":[1]}`, ""},
		{"long_s_over", MsgProbeReport, `{"families":[{"ſockets":[0,0,0,0,0,0,0]}]}`, "families[0].sockets"},
		{"kelvin_over", MsgProbeReport, `{"families":[{"SOC\u212AETS":[0,0,0,0,0,0,0]}]}`, "families[0].sockets"},
		{"nested_index", MsgProbeReport, `{"families":[{},{"sockets":[{},{},{"rows":[` + strings.Repeat("0,", 16) + `0]}]}]}`, "families[1].sockets[2].rows"},
		{"not_a_field", MsgPunchResult, `{"warn_":[1,2,3,4,5,6,7,8,9],"wärn":[1,2,3,4,5,6,7,8,9],"w\"rn":[1,2,3,4,5,6,7,8,9]}`, ""},
		{"unknown_list", MsgRoundResult, `{"future":[` + strings.Repeat("0,", 99) + `0],"families":[]}`, ""},
		{"commas_in_strings", MsgPunchResult, `{"warn":["a,b,c,d,e,f,g,h,i,j", "[,,,,,,,,]"]}`, ""},
		{"nested_unknown_object", MsgPunchResult, `{"x":{"warn":[1,2,3,4,5,6,7,8,9]}}`, ""},
		{"server_lists_truncated", MsgProbeSummary, `{"plan":{"round1":{"sides":[{"stages":[` + strings.Repeat("{},", 99) + `{}]}]}}}`, ""},
	} {
		err := scanPayload(tc.typ, []byte(tc.payload))
		var verr *ValidationError
		switch {
		case tc.detail == "" && err != nil:
			t.Errorf("%s: %v, want no error", tc.name, err)
		case tc.detail != "" && (!errors.As(err, &verr) || verr.Detail != tc.detail):
			t.Errorf("%s: %v, want detail %q", tc.name, err, tc.detail)
		}
	}
	report := maximalReport()
	f, err := Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(f); err != nil {
		t.Fatalf("a report with every list full: %v", err)
	}
	if n := testing.AllocsPerRun(10, func() { _ = scanPayload(MsgProbeReport, f.Payload) }); n != 0 {
		t.Fatalf("scanPayload allocated %v times", n)
	}
}

// allocBytes is the average number of bytes f allocates.
func allocBytes(f func()) uint64 {
	const runs = 20
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / runs
}

// maximalReport is a valid probe_report with every list at its limit.
func maximalReport() ProbeReport {
	m := sample[ProbeReport]()
	m.Control.Features = features(maxFeatures)
	m.Caps.Families = []FamilyCaps{{Family: FamilyUDP4}, {Family: FamilyUDP6}}
	m.Caps.PortMap = []PortMapMethod{PortMapPCP, PortMapNATPMP, PortMapUPnP}
	fam := func(f Family, a netip.Addr) FamilyReport {
		local := netip.AddrPortFrom(a, 5000)
		row := RowReport{Observer: 1, Observed: local, FirstSeq: 1, SentMs: 2}
		return FamilyReport{Family: f,
			Sockets:    repeat(SocketReport{Kind: SocketPrimary, Local: local, Rows: repeat(row, maxReportRows)}, maxReportSockets),
			Filters:    make([]FilterReport, maxReportFilters),
			STUN:       repeat(row, maxReportSTUNRows),
			LocalAddrs: repeat(a, maxLocalAddrs),
			Overlay:    repeat(a, maxOverlayAddrs),
		}
	}
	m.Families = []FamilyReport{fam(FamilyUDP4, ip("192.0.2.1")), fam(FamilyUDP6, ip("2001:db8::1"))}
	return m
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

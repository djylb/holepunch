package proto

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/goroutines"
)

func TestMain(m *testing.M) { goroutines.VerifyTestMain(m) }

// samples has one valid message of every type.
func samples() []Message {
	return []Message{
		&Register{HostID: "office-1", AuthToken: "secret", Credential: "cred", Metadata: map[string]string{"os": "linux"}},
		&Registered{Credential: "CRED42", HeartbeatMs: 15000},
		&Open{HostID: "office-1", DialerID: "laptop", AuthToken: "secret", Metadata: map[string]string{"user": "ann"}},
		&Join{SessionID: "abc_DEF-123", Ticket: "TICKET"},
		&SessionInfo{SessionID: "abc_DEF-123", HostID: "office-1", DialerID: "laptop",
			HostMetadata: map[string]string{"os": "linux"}, DialerMetadata: map[string]string{"user": "ann"},
			Policy: AccessPolicy{Targets: []string{"127.0.0.1:22", "db.internal:5432"}}},
		&Incoming{SessionID: "abc_DEF-123", Ticket: "TICKET", DialerID: "laptop", DialerMetadata: map[string]string{"user": "ann"}},
		&Heartbeat{},
		&Transport{SessionID: "abc_DEF-123", OK: true, Detail: "quic"},
		&Fail{Code: CodeHostNotFound, Message: "no such host"},
	}
}

func TestRoundTrip(t *testing.T) {
	for _, m := range samples() {
		frame, err := Encode(m)
		if err != nil {
			t.Fatalf("%v: %v", m.Type(), err)
		}
		if frame[0] != Version || Type(frame[1]) != m.Type() || int(binary.BigEndian.Uint16(frame[2:])) != len(frame)-HeaderSize {
			t.Fatalf("%v: header % x", m.Type(), frame[:HeaderSize])
		}
		got, err := Decode(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("%v: %v", m.Type(), err)
		}
		if !reflect.DeepEqual(got, m) {
			t.Fatalf("%v: got %+v want %+v", m.Type(), got, m)
		}
	}
}

// TestTypesConsecutive: the types run from 1 without gaps and every
// value outside them is unknown.
func TestTypesConsecutive(t *testing.T) {
	for i, m := range samples() {
		if want := Type(i + 1); m.Type() != want || newMessage(want) == nil {
			t.Fatalf("sample %d has type %v, want %v", i, m.Type(), want)
		}
		if strings.HasPrefix(m.Type().String(), "type_") {
			t.Fatalf("%d has no name", m.Type())
		}
	}
	for _, ty := range []Type{0, TypeFail + 1, 255} {
		if newMessage(ty) != nil {
			t.Fatalf("type %d known", ty)
		}
		if ty.String() == "" {
			t.Fatal("empty name")
		}
	}
}

func frameOf(version, ty byte, payload string) []byte {
	b := []byte{version, ty, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(len(payload)))
	return append(b, payload...)
}

func TestDecodeErrors(t *testing.T) {
	big := frameOf(Version, byte(TypeOpen), `{"host_id":"h"}`)
	binary.BigEndian.PutUint16(big[2:], MaxPayload)
	cases := []struct {
		name  string
		frame []byte
		want  error
	}{
		{"version", frameOf(2, byte(TypeHeartbeat), "{}"), ErrVersion},
		{"unknown type", frameOf(Version, 0, "{}"), ErrType},
		{"unknown type high", frameOf(Version, byte(TypeFail+1), "{}"), ErrType},
		{"announced larger than sent", big, io.ErrUnexpectedEOF},
		{"truncated header", []byte{Version, byte(TypeOpen)}, io.ErrUnexpectedEOF},
		{"truncated payload", frameOf(Version, byte(TypeHeartbeat), "{}")[:5], io.ErrUnexpectedEOF},
		{"bad json", frameOf(Version, byte(TypeOpen), "{"), ErrInvalid},
		{"empty payload", frameOf(Version, byte(TypeHeartbeat), ""), ErrInvalid},
		{"missing host", frameOf(Version, byte(TypeOpen), `{"dialer_id":"x"}`), ErrInvalid},
		{"bad session id", frameOf(Version, byte(TypeJoin), `{"session_id":"a b","ticket":"t"}`), ErrInvalid},
		{"no ticket", frameOf(Version, byte(TypeJoin), `{"session_id":"ab"}`), ErrInvalid},
		{"heartbeat range", frameOf(Version, byte(TypeRegistered), `{"credential":"c","heartbeat_ms":10}`), ErrInvalid},
		{"bad code", frameOf(Version, byte(TypeFail), `{"code":"Bad"}`), ErrInvalid},
		{"policy not canonical", frameOf(Version, byte(TypeSessionInfo), `{"session_id":"s","host_id":"h","policy":{"targets":["HOST:22"]}}`), ErrInvalid},
	}
	for _, c := range cases {
		_, err := Decode(bytes.NewReader(c.frame))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := Decode(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("empty stream: %v", err)
	}
}

// TestDecodeLargestFrame: a payload of MaxPayload bytes, read in growing
// chunks, decodes, and the bytes after it stay on the stream.
func TestDecodeLargestFrame(t *testing.T) {
	payload := `{"host_id":"h"}`
	payload += strings.Repeat(" ", MaxPayload-len(payload))
	r := bytes.NewReader(append(frameOf(Version, byte(TypeOpen), payload), "next"...))
	m, err := Decode(r)
	if err != nil || m.(*Open).HostID != "h" {
		t.Fatalf("%v %v", m, err)
	}
	if r.Len() != len("next") {
		t.Fatalf("%d bytes left", r.Len())
	}
}

// TestLargestMessages: every message at its field limits, filled with the
// characters JSON escapes the most, encodes within MaxPayload and decodes
// back. Metadata that a dialer sent in a small frame is relayed in Incoming
// and SessionInfo, so no character may make those overflow.
func TestLargestMessages(t *testing.T) {
	name := strings.Repeat("n", MaxNameLen)
	secret := strings.Repeat("s", MaxSecretLen)
	for _, fill := range []string{`"`, `\`, "<", "\u2028", "é"} {
		repeat := func(n int) string { return strings.Repeat(fill, n/len(fill)) }
		meta := map[string]string{}
		for c := 'a'; c < 'a'+MaxMetadata; c++ {
			meta[strings.Repeat(string(c), MaxNameLen)] = repeat(MaxMetaValueLen)
		}
		const ipv6 = "[fe80::1%]:65535"
		targets := make([]string, MaxTargets)
		for i := range targets {
			targets[i] = "[fe80::1%" + repeat(MaxTargetLen-len(ipv6)) + "]:65535"
		}
		for _, m := range []Message{
			&Register{HostID: name, AuthToken: secret, Credential: secret, Metadata: meta},
			&Open{HostID: name, DialerID: name, AuthToken: secret, Metadata: meta},
			&SessionInfo{SessionID: name, HostID: name, DialerID: name, HostMetadata: meta, DialerMetadata: meta,
				Policy: AccessPolicy{Targets: targets}},
			&Incoming{SessionID: name, Ticket: secret, DialerID: name, DialerMetadata: meta},
			&Transport{SessionID: name, Detail: repeat(MaxTextLen)},
			&Fail{Code: Code(strings.Repeat("c", 32)), Message: repeat(MaxTextLen)},
		} {
			frame, err := Encode(m)
			if err != nil {
				t.Fatalf("%q %v: %v", fill, m.Type(), err)
			}
			got, err := Decode(bytes.NewReader(frame))
			if err != nil || !reflect.DeepEqual(got, m) {
				t.Fatalf("%q %v: round trip %v", fill, m.Type(), err)
			}
		}
	}
}

// TestUnknownFieldsIgnored: fields this version does not know are skipped.
func TestUnknownFieldsIgnored(t *testing.T) {
	m, err := Decode(bytes.NewReader(frameOf(Version, byte(TypeOpen), `{"host_id":"h","future":{"x":1}}`)))
	if err != nil || m.(*Open).HostID != "h" {
		t.Fatalf("%v %v", m, err)
	}
}

func TestValidation(t *testing.T) {
	long := strings.Repeat("a", MaxNameLen+1)
	meta := map[string]string{}
	for c := 'a'; c < 'a'+MaxMetadata+1; c++ {
		meta[string(c)] = "v"
	}
	bad := []Message{
		&Register{HostID: ""},
		&Register{HostID: long},
		&Register{HostID: "a/b"},
		&Register{HostID: "h", AuthToken: "has space"},
		&Register{HostID: "h", Credential: strings.Repeat("c", MaxSecretLen+1)},
		&Register{HostID: "h", Metadata: meta},
		&Register{HostID: "h", Metadata: map[string]string{"k k": "v"}},
		&Register{HostID: "h", Metadata: map[string]string{"k": strings.Repeat("v", MaxMetaValueLen+1)}},
		&Register{HostID: "h", Metadata: map[string]string{"k": "line\nbreak"}},
		&Register{HostID: "h", Metadata: map[string]string{"k": "\xff"}},
		&Registered{Credential: "", HeartbeatMs: 1000},
		&Registered{Credential: "c", HeartbeatMs: MaxHeartbeatMs + 1},
		&Open{HostID: "h", DialerID: "bad id"},
		&Join{SessionID: strings.Repeat("s", MaxNameLen+1), Ticket: "t"},
		&SessionInfo{SessionID: "s", HostID: "h", Policy: AccessPolicy{Targets: make([]string, MaxTargets+1)}},
		&Incoming{SessionID: "s"},
		&Transport{SessionID: "s", Detail: strings.Repeat("d", MaxTextLen+1)},
		&Fail{Code: ""},
		&Fail{Code: "x-y"},
		&Fail{Code: Code(strings.Repeat("x", 33))},
	}
	for _, m := range bad {
		if _, err := Encode(m); !errors.Is(err, ErrInvalid) {
			t.Errorf("%T %+v: %v", m, m, err)
		}
	}
	if _, err := Encode(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil message encoded")
	}
	var nilOpen *Open
	if _, err := Encode(nilOpen); !errors.Is(err, ErrInvalid) {
		t.Fatal("typed nil encoded")
	}
	huge := &Register{HostID: "h", Metadata: map[string]string{}}
	for c := 'a'; c < 'a'+MaxMetadata; c++ {
		huge.Metadata[strings.Repeat(string(c), MaxNameLen)] = strings.Repeat("v", MaxMetaValueLen)
	}
	if _, err := Encode(huge); err != nil {
		t.Fatalf("largest valid register: %v", err)
	}
}

// TestDecodeReadsOneFrame: Decode leaves the bytes after its frame on the
// stream, as holepunch's punch_start follows SessionInfo.
func TestDecodeReadsOneFrame(t *testing.T) {
	a, _ := Encode(&Heartbeat{})
	b, _ := Encode(&Fail{Code: CodeBusy})
	r := bytes.NewReader(append(append(append([]byte(nil), a...), b...), "trailer"...))
	if m, err := Decode(r); err != nil || m.Type() != TypeHeartbeat {
		t.Fatal(m, err)
	}
	if m, err := Decode(r); err != nil || m.Type() != TypeFail {
		t.Fatal(m, err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "trailer" {
		t.Fatalf("rest %q", rest)
	}
}

func TestWriteRead(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	go func() { _ = Write(a, &Join{SessionID: "s1", Ticket: "t"}, time.Second) }()
	j, err := Expect[*Join](context.Background(), b)
	if err != nil || j.SessionID != "s1" {
		t.Fatal(j, err)
	}

	go func() { _ = Write(a, &Fail{Code: CodeUnauthorized, Message: "no"}, time.Second) }()
	_, err = Expect[*SessionInfo](context.Background(), b)
	var f *Fail
	if !errors.As(err, &f) || f.Code != CodeUnauthorized || err.Error() != "standalone: unauthorized: no" {
		t.Fatalf("fail: %v", err)
	}

	go func() { _ = Write(a, &Heartbeat{}, 0) }()
	if _, err := Expect[*SessionInfo](context.Background(), b); !errors.Is(err, ErrUnexpected) {
		t.Fatalf("unexpected: %v", err)
	}
	if (&Fail{Code: CodeBusy}).Error() != "standalone: busy" {
		t.Fatal("bare fail text")
	}
}

// TestReadContext: the end of the context interrupts a blocked read and the
// connection is usable afterwards (no stale deadline).
func TestReadContext(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := Read(ctx, b); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read: %v", err)
	}
	if _, err := Read(ctx, b); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read on a done context: %v", err)
	}
	go func() { _ = Write(a, &Heartbeat{}, time.Second) }()
	if m, err := Read(context.Background(), b); err != nil || m.Type() != TypeHeartbeat {
		t.Fatalf("after interrupt: %v %v", m, err)
	}
}

func TestWriteTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	start := time.Now()
	err := Write(a, &Heartbeat{}, 20*time.Millisecond)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("write without reader: %v after %v", err, time.Since(start))
	}
	if err := Write(a, &Fail{}, time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid message written: %v", err)
	}
}

func TestCanonicalTarget(t *testing.T) {
	good := map[string]string{
		"127.0.0.1:22":          "127.0.0.1:22",
		"[::1]:8080":            "[::1]:8080",
		"[::ffff:10.0.0.1]:443": "10.0.0.1:443",
		"[2001:DB8::0001]:1":    "[2001:db8::1]:1",
		"DB.Internal:5432":      "db.internal:5432",
		"svc.test:080":          "svc.test:80",
		"[fe80::1%eth0]:9":      "[fe80::1%eth0]:9",
	}
	for in, want := range good {
		if got, err := CanonicalTarget(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "host", ":22", "host:0", "host:65536", "host:x", "bad host:1", "a/b:1", strings.Repeat("a", 300) + ":1"} {
		if _, err := CanonicalTarget(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestAccessPolicy(t *testing.T) {
	if !(AccessPolicy{}).Allows("anything:1") {
		t.Fatal("empty policy refuses")
	}
	p := AccessPolicy{Targets: []string{"127.0.0.1:22", "db.internal:5432"}}
	for target, want := range map[string]bool{
		"127.0.0.1:22": true, "DB.internal:5432": true, "127.0.0.1:23": false, "bad": false,
	} {
		if p.Allows(target) != want {
			t.Errorf("%q: %v", target, !want)
		}
	}
}

func TestCodeRetryable(t *testing.T) {
	for c, want := range map[Code]bool{
		CodeUnauthorized: false, CodeInvalidRequest: false, CodeHostExists: false,
		CodeHostNotFound: true, CodeSessionNotFound: true, CodeBusy: true, CodeShutdown: true, CodeInternal: true,
		"from_a_newer_server": true,
	} {
		if c.Retryable() != want {
			t.Errorf("%s retryable %v", c, !want)
		}
	}
}

func TestValidName(t *testing.T) {
	for s, want := range map[string]bool{"a": true, "A.b_c-9": true, "": false, "a b": false, "ä": false, strings.Repeat("x", 64): true, strings.Repeat("x", 65): false} {
		if ValidName(s) != want {
			t.Errorf("%q: %v", s, !want)
		}
	}
}

func BenchmarkEncodeDecode(b *testing.B) {
	m := samples()[4] // SessionInfo, the largest common message
	b.ReportAllocs()
	for b.Loop() {
		frame, err := Encode(m)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := Decode(bytes.NewReader(frame)); err != nil {
			b.Fatal(err)
		}
	}
}

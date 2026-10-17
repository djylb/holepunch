package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/djylb/holepunch/internal/controlwire"
)

// FuzzDecodeMessage covers all twelve message types: any
// type byte and payload either decodes to a valid message or fails with a
// protocol-level error; a decoded message stays valid after Normalize,
// Normalize is idempotent, and re-encoding is stable (encode → decode →
// encode gives the same bytes) whenever the re-encoding fits the type's cap.
func FuzzDecodeMessage(f *testing.F) {
	for _, m := range sampleMessages() {
		fr, err := marshalFrame(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(fr.Type), fr.Payload)
	}
	var manifest []struct {
		File string `json:"file"`
		Type string `json:"type"`
	}
	raw, err := os.ReadFile("testdata/examples/manifest.json")
	if err != nil {
		f.Fatal(err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		f.Fatal(err)
	}
	for _, e := range manifest {
		p, err := os.ReadFile(filepath.Join("testdata/examples", e.File))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(messageTypeNamed(f, e.Type)), p)
	}
	f.Add(uint8(MsgPunchResult+1), []byte(`{}`)) // first reserved type
	f.Add(uint8(MsgPunchGo), []byte(`{"session_id":"a","round":2,"window_ms":9,"plan":{"round":2,"variant":"v","budget":"light","window_ms":9,"sides":[{"family":"udp4","role":"both","sockets":1,"stages":[{"kind":"direct","ttl":1,"targets":["1.2.3.4:5"]}]}]}}`))
	f.Add(uint8(MsgAssist), []byte(`{"session_id":"a","role":"initiator","from":"server","kind":"peer_targets","round":1,"family":"udp4","source":"x"}`))
	f.Fuzz(func(t *testing.T, typ uint8, payload []byte) {
		m, err := decodeFrame(controlwire.Frame{Type: controlwire.Type(typ), Payload: payload})
		if err != nil {
			var verr *ValidationError
			if !errors.As(err, &verr) && !errors.Is(err, ErrUnexpectedMessage) {
				t.Fatalf("Decode error %v (%T) is neither a ValidationError nor ErrUnexpectedMessage", err, err)
			}
			if verr != nil && verr.Reason != ReasonProtocolViolation && verr.Reason != ReasonControlVersionMismatch {
				t.Fatalf("Decode error has reason %q", verr.Reason)
			}
			return
		}
		if m.MessageType() != MessageType(typ) {
			t.Fatalf("decoded %s from type %d", m.MessageType(), typ)
		}
		if a, ok := m.(*Assist); ok {
			// What a receiver does before using an assist: a server drops the
			// fields only it may write; a client checks them.
			if a.Role != "" {
				*a, _ = a.StripServerFields()
			} else if a.ValidateRelayed() != nil {
				return
			}
		}
		normalize(t, m)
		if err := m.Validate(); err != nil {
			t.Fatalf("valid %s invalid after Normalize: %v", m.MessageType(), err)
		}
		if normalize(t, m) {
			t.Fatalf("%s: Normalize is not idempotent", m.MessageType())
		}
		f1, err := marshalFrame(m)
		if err != nil {
			if verr, ok := errors.AsType[*ValidationError](err); ok && verr.Detail == "frame_too_large" {
				return // escaping or explicit fields made the re-encoding larger than the cap
			}
			t.Fatalf("Marshal of a valid %s: %v", m.MessageType(), err)
		}
		m2, err := decodeFrame(f1)
		if err != nil {
			t.Fatalf("re-decode %s: %v\n%s", m.MessageType(), err, f1.Payload)
		}
		f2, err := marshalFrame(m2)
		if err != nil || !bytes.Equal(f1.Payload, f2.Payload) {
			t.Fatalf("unstable encoding of %s: %v\n%s\n%s", m.MessageType(), err, f1.Payload, f2.Payload)
		}
	})
}

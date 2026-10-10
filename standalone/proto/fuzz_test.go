package proto

import (
	"bytes"
	"reflect"
	"testing"
)

// FuzzDecode: arbitrary bytes never panic Decode, never make it read past
// one frame, and whatever it accepts encodes back to an equivalent message.
func FuzzDecode(f *testing.F) {
	for _, m := range samples() {
		frame, err := Encode(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(frame)
	}
	f.Add(frameOf(Version, byte(TypeOpen), `{"host_id":"h","metadata":{"k":"v"}}`))
	f.Add([]byte{Version, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		m, err := Decode(r)
		if err != nil {
			return
		}
		if used := len(data) - r.Len(); used > HeaderSize+MaxPayload {
			t.Fatalf("read %d bytes", used)
		}
		frame, err := Encode(m)
		if err != nil {
			t.Fatalf("accepted %v does not encode: %v", m.Type(), err)
		}
		again, err := Decode(bytes.NewReader(frame))
		if err != nil || !reflect.DeepEqual(again, m) {
			t.Fatalf("re-decode of %v: %+v %v", m.Type(), again, err)
		}
	})
}

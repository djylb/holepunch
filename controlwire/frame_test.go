package controlwire

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	Types map[string]struct {
		Type     int    `json:"type"`
		Sender   string `json:"sender"`
		Cap      int    `json:"cap"`
		Priority int    `json:"priority"`
	} `json:"types"`
	DiscardCap int `json:"discard_cap"`
	MaxPayload int `json:"max_payload"`
	Encode     []struct {
		Name    string `json:"name"`
		Type    int    `json:"type"`
		Payload string `json:"payload"`
		Hex     string `json:"hex"`
	} `json:"encode"`
	Decode []struct {
		Name   string `json:"name"`
		Side   string `json:"side"`
		Hex    string `json:"hex"`
		Frames []struct {
			Type    int    `json:"type"`
			Payload string `json:"payload"`
		} `json:"frames"`
		Err       string `json:"err"`
		Discarded uint64 `json:"discarded"`
	} `json:"decode"`
}

func loadVectors(t testing.TB) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/frames.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestTypeTableMatchesVectors checks the Go type table against the table the
// independent Python generator was written from.
func TestTypeTableMatchesVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.Types) != 12 {
		t.Fatalf("vector table has %d types", len(v.Types))
	}
	if v.DiscardCap != DiscardCap || v.MaxPayload != MaxPayload {
		t.Fatalf("caps: vectors %d/%d, Go %d/%d", v.DiscardCap, v.MaxPayload, DiscardCap, MaxPayload)
	}
	seen := 0
	for typ := range 256 {
		ty := Type(typ)
		inf, known := ty.info()
		if !known {
			if ty.Cap() != DiscardCap || SideClient.Sends(ty) || SideServer.Sends(ty) || SideClient.Receives(ty) || SideServer.Receives(ty) {
				t.Errorf("reserved %v: cap %d, sends %v/%v", ty, ty.Cap(), SideClient.Sends(ty), SideServer.Sends(ty))
			}
			continue
		}
		seen++
		want, ok := v.Types[ty.String()]
		if !ok {
			t.Errorf("%v (%d) missing from the vector table", ty, typ)
			continue
		}
		if want.Type != typ || want.Cap != ty.Cap() || want.Priority != int(inf.prio) {
			t.Errorf("%v: Go %d/%d/P%d, vectors %d/%d/P%d", ty, typ, ty.Cap(), inf.prio, want.Type, want.Cap, want.Priority)
		}
		client, server := SideClient.Sends(ty), SideServer.Sends(ty)
		var sender string
		switch {
		case client && server:
			sender = "both"
		case client:
			sender = "client"
		case server:
			sender = "server"
		}
		if sender != want.Sender {
			t.Errorf("%v: sender %q, vectors %q", ty, sender, want.Sender)
		}
		if SideClient.Receives(ty) != server || SideServer.Receives(ty) != client {
			t.Errorf("%v: Receives is not the mirror of Sends", ty)
		}
	}
	if seen != 12 {
		t.Fatalf("Go table has %d known types", seen)
	}
}

func TestEncodeVectors(t *testing.T) {
	for _, vec := range loadVectors(t).Encode {
		got, err := AppendFrame(nil, Frame{Type: Type(vec.Type), Payload: []byte(vec.Payload)})
		if err != nil {
			t.Errorf("%s: %v", vec.Name, err)
			continue
		}
		if hex.EncodeToString(got) != vec.Hex {
			t.Errorf("%s: got %x, want %s", vec.Name, got, vec.Hex)
		}
	}
}

func vectorError(name string) error {
	switch name {
	case "EOF":
		return io.EOF
	case "ErrUnexpectedEOF":
		return io.ErrUnexpectedEOF
	case "ErrVersion":
		return ErrVersion
	case "ErrBadMagic":
		return ErrBadMagic
	case "ErrZeroType":
		return ErrZeroType
	case "ErrFrameTooLarge":
		return ErrFrameTooLarge
	case "ErrTooManyUnknown":
		return ErrTooManyUnknown
	case "ErrFlood":
		return ErrFlood
	}
	panic("unknown vector error " + name)
}

// TestDecodeVectors replays every byte-stream vector through a Conn, whole
// and in 3-byte chunks.
func TestDecodeVectors(t *testing.T) {
	for _, vec := range loadVectors(t).Decode {
		for _, chunk := range []int{0, 3} {
			data, err := hex.DecodeString(vec.Hex)
			if err != nil {
				t.Fatal(err)
			}
			side := SideClient
			if vec.Side == "server" {
				side = SideServer
			}
			c := mustConn(t, newMemConn(data, chunk), ConnOptions{Side: side})
			var got []Frame
			var rerr error
			for {
				f, err := c.ReadFrame(context.Background())
				if err != nil {
					rerr = err
					break
				}
				got = append(got, f)
			}
			if !errors.Is(rerr, vectorError(vec.Err)) {
				t.Errorf("%s/chunk %d: error %v, want %s", vec.Name, chunk, rerr, vec.Err)
			}
			if len(got) != len(vec.Frames) {
				t.Errorf("%s/chunk %d: %d frames, want %d", vec.Name, chunk, len(got), len(vec.Frames))
			} else {
				for i, f := range got {
					if int(f.Type) != vec.Frames[i].Type || string(f.Payload) != vec.Frames[i].Payload {
						t.Errorf("%s/chunk %d: frame %d = %v %q", vec.Name, chunk, i, f.Type, f.Payload)
					}
				}
			}
			if d := c.Stats().Discarded; d != vec.Discarded {
				t.Errorf("%s/chunk %d: discarded %d, want %d", vec.Name, chunk, d, vec.Discarded)
			}
			if !errors.Is(c.Err(), vectorError(vec.Err)) {
				t.Errorf("%s/chunk %d: Err() = %v", vec.Name, chunk, c.Err())
			}
			_ = c.Close()
		}
	}
}

func TestParseHeader(t *testing.T) {
	hdr := func(magic0, magic1, major byte, typ Type, n uint32) [HeaderSize]byte {
		var h [HeaderSize]byte
		h[0], h[1], h[2], h[3] = magic0, magic1, major, byte(typ)
		binary.BigEndian.PutUint32(h[4:], n)
		return h
	}
	cases := []struct {
		name   string
		h      [HeaderSize]byte
		capFor func(Type) int
		typ    Type
		n      int
		err    error
	}{
		{"ok", hdr('h', 'p', Version, TypePunchGo, 5), nil, TypePunchGo, 5, nil},
		{"at cap", hdr('h', 'p', Version, TypePing, 256), nil, TypePing, 256, nil},
		{"over cap", hdr('h', 'p', Version, TypePing, 257), nil, 0, 0, ErrFrameTooLarge},
		{"bad magic", hdr('H', 'p', Version, TypePing, 0), nil, 0, 0, ErrBadMagic},
		{"bad magic 2", hdr('h', 'P', Version, TypePing, 0), nil, 0, 0, ErrBadMagic},
		{"major 0", hdr('h', 'p', 0, TypePing, 0), nil, 0, 0, ErrVersion},
		{"major 2", hdr('h', 'p', 2, TypePing, 0), nil, 0, 0, ErrVersion},
		{"type 0", hdr('h', 'p', Version, 0, 0), nil, 0, 0, ErrZeroType},
		{"reserved uses discard cap", hdr('h', 'p', Version, 77, DiscardCap), nil, 77, DiscardCap, nil},
		{"reserved over discard cap", hdr('h', 'p', Version, 77, DiscardCap+1), nil, 0, 0, ErrFrameTooLarge},
		{"capFor tighter", hdr('h', 'p', Version, TypeProbeSummary, 100), func(Type) int { return 99 }, 0, 0, ErrFrameTooLarge},
		{"capFor cannot exceed global", hdr('h', 'p', Version, TypeProbeSummary, MaxPayload+1), func(Type) int { return 1 << 30 }, 0, 0, ErrFrameTooLarge},
		{"huge length", hdr('h', 'p', Version, TypeProbeSummary, ^uint32(0)), nil, 0, 0, ErrFrameTooLarge},
	}
	for _, tc := range cases {
		typ, n, err := ParseHeader(tc.h, tc.capFor)
		if !errors.Is(err, tc.err) {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.err)
			continue
		}
		if err == nil && (typ != tc.typ || n != tc.n) {
			t.Errorf("%s: got %v/%d", tc.name, typ, n)
		}
	}
}

func TestAppendFrameChecks(t *testing.T) {
	if _, err := AppendFrame(nil, Frame{}); !errors.Is(err, ErrZeroType) {
		t.Fatalf("type 0: %v", err)
	}
	for typ := range 256 {
		ty := Type(typ)
		if ty == 0 {
			continue
		}
		if _, err := AppendFrame(nil, Frame{Type: ty, Payload: make([]byte, ty.Cap())}); err != nil {
			t.Fatalf("%v at cap: %v", ty, err)
		}
		if _, err := AppendFrame(nil, Frame{Type: ty, Payload: make([]byte, ty.Cap()+1)}); !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("%v over cap: %v", ty, err)
		}
	}
	dst := []byte("prefix")
	out, _ := AppendFrame(dst, Frame{Type: TypePing, Payload: []byte("{}")})
	if string(out[:6]) != "prefix" || len(out) != 6+HeaderSize+2 {
		t.Fatalf("AppendFrame did not append: %q", out)
	}
}

func TestTypeStrings(t *testing.T) {
	if TypePunchGo.String() != "punch_go" || Type(200).String() != "type(200)" {
		t.Fatal(TypePunchGo.String(), Type(200).String())
	}
	if SideClient.String() != "client" || SideServer.String() != "server" {
		t.Fatal("side names")
	}
}

// TestOversizeReadsOnlyHeader sends a Cap+1 header for every type on both
// sides: exactly the 8 header bytes are read and the link fails with
// ErrFrameTooLarge.
func TestOversizeReadsOnlyHeader(t *testing.T) {
	for _, side := range []Side{SideClient, SideServer} {
		for typ := 1; typ <= 14; typ++ {
			ty := Type(typ)
			limit := ty.Cap()
			if !side.Receives(ty) {
				limit = DiscardCap
			}
			stream := rawFrame(Version, ty, "")
			binary.BigEndian.PutUint32(stream[4:], uint32(limit+1))
			stream = append(stream, strings.Repeat("x", 64)...)
			mc := newMemConn(stream, 0)
			c := mustConn(t, mc, ConnOptions{Side: side})
			<-c.Done()
			if !errors.Is(c.Err(), ErrFrameTooLarge) {
				t.Fatalf("%v/%v: %v", side, ty, c.Err())
			}
			if read := len(stream) - mc.r.Len(); read != HeaderSize {
				t.Fatalf("%v/%v: read %d bytes, want %d", side, ty, read, HeaderSize)
			}
			_ = c.Close()
		}
	}
}

// TestOversizeAllocatesNoPayload: rejecting a header that announces 64 KiB
// allocates far less than the payload would need.
func TestOversizeAllocatesNoPayload(t *testing.T) {
	stream := rawFrame(Version, TypeProbeSummary, "")
	binary.BigEndian.PutUint32(stream[4:], MaxPayload)
	const runs = 50
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range runs {
		c, err := NewConn(newMemConn(stream, 0), ConnOptions{Side: SideServer})
		if err != nil {
			t.Fatal(err)
		}
		<-c.Done()
		_ = c.Close()
	}
	runtime.ReadMemStats(&after)
	perConn := (after.TotalAlloc - before.TotalAlloc) / runs
	if perConn > 16<<10 {
		t.Fatalf("%d bytes allocated per rejected frame: the payload was allocated", perConn)
	}
}

// TestFrameAtUsesNow: Frame.At comes from ConnOptions.Now, taken after the
// frame was read completely.
func TestFrameAtUsesNow(t *testing.T) {
	fixed := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	c := mustConn(t, newMemConn(frameBytes(TypePunchGo, "{}"), 0), ConnOptions{Now: func() time.Time { return fixed }})
	f, err := c.ReadFrame(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !f.At.Equal(fixed) {
		t.Fatalf("At = %v", f.At)
	}
}

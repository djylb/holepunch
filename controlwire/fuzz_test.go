package controlwire

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/life"
)

func FuzzParseHeader(f *testing.F) {
	f.Add([]byte("hp\x01\x05\x00\x00\x00\x02"))
	f.Add([]byte("hp\x01\x00\x00\x00\x00\x00"))
	f.Add([]byte("hp\x02\x01\x00\x00\x00\x00"))
	f.Add([]byte("HP\x01\x01\x00\x00\x00\x00"))
	f.Add([]byte("hp\x01\xc8\xff\xff\xff\xff"))
	f.Fuzz(func(t *testing.T, b []byte) {
		var h [HeaderSize]byte
		copy(h[:], b)
		typ, n, err := ParseHeader(h, nil)
		if err != nil {
			for _, known := range []error{ErrBadMagic, ErrVersion, ErrZeroType, ErrFrameTooLarge} {
				if errors.Is(err, known) {
					return
				}
			}
			t.Fatalf("unexpected error %v", err)
		}
		if h[0] != 'h' || h[1] != 'p' || h[2] != Version || typ == 0 || typ != Type(h[3]) {
			t.Fatalf("accepted a bad header % x", h)
		}
		if n != int(binary.BigEndian.Uint32(h[4:])) || n > typ.Cap() || n > MaxPayload {
			t.Fatalf("length %d accepted for %v", n, typ)
		}
	})
}

// FuzzReadFrame feeds an arbitrary byte stream, in arbitrary chunks, to a Conn
// on either side. It must not panic or hang; every delivered frame must be an
// accepted type within its cap; the terminal error must be one of the
// documented ones; Close must return.
func FuzzReadFrame(f *testing.F) {
	for _, vec := range loadVectors(f).Decode {
		data, err := hex.DecodeString(vec.Hex)
		if err != nil {
			f.Fatal(err)
		}
		if len(data) < 2048 {
			f.Add(data, uint8(0), vec.Side == "server")
			f.Add(data, uint8(3), vec.Side == "server")
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8, server bool) {
		side := SideClient
		if server {
			side = SideServer
		}
		c, err := NewConn(newMemConn(data, int(chunk)), ConnOptions{Side: side})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if s := c.g.Stats(); s.Running != 0 || s.Leaked != 0 || s.Panics != 0 {
				t.Fatalf("goroutines after Close: %+v", s)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		frames := 0
		for {
			fr, err := c.ReadFrame(ctx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("reading did not terminate")
				}
				var perr *life.PanicError
				if errors.As(err, &perr) {
					t.Fatalf("panic while reading: %v", err)
				}
				for _, known := range []error{io.EOF, io.ErrUnexpectedEOF, ErrBadMagic, ErrVersion, ErrZeroType,
					ErrFrameTooLarge, ErrTooManyUnknown, ErrFlood} {
					if errors.Is(err, known) {
						return
					}
				}
				t.Fatalf("unexpected terminal error %v", err)
			}
			frames++
			if !side.Receives(fr.Type) || len(fr.Payload) > fr.Type.Cap() {
				t.Fatalf("delivered %v with %d bytes on the %v side", fr.Type, len(fr.Payload), side)
			}
			if frames > DefaultMaxFrames {
				t.Fatal("more frames than the link limit")
			}
		}
	})
}

package controlwire

import (
	"context"
	"net"
	"testing"
)

func BenchmarkParseHeader(b *testing.B) {
	h := [HeaderSize]byte{'h', 'p', Version, byte(TypePunchGo), 0, 0, 1, 0}
	for b.Loop() {
		if _, _, err := ParseHeader(h, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAppendFrame(b *testing.B) {
	payload := make([]byte, 200)
	buf := make([]byte, 0, 512)
	b.ReportAllocs()
	for b.Loop() {
		buf, _ = AppendFrame(buf[:0], Frame{Type: TypeAssist, Payload: payload})
	}
}

// BenchmarkControlFrameRoundTrip: a 200-byte frame queued with Send on one
// Conn and taken from ReadFrame on the other, over net.Pipe.
func BenchmarkControlFrameRoundTrip(b *testing.B) {
	cs, ss := net.Pipe()
	client := mustConn(b, cs, ConnOptions{Side: SideClient})
	server := mustConn(b, ss, ConnOptions{Side: SideServer, MaxFrames: 1 << 30}) // beyond the per-link limit
	payload := make([]byte, 200)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if err := client.Send(Frame{Type: TypeAssist, Payload: payload}); err != nil {
			b.Fatal(err)
		}
		if _, err := server.ReadFrame(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

package udpwire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// foreignSamples returns datagrams of other UDP protocols, each starting
// with that protocol's real first byte(s).
func foreignSamples() map[string][]byte {
	pad := func(prefix []byte, n int) []byte {
		b := make([]byte, n)
		copy(b, prefix)
		for i := len(prefix); i < n; i++ {
			b[i] = byte(i*7 + 3)
		}
		return b
	}
	quicInitial := append([]byte{0xC3, 0, 0, 0, 1, 8}, bytes.Repeat([]byte{0xAB}, 8)...) // long header, v1, DCID
	stun := binary.BigEndian.AppendUint32([]byte{0x00, 0x01, 0x00, 0x00}, 0x2112A442)    // Binding request
	return map[string][]byte{
		"QUIC long header Initial":    pad(quicInitial, 1200),
		"QUIC long header 0-RTT":      pad([]byte{0xD1, 0, 0, 0, 1}, 300),
		"QUIC version negotiation":    pad([]byte{0x80, 0, 0, 0, 0}, 100),
		"QUIC short header":           pad([]byte{0x43}, 100),
		"QUIC short header max":       pad([]byte{0x7F}, 1400),
		"STUN binding request":        pad(stun, 20),
		"STUN with attributes":        pad(stun, 120),
		"STUN success response":       pad([]byte{0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42}, 100),
		"DTLS ClientHello":            pad([]byte{0x16, 0xFE, 0xFD, 0, 0}, 200),
		"DTLS application data":       pad([]byte{0x17, 0xFE, 0xFD, 0, 1}, 1000),
		"WireGuard initiation":        pad([]byte{0x01, 0, 0, 0}, 148),
		"WireGuard response":          pad([]byte{0x02, 0, 0, 0}, 92),
		"WireGuard cookie reply":      pad([]byte{0x03, 0, 0, 0}, 64),
		"WireGuard transport (b0=4)":  pad([]byte{0x04, 0, 0, 0}, 128),
		"WireGuard transport large":   pad([]byte{0x04, 0, 0, 0}, 1000),
		"WireGuard keepalive (short)": pad([]byte{0x04, 0, 0, 0}, 32),
		"RTP":                         pad([]byte{0x80, 0x60}, 172),
		"Tailscale disco":             pad([]byte{0x54, 0x53, 0xF0, 0x9F, 0x92, 0xAC}, 100),
		"empty":                       {},
	}
}

// TestForeignPacketsRejected feeds random bytes and other protocols'
// first-byte samples to both receivers: nothing is ever accepted, the client
// classifies into {short, foreign, auth} and natprobe into
// {short, foreign, route}.
func TestForeignPacketsRejected(t *testing.T) {
	client, nat := newCodec(t, RoleInitiator), newCodec(t, RoleServer)
	scratch := make([]byte, MaxPlaintext)
	var h Header
	var tl TLVs
	clientClasses := map[DecodeError]int{}
	natClasses := map[DecodeError]int{}
	check := func(name string, pkt []byte) {
		ce := client.Open(pkt, scratch, &h, &tl)
		ne := nat.OpenProbe(pkt, scratch, &h, &tl)
		if ce != ErrShort && ce != ErrForeign && ce != ErrAuth {
			t.Fatalf("%s: client %v", name, ce)
		}
		if ne != ErrShort && ne != ErrForeign && ne != ErrRoute {
			t.Fatalf("%s: natprobe %v", name, ne)
		}
		clientClasses[ce]++
		natClasses[ne]++
	}
	for name, pkt := range foreignSamples() {
		check(name, pkt)
	}

	r := newRand(8)
	pool := make([]byte, 1<<20)
	for i := range pool {
		pool[i] = byte(r.Uint32())
	}
	for i := range iterations(1000000) {
		n := r.IntN(160)
		if i%16 == 0 {
			n = r.IntN(maxProbePacket + 64)
		}
		off := r.IntN(len(pool) - n)
		pkt := pool[off : off+n]
		if i%4 == 0 && n > 0 {
			// Force b0 into range so the AEAD and the route check are reached.
			pkt[0] = B0Min + byte(r.IntN(b0Count))
		}
		check("random", pkt)
	}
	for _, e := range []DecodeError{ErrShort, ErrForeign, ErrAuth} {
		if clientClasses[e] == 0 {
			t.Errorf("client never classified %v: %v", e, clientClasses)
		}
	}
	for _, e := range []DecodeError{ErrShort, ErrForeign, ErrRoute} {
		if natClasses[e] == 0 {
			t.Errorf("natprobe never classified %v: %v", e, natClasses)
		}
	}
}

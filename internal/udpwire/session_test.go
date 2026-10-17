package udpwire

import (
	"bytes"
	"fmt"
	"testing"
)

// sessionTraffic seals a session's mixed traffic: initiator punches,
// responder punch-class packets, initiator probes and server acks.
func sessionTraffic(tb testing.TB, ini, resp, srv *Codec, punches, others int) map[string][][]byte {
	tb.Helper()
	groups := map[string][][]byte{}
	add := func(c *Codec, typ Type, plainLen int, edit func(*Header)) {
		h, t := headerFor(c, typ), tlvsFor(typ)
		if edit != nil {
			edit(&h)
		}
		pkt, err := c.Seal(nil, &h, &t, plainLen)
		if err != nil {
			tb.Fatalf("Seal type %d: %v", typ, err)
		}
		key := groupKey(c.role, typ)
		groups[key] = append(groups[key], pkt)
	}
	for range punches {
		add(ini, TPunch, 0, nil)
	}
	respTypes := []Type{TPunch, TSuccess, TAccept, THandoverAck, THairpin}
	for i := range others {
		add(resp, respTypes[i%len(respTypes)], 0, nil)
		add(ini, TProbe, 0, func(h *Header) { h.FA = i%2 == 0 })
		ack, _ := ReplyLengths(189, false, false, nil)
		add(srv, TProbeAck, ack, nil)
	}
	return groups
}

func groupKey(r Role, t Type) string { return fmt.Sprintf("role %d, type %d", r, t) }

// TestNoConstantFieldInSession checks that within one session no byte
// position holds the same value in every packet. Positions after b0 must look
// uniformly random (hundreds of distinct values), b0 covers [B0Min, B0Max]
// uniformly (χ², p > 0.01) and is never a QUIC first byte, nonces never
// repeat, and probes' masked routes are pairwise distinct.
func TestNoConstantFieldInSession(t *testing.T) {
	ini, resp, srv := newCodec(t, RoleInitiator), newCodec(t, RoleResponder), newCodec(t, RoleServer)
	groups := sessionTraffic(t, ini, resp, srv, 10000, 2000)

	var session [][]byte
	for name, pkts := range groups {
		session = append(session, pkts...)
		assertNoConstantPosition(t, name, pkts)
	}
	assertNoConstantPosition(t, "whole session", session)

	for name, pkts := range map[string][][]byte{"initiator punches": groups[groupKey(RoleInitiator, TPunch)], "whole session": session} {
		var counts [b0Count]int
		for _, p := range pkts {
			counts[p[0]-B0Min]++
		}
		if x := chiSquare(counts[:], len(pkts)); x >= chiSquare11At01 {
			t.Errorf("%s: b0 χ² = %.2f over %d packets, counts %v", name, x, len(pkts), counts)
		}
	}

	nonces := map[[NonceSize]byte]bool{}
	for _, p := range session {
		n := [NonceSize]byte(p[1:PeerOuterSize])
		if nonces[n] {
			t.Fatalf("nonce %x repeated", n)
		}
		nonces[n] = true
		if potential, long := quicBits(p[0]); potential || long {
			t.Fatalf("b0 %#x is a QUIC first byte", p[0])
		}
	}
	route := testRoute()
	for _, p := range session {
		if bytes.Contains(p, route[:]) {
			t.Fatalf("route in clear on the wire: %x", p)
		}
	}
	mroutes := map[[RouteSize]byte]bool{}
	for _, p := range groups[groupKey(RoleInitiator, TProbe)] {
		m := [RouteSize]byte(p[PeerOuterSize:ProbeOuterSize])
		if mroutes[m] {
			t.Fatalf("mroute %x repeated", m)
		}
		mroutes[m] = true
	}

	// Across many sessions: none has a constant position either.
	r := newRand(77)
	for s := range 100 {
		tok, route := randomSession(r)
		pad := NewPadPolicy(r)
		groups := sessionTraffic(t,
			newSessionCodec(t, tok, route, RoleInitiator, pad),
			newSessionCodec(t, tok, route, RoleResponder, pad),
			newSessionCodec(t, tok, route, RoleServer, PadPolicy{}), 60, 60)
		var all [][]byte
		for _, pkts := range groups {
			all = append(all, pkts...)
		}
		assertNoConstantPosition(t, fmt.Sprint("session ", s), all)
	}
}

// constantPosition returns the first byte position, among those all pkts
// share, that holds one value throughout, or -1.
func constantPosition(pkts [][]byte) int {
	shortest := len(pkts[0])
	for _, p := range pkts {
		shortest = min(shortest, len(p))
	}
	for pos := range shortest {
		same := true
		for _, p := range pkts[1:] {
			if p[pos] != pkts[0][pos] {
				same = false
				break
			}
		}
		if same {
			return pos
		}
	}
	return -1
}

// assertNoConstantPosition fails if any byte position shared by all pkts
// holds one value throughout. For large groups it demands near-uniform
// diversity: random bytes over ≥ 1000 packets show far more than 128 values.
func assertNoConstantPosition(t *testing.T, name string, pkts [][]byte) {
	t.Helper()
	if len(pkts) < 16 {
		t.Fatalf("%s: only %d packets", name, len(pkts))
	}
	if pos := constantPosition(pkts); pos >= 0 {
		t.Fatalf("%s: byte %d is constant (%#x) over %d packets", name, pos, pkts[0][pos], len(pkts))
	}
	if len(pkts) < 1000 {
		return
	}
	for pos := range MinPeerPacket {
		var seen [256]bool
		distinct := 0
		for _, p := range pkts {
			if !seen[p[pos]] {
				seen[p[pos]] = true
				distinct++
			}
		}
		switch {
		case pos == 0 && distinct != b0Count:
			t.Fatalf("%s: b0 takes %d values, want %d", name, distinct, b0Count)
		case pos > 0 && distinct < 128:
			t.Fatalf("%s: byte %d takes only %d values over %d packets", name, pos, distinct, len(pkts))
		}
	}
}

// TestConstantScanDetects is the negative control of the constant-position
// scan: a clear route prefix or a single fixed byte anywhere is reported at
// its offset.
func TestConstantScanDetects(t *testing.T) {
	r := newRand(12)
	route := testRoute()
	random := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return b
	}
	var prefixed, fixed [][]byte
	for range 64 {
		p := random(120)
		copy(p, route[:]) // route in clear at offset 0
		prefixed = append(prefixed, p)
		q := random(90 + r.IntN(30))
		q[40] = 0x5A
		fixed = append(fixed, q)
	}
	if pos := constantPosition(prefixed); pos != 0 {
		t.Errorf("clear route prefix reported at %d, want 0", pos)
	}
	if pos := constantPosition(fixed); pos != 40 {
		t.Errorf("fixed byte reported at %d, want 40", pos)
	}
}

// TestSessionLengthIntervals checks that two sessions with different
// PadPolicies produce different length ranges, each spanning exactly its
// session interval (wire = 29 + plaintext).
func TestSessionLengthIntervals(t *testing.T) {
	pads := [2]PadPolicy{NewPadPolicy(newRand(1)), NewPadPolicy(newRand(2))}
	if pads[0] == pads[1] {
		t.Fatalf("seeds gave equal policies %+v", pads[0])
	}
	var ranges [2][2]int
	for i, pad := range pads {
		tok, route := randomSession(newRand(uint64(10 + i)))
		c := newSessionCodec(t, tok, route, RoleInitiator, pad)
		lo, hi := 1<<30, 0
		for range 5000 {
			h := headerFor(c, TPunch)
			n := len(mustSeal(t, c, &h, nil))
			lo, hi = min(lo, n), max(hi, n)
		}
		want := [2]int{replyOverhead + int(pad.Min), replyOverhead + int(pad.Max)}
		if [2]int{lo, hi} != want {
			t.Errorf("session %d (%+v): wire lengths [%d, %d], want %v", i, pad, lo, hi, want)
		}
		ranges[i] = [2]int{lo, hi}
	}
	if ranges[0] == ranges[1] {
		t.Errorf("two sessions share the length range %v", ranges[0])
	}
}

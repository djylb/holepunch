package udpwire

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// plaintext builds a raw plaintext: an encoded header (then edited by
// mutate), the given TLV bytes, and zero padding to n bytes.
func plaintext(typ Type, role Role, tlvs []byte, n int, mutate func(hdr []byte)) []byte {
	h := Header{Type: typ, Role: role, Seq: 1, Cand: NoCand}
	b := make([]byte, max(n, HeaderSize+len(tlvs)))
	h.put(b)
	if mutate != nil {
		mutate(b[:HeaderSize])
	}
	copy(b[HeaderSize:], tlvs)
	return b
}

func observedTLV(addr [16]byte, port uint16) []byte {
	v := append([]byte{tlvObserved, observedSize}, addr[:]...)
	return binary.BigEndian.AppendUint16(v, port)
}

func v4Mapped(a, b, c, d byte) [16]byte {
	return [16]byte{10: 0xff, 11: 0xff, 12: a, 13: b, 14: c, 15: d}
}

// TestPayloadErrors checks the payload parse: authentic packets with structural
// faults are ErrPayload, and h/t come back zeroed.
func TestPayloadErrors(t *testing.T) {
	c := newCodec(t, RoleServer)
	obs := observedTLV(v4Mapped(192, 0, 2, 1), 4000)
	ackTLVs := append(append(bytes.Clone(obs), tlvExtraPort, 2, 0, 0), tlvCookie, 4, 0, 0, 0, 0)
	setFlags := func(f byte) func([]byte) { return func(h []byte) { h[1] |= f } }
	cases := []struct {
		name  string
		plain []byte
		probe bool
	}{
		{"type 0", plaintext(TPunch, RoleInitiator, nil, 40, func(h []byte) { h[0] = 0 }), false},
		{"type after last", plaintext(TPunch, RoleInitiator, nil, 40, func(h []byte) { h[0] = byte(THandoverAck + 1) }), false},
		{"type 255", plaintext(TPunch, RoleInitiator, nil, 40, func(h []byte) { h[0] = 255 }), false},
		{"reserved flag", plaintext(TPunch, RoleInitiator, nil, 40, setFlags(flagReserved)), false},
		{"role 0", plaintext(TPunch, RoleInitiator, nil, 40, func(h []byte) { h[1] &^= flagRole }), false},
		{"server punch", plaintext(TPunch, RoleServer, nil, 40, nil), false},
		{"responder nominate", plaintext(TNominate, RoleResponder, nil, 40, nil), false},
		{"initiator handover_ack", plaintext(THandoverAck, RoleInitiator, nil, 40, nil), false},
		{"client probe_ack", plaintext(TProbeAck, RoleInitiator, ackTLVs, 60, nil), false},
		{"FA on punch", plaintext(TPunch, RoleInitiator, nil, 40, setFlags(flagFA)), false},
		{"FC on extra", plaintext(TProbeExtra, RoleServer, obs, 60, setFlags(flagFC)), false},
		{"FC on probe", plaintext(TProbe, RoleInitiator, nil, 100, setFlags(flagFC)), true},
		{"FA and FB on probe", plaintext(TProbe, RoleInitiator, nil, 200, setFlags(flagFA|flagFB)), true},
		{"FA and FB on ack", plaintext(TProbeAck, RoleServer, ackTLVs, 60, setFlags(flagFA|flagFB)), false},
		{"probe in envelope S", plaintext(TProbe, RoleInitiator, nil, 100, nil), false},
		{"punch in envelope P", plaintext(TPunch, RoleInitiator, nil, 100, nil), true},
		{"TLV header overrun", plaintext(TPunch, RoleInitiator, []byte{0x09}, 0, nil), false},
		{"TLV value overrun", plaintext(TPunch, RoleInitiator, []byte{0x09, 5, 1, 2}, 0, nil), false},
		{"ack without OBSERVED", plaintext(TProbeAck, RoleServer, nil, MinAckPlaintext, nil), false},
		{"ack without COOKIE", plaintext(TProbeAck, RoleServer, append(bytes.Clone(obs), tlvExtraPort, 2, 0, 0), MinAckPlaintext, nil), false},
		{"ack without EXTRA_PORT", plaintext(TProbeAck, RoleServer, append(bytes.Clone(obs), tlvCookie, 4, 0, 0, 0, 0), MinAckPlaintext, nil), false},
		{"extra without OBSERVED", plaintext(TProbeExtra, RoleServer, []byte{0x09, 0}, MinExtraPlaintext, nil), false},
		{"OBSERVED length 17", plaintext(TProbeAlt, RoleServer, append([]byte{tlvObserved, 17}, make([]byte, 17)...), 60, nil), false},
		{"OBSERVED port 0", plaintext(TSuccess, RoleInitiator, observedTLV(v4Mapped(192, 0, 2, 1), 0), 60, nil), false},
		{"OBSERVED unspecified", plaintext(TSuccess, RoleInitiator, observedTLV([16]byte{}, 80), 60, nil), false},
		{"OBSERVED v4-mapped 0.0.0.0", plaintext(TSuccess, RoleInitiator, observedTLV(v4Mapped(0, 0, 0, 0), 80), 60, nil), false},
		{"SANDWICH phase 3 (second refresh probe)", plaintext(TProbe, RoleInitiator, []byte{tlvSandwich, 2, 1, 3}, 100, nil), false},
		{"SANDWICH phase 4", plaintext(TProbe, RoleInitiator, []byte{tlvSandwich, 2, 1, 4}, 100, nil), true},
		{"SANDWICH length 3", plaintext(TProbe, RoleInitiator, []byte{tlvSandwich, 3, 1, 0, 0}, 100, nil), true},
		{"RX_COUNT length 3", plaintext(TAccept, RoleResponder, []byte{tlvRxCount, 3, 0, 0, 1}, 40, nil), false},
		{"EXTRA_PORT length 4", plaintext(TProbeAck, RoleServer, append(bytes.Clone(obs), tlvExtraPort, 4, 0, 0, 0, 0), 60, nil), false},
		{"PATH_SLOT 0", plaintext(TNominate, RoleInitiator, []byte{tlvPathSlot, 1, 0}, 40, nil), false},
		{"PATH_SLOT past the last", plaintext(TAccept, RoleResponder, []byte{tlvPathSlot, 1, maxPathSlot + 1}, 40, nil), false},
		{"PATH_SLOT length 2", plaintext(TNominate, RoleInitiator, []byte{tlvPathSlot, 2, 1, 0}, 40, nil), false},
		{"PATHS 0", plaintext(TReady, RoleInitiator, []byte{tlvPaths, 1, 0}, 40, nil), false},
		{"PATHS length 2", plaintext(TAccept, RoleResponder, []byte{tlvPaths, 2, 1, 1}, 40, nil), false},
	}
	for _, tc := range cases {
		pkt := sealPlain(c, tc.plain, tc.probe, B0Min+3)
		h, tl := Header{Seq: 99}, TLVs{Cookie: 99}
		if got := open(c, pkt, tc.probe, &h, &tl); got != ErrPayload {
			t.Errorf("%s: %v, want payload", tc.name, got)
		}
		if h != (Header{}) || tl != (TLVs{}) {
			t.Errorf("%s: fields not cleared: %+v %+v", tc.name, h, tl)
		}
	}
}

// TestTLVLeniency checks what the parser deliberately tolerates.
func TestTLVLeniency(t *testing.T) {
	c := newCodec(t, RoleServer)
	obsA := observedTLV(v4Mapped(192, 0, 2, 1), 4000)
	obsB := observedTLV(v4Mapped(192, 0, 2, 2), 5000)
	first := TLVs{}
	first.Observed = netip.MustParseAddrPort("192.0.2.1:4000")
	cases := []struct {
		name  string
		typ   Type
		role  Role
		tlvs  []byte
		n     int
		check func(TLVs) bool
	}{
		{"unknown and experimental codes skipped", TProbeExtra, RoleServer,
			append([]byte{0x08, 3, 1, 2, 3, 0x80, 0, 0xFF, 1, 9}, obsA...), 80,
			func(tl TLVs) bool { return tl == first }},
		{"duplicate keeps first", TProbeExtra, RoleServer, append(bytes.Clone(obsA), obsB...), 80,
			func(tl TLVs) bool { return tl == first }},
		{"code not carried by type skipped", TPunch, RoleInitiator,
			[]byte{tlvCookie, 4, 1, 2, 3, 4, tlvObserved, 3, 1, 2, 3}, 40,
			func(tl TLVs) bool { return tl == TLVs{} }},
		{"padding content not inspected", TPunch, RoleInitiator, []byte{tlvPad, 0xAA, 0x01, 0xFF}, 40,
			func(tl TLVs) bool { return tl == TLVs{} }},
		{"TLVs end exactly at plaintext end", TAccept, RoleResponder, []byte{tlvRxCount, 4, 0, 0, 0, 7}, 0,
			func(tl TLVs) bool { return tl.HasRx && tl.RxCount == 7 }},
		{"PATH_SLOT not carried by ready skipped", TReady, RoleInitiator, []byte{tlvPathSlot, 1, 9, tlvPaths, 1, 6}, 40,
			func(tl TLVs) bool { return tl == TLVs{Paths: 6} }},
		{"PATHS on ready is any non-zero set", TReady, RoleInitiator, []byte{tlvPaths, 1, 0xFF}, 40,
			func(tl TLVs) bool { return tl == TLVs{Paths: 0xFF} }},
	}
	for _, tc := range cases {
		pkt := sealPlain(c, plaintext(tc.typ, tc.role, tc.tlvs, tc.n, nil), false, B0Max)
		var h Header
		var tl TLVs
		if got := c.Open(pkt, nil, &h, &tl); got != OK || !tc.check(tl) {
			t.Errorf("%s: %v %+v", tc.name, got, tl)
		}
	}
}

// TestTamperRejected flips every bit of a sealed packet of each envelope: no
// flip is accepted, and each is classified at the right receive step.
func TestTamperRejected(t *testing.T) {
	ini, srv := newCodec(t, RoleInitiator), newCodec(t, RoleServer)
	sh, st := headerFor(ini, TSuccess), tlvsFor(TSuccess)
	ph, pt := headerFor(ini, TProbe), tlvsFor(TProbe)
	for _, env := range []struct {
		name  string
		pkt   []byte
		probe bool
	}{
		{"S", mustSeal(t, ini, &sh, &st), false},
		{"P", mustSeal(t, ini, &ph, &pt), true},
	} {
		for i := range len(env.pkt) * 8 {
			pkt := bytes.Clone(env.pkt)
			pkt[i/8] ^= 1 << (i % 8)
			var h Header
			var tl TLVs
			got := open(srv, pkt, env.probe, &h, &tl)
			want := ErrAuth
			switch byteAt := i / 8; {
			case byteAt == 0 && (pkt[0] < B0Min || pkt[0] > B0Max):
				want = ErrForeign
			case env.probe && byteAt >= 1 && byteAt < ProbeOuterSize:
				want = ErrRoute // the nonce feeds the mask, so it unmasks another route
			}
			if got != want {
				t.Fatalf("envelope %s bit %d: %v, want %v", env.name, i, got, want)
			}
		}
		// Truncation and extension change the tag position: never accepted.
		for _, pkt := range [][]byte{env.pkt[:len(env.pkt)-1], env.pkt[:len(env.pkt)-TagSize], append(bytes.Clone(env.pkt), 0)} {
			if got := open(srv, bytes.Clone(pkt), env.probe, nil, nil); got != ErrAuth && got != ErrShort {
				t.Fatalf("envelope %s length %d: %v", env.name, len(pkt), got)
			}
		}
	}
}

// receiver is the client/natprobe receive pipeline without the rate
// stage: open, role check, replay window per sender role.
type receiver struct {
	c   *Codec
	win [RoleServer + 1]SeqWindow
}

func (r *receiver) deliver(pkt []byte, probe bool) DecodeError {
	var h Header
	var t TLVs
	if e := open(r.c, pkt, probe, &h, &t); e != OK {
		return e
	}
	if e := r.c.CheckRole(&h); e != OK {
		return e
	}
	if !r.win[h.Role].Accept(h.Seq) {
		return ErrReplay
	}
	return OK
}

// codecWithInfo returns a codec of the vector session whose key is derived
// with another HKDF info string, as another protocol version would.
func codecWithInfo(t *testing.T, role Role, info string) *Codec {
	t.Helper()
	tok, route := testToken(), testRoute()
	c := newCodec(t, role)
	c.aead = gcmFor(t, rfc5869(tok[:], route[:], []byte(info), 32))
	return c
}

// TestOtherVersionsRejected: packets keyed with any other info string — other
// major versions, the old "holepunch v2" naming, a near miss — fail as
// ErrAuth on both envelopes, because the version lives only in the key.
func TestOtherVersionsRejected(t *testing.T) {
	resp, srv := newCodec(t, RoleResponder), newCodec(t, RoleServer)
	for _, info := range []string{"holepunch/0 udp aead", "holepunch/2 udp aead", "holepunch v2 udp aead", "holepunch/1 udp aead "} {
		other := codecWithInfo(t, RoleInitiator, info)
		punch, probe := headerFor(other, TPunch), headerFor(other, TProbe)
		if e := resp.Open(mustSeal(t, other, &punch, nil), nil, nil, nil); e != ErrAuth {
			t.Errorf("%q punch: %v", info, e)
		}
		if e := srv.OpenProbe(mustSeal(t, other, &probe, nil), nil, nil, nil); e != ErrAuth {
			t.Errorf("%q probe: %v", info, e)
		}
	}
}

// TestDecodeClassification checks that one packet per drop class reaches its
// class through the pipeline, and short, foreign and route never reach the
// AEAD.
func TestDecodeClassification(t *testing.T) {
	tok, route := testToken(), testRoute()
	ini, resp := newCodec(t, RoleInitiator), newCodec(t, RoleResponder)
	counter := &countingAEAD{AEAD: ini.aead}
	ini.aead = counter
	rx := &receiver{c: ini}

	punch := headerFor(resp, TPunch)
	good := mustSeal(t, resp, &punch, nil)
	if e := rx.deliver(bytes.Clone(good), false); e != OK {
		t.Fatalf("legitimate punch: %v", e)
	}

	otherTok := tok
	otherTok[31] ^= 0xFF
	oldSession := newSessionCodec(t, otherTok, route, RoleResponder, testPad)
	otherTok2, otherRoute := randomSession(newRand(9))
	otherSession := newSessionCodec(t, otherTok2, otherRoute, RoleResponder, testPad)
	nextMajor := codecWithInfo(t, RoleResponder, "holepunch/2 udp aead")
	own := headerFor(ini, TPunch)
	reflected := mustSeal(t, ini, &own, nil)

	sealFrom := func(c *Codec) []byte {
		h := headerFor(c, TPunch)
		return mustSeal(t, c, &h, nil)
	}
	foreign := bytes.Clone(good)
	foreign[0] = 0x45 // a QUIC short-header first byte
	cases := []struct {
		name     string
		pkt      []byte
		want     DecodeError
		useAEAD  bool
		probeEnv bool
	}{
		{"short", good[:MinPeerPacket-1], ErrShort, false, false},
		{"foreign first byte", foreign, ErrForeign, false, false},
		{"foreign oversize", append(bytes.Clone(good), make([]byte, maxPeerPacket)...), ErrForeign, false, false},
		{"old session (other token)", sealFrom(oldSession), ErrAuth, true, false},
		{"other session", sealFrom(otherSession), ErrAuth, true, false},
		{"other major version", sealFrom(nextMajor), ErrAuth, true, false},
		{"payload", sealPlain(resp, plaintext(TPunch, RoleResponder, nil, 40, func(h []byte) { h[1] |= flagReserved }), false, B0Min), ErrPayload, true, false},
		{"role (own punch reflected)", reflected, ErrRole, true, false},
		{"replay", bytes.Clone(good), ErrReplay, true, false},
	}
	for _, tc := range cases {
		before := counter.count()
		if got := rx.deliver(tc.pkt, tc.probeEnv); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
		if used := counter.count() > before; used != tc.useAEAD {
			t.Errorf("%s: AEAD used = %v, want %v", tc.name, used, tc.useAEAD)
		}
	}

	// natprobe: an unknown route is classified before decryption.
	srv := newCodec(t, RoleServer)
	srvCounter := &countingAEAD{AEAD: srv.aead}
	srv.aead = srvCounter
	nat := &receiver{c: srv}
	probeFrom := func(c *Codec) []byte {
		h := headerFor(c, TProbe)
		return mustSeal(t, c, &h, nil)
	}
	for _, tc := range []struct {
		name string
		pkt  []byte
		want DecodeError
	}{
		{"probe", probeFrom(ini), OK},
		{"short probe", probeFrom(ini)[:MinProbePacket-1], ErrShort},
		{"other route", probeFrom(otherSession), ErrRoute},
		{"same route, other token", probeFrom(oldSession), ErrAuth},
		{"punch to natprobe", sealPlain(srv, plaintext(TPunch, RoleInitiator, nil, 60, nil), true, B0Min), ErrPayload},
	} {
		before := srvCounter.count()
		if got := nat.deliver(tc.pkt, true); got != tc.want {
			t.Errorf("natprobe %s: %v, want %v", tc.name, got, tc.want)
		}
		if tc.want == ErrRoute || tc.want == ErrShort {
			if srvCounter.count() != before {
				t.Errorf("natprobe %s: AEAD was called", tc.name)
			}
		}
	}
}

// TestDecodeErrorKeys pins the drop-counter keys (there is no "version"
// key) and the error strings, which carry no stack.
func TestDecodeErrorKeys(t *testing.T) {
	want := []string{"ok", "short", "foreign", "route", "rate", "auth", "payload", "role", "replay"}
	for i, k := range want {
		if got := DecodeError(i).String(); got != k {
			t.Errorf("DecodeError(%d) = %q, want %q", i, got, k)
		}
	}
	if ErrReplay != DecodeError(len(want)-1) {
		t.Error("DecodeError values are not contiguous from OK")
	}
	if got := (ErrReplay + 1).String(); got != "DecodeError(9)" {
		t.Errorf("unknown value = %q", got)
	}
	if _, err := NewCodec(testToken(), testRoute(), 0, testPad, nil); err == nil || err.Error() != string(errBadRole) {
		t.Errorf("error text: %v", err)
	}
}

package udpwire

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"slices"
	"testing"
)

// stunAttr is one attribute of a STUN message as a generic RFC 8489 parser
// sees it.
type stunAttr struct {
	typ uint16
	val []byte
}

// parseSTUN is an independent, generic STUN parser: header, cookie, length
// and 4-byte aligned attributes. It reports false for anything a STUN stack
// would reject at the framing level.
func parseSTUN(pkt []byte) (typ uint16, txid []byte, attrs []stunAttr, ok bool) {
	if len(pkt) < 20 || pkt[0]&0xC0 != 0 || binary.BigEndian.Uint32(pkt[4:]) != 0x2112A442 {
		return 0, nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(pkt[2:]))
	if n%4 != 0 || 20+n != len(pkt) {
		return 0, nil, nil, false
	}
	rest := pkt[20:]
	for len(rest) > 0 {
		if len(rest) < 4 {
			return 0, nil, nil, false
		}
		l := int(binary.BigEndian.Uint16(rest[2:]))
		padded := (l + 3) &^ 3
		if 4+padded > len(rest) {
			return 0, nil, nil, false
		}
		attrs = append(attrs, stunAttr{typ: binary.BigEndian.Uint16(rest), val: rest[4 : 4+l]})
		rest = rest[4+padded:]
	}
	return binary.BigEndian.Uint16(pkt), pkt[8:20], attrs, true
}

// TestWrapIsStandardSTUN checks the opener of every packet type at many
// lengths against the generic parser: a Binding Request whose attributes are
// PADDING carrying the packet and a valid FINGERPRINT (RFC 8489, section 14.7), the
// whole datagram a multiple of four, and Unwrap giving the packet back.
func TestWrapIsStandardSTUN(t *testing.T) {
	r := newRand(11)
	for _, typ := range allTypes() {
		c := newCodec(t, sendersOf(typ)[0])
		for range 40 {
			h, tl := headerFor(c, typ), tlvsFor(typ)
			pkt := mustSeal(t, c, &h, &tl)
			if typ == TProbeAck || typ == TProbeExtra || typ == TProbeAlt {
				// Replies take explicit lengths: vary them too.
				plain := MinAckPlaintext + r.IntN(MaxPlaintext-MinAckPlaintext)
				var err error
				if pkt, err = c.Seal(nil, &h, &tl, plain); err != nil {
					t.Fatal(err)
				}
			}
			w := c.Wrap(nil, pkt)
			mt, txid, attrs, ok := parseSTUN(w)
			if !ok || mt != stunBindingRequest {
				t.Fatalf("%v: opener is not a STUN Binding Request: % x", typ, w[:20])
			}
			if len(w)%4 != 0 || len(w) != wrapOverhead+len(pkt)+(4-len(pkt)%4)%4 || len(w) > MaxWrapped {
				t.Fatalf("%v: opener of %d bytes for %d", typ, len(w), len(pkt))
			}
			if len(attrs) != 2 || attrs[0].typ != attrPadding || !bytes.Equal(attrs[0].val, pkt) ||
				attrs[1].typ != attrFingerprint || len(attrs[1].val) != 4 {
				t.Fatalf("%v: attributes %+v", typ, attrs)
			}
			pad := w[wrapOverhead-attrHeaderSize-fingerprintSize+len(pkt) : len(w)-attrHeaderSize-fingerprintSize]
			if !bytes.Equal(pad, make([]byte, len(pad))) {
				t.Fatalf("%v: alignment bytes % x, want zeros (RFC 8489, section 14)", typ, pad)
			}
			want := crc32.ChecksumIEEE(w[:len(w)-8]) ^ 0x5354554E
			if got := binary.BigEndian.Uint32(attrs[1].val); got != want {
				t.Fatalf("%v: FINGERPRINT %#x, want %#x", typ, got, want)
			}
			if bytes.Equal(txid, make([]byte, 12)) {
				t.Fatalf("%v: zero transaction id", typ)
			}
			inner, e := Unwrap(w)
			if e != OK || !bytes.Equal(inner, pkt) || !Wrapped(w) || Wrapped(pkt) {
				t.Fatalf("%v: Unwrap = %v, %v", typ, e, bytes.Equal(inner, pkt))
			}
		}
	}
}

// TestWrapConstantsAreSTUNs checks that across one session's openers the only
// bytes that never change are the ones the STUN standard fixes for every
// Binding Request with PADDING: the message type and the magic cookie in the
// header and the PADDING type. Lengths follow the packet and the
// transaction id is random.
func TestWrapConstantsAreSTUNs(t *testing.T) {
	c := newSessionCodec(t, testToken(), testRoute(), RoleInitiator, PadPolicy{Min: padMinLow, Max: MaxPlaintext})
	var ref []byte
	fixed := map[int]bool{}
	for i := range 256 {
		h := headerFor(c, TPunch)
		w := c.Wrap(nil, mustSeal(t, c, &h, nil))
		if i == 0 {
			ref = w
			for off := range w {
				fixed[off] = true
			}
			continue
		}
		for off := range fixed {
			if off >= len(w) || w[off] != ref[off] {
				delete(fixed, off)
			}
		}
	}
	var got []int
	for off := range fixed {
		got = append(got, off)
	}
	slices.Sort(got)
	// 0–1 type 0x0001, 4–7 cookie, 20–21 PADDING type 0x0026.
	if want := []int{0, 1, 4, 5, 6, 7, 20, 21}; !slices.Equal(got, want) {
		t.Fatalf("constant offsets %v, want %v", got, want)
	}
}

// TestUnwrapRejects checks that Unwrap accepts only the opener's exact form:
// any change to a STUN field, a truncation, other STUN messages, a nested
// opener and bare sealed packets are foreign (or short), never an inner packet.
func TestUnwrapRejects(t *testing.T) {
	c := newCodec(t, RoleInitiator)
	h := headerFor(c, TPunch)
	pkt := mustSeal(t, c, &h, nil)
	w := c.Wrap(nil, pkt)
	if _, e := Unwrap(pkt); e != ErrForeign {
		t.Errorf("sealed packet: %v", e)
	}
	if _, e := Unwrap(nil); e != ErrForeign {
		t.Errorf("empty: %v", e)
	}
	for _, n := range []int{1, 19, 20, minWrapped - 1} {
		if _, e := Unwrap(w[:n]); e != ErrShort {
			t.Errorf("first %d bytes: %v", n, e)
		}
	}
	if _, e := Unwrap(append(slices.Clone(w), make([]byte, MaxWrapped)...)); e != ErrForeign {
		t.Errorf("too long: %v", e)
	}
	if _, e := Unwrap(w[:len(w)-4]); e != ErrForeign {
		t.Errorf("truncated: %v", e)
	}
	// Every byte outside the transaction id and the packet is checked by
	// the type, length, cookie and attribute rules or by FINGERPRINT; the
	// packet's bytes by FINGERPRINT.
	for off := range w {
		if off >= 8 && off < 20 {
			continue
		}
		bad := slices.Clone(w)
		bad[off] ^= 0x01
		if _, e := Unwrap(bad); e != ErrForeign {
			t.Fatalf("byte %d flipped: %v", off, e)
		}
	}
	// A Binding Success Response of the same shape is a third party's
	// answer, not an opener.
	resp := slices.Clone(w)
	binary.BigEndian.PutUint16(resp, 0x0101)
	refingerprint(resp)
	if _, e := Unwrap(resp); e != ErrForeign {
		t.Errorf("Binding Success: %v", e)
	}
	// An opener around an opener, or around bytes that are no sealed packet.
	nested := c.Wrap(nil, w)
	if _, e := Unwrap(nested); e != ErrForeign {
		t.Errorf("nested opener: %v", e)
	}
	stray := slices.Clone(pkt)
	stray[0] = 0x14 // DTLS
	if _, e := Unwrap(c.Wrap(nil, stray)); e != ErrForeign {
		t.Errorf("unsealed inner packet: %v", e)
	}
	// A bare Binding Request (a STUN client's) is no opener either.
	bare := make([]byte, 20)
	binary.BigEndian.PutUint16(bare, 0x0001)
	binary.BigEndian.PutUint32(bare[4:], 0x2112A442)
	if _, e := Unwrap(bare); e != ErrShort {
		t.Errorf("bare Binding Request: %v", e)
	}
}

// refingerprint recomputes the FINGERPRINT of an opener-shaped message.
func refingerprint(w []byte) {
	binary.BigEndian.PutUint32(w[len(w)-4:], crc32.ChecksumIEEE(w[:len(w)-8])^0x5354554E)
}

// TestWrapTransactionIDs checks that openers of the same packet differ in
// their transaction id: fresh CSPRNG output, never a counter.
func TestWrapTransactionIDs(t *testing.T) {
	c := newCodec(t, RoleResponder)
	h := headerFor(c, TSuccess)
	tl := tlvsFor(TSuccess)
	pkt := mustSeal(t, c, &h, &tl)
	seen := map[string]bool{}
	for range 256 {
		w := c.Wrap(nil, pkt)
		id := string(w[8:20])
		if seen[id] {
			t.Fatal("transaction id repeated")
		}
		seen[id] = true
	}
}

// TestWrapAppends checks that Wrap appends to dst and allocates nothing when
// dst has room.
func TestWrapAppends(t *testing.T) {
	c := newCodec(t, RoleInitiator)
	h := headerFor(c, TPunch)
	pkt := mustSeal(t, c, &h, nil)
	dst := append(make([]byte, 0, 3+MaxWrapped), 1, 2, 3)
	out := c.Wrap(dst, pkt)
	if !bytes.Equal(out[:3], []byte{1, 2, 3}) {
		t.Fatal("prefix lost")
	}
	if inner, e := Unwrap(out[3:]); e != OK || !bytes.Equal(inner, pkt) {
		t.Fatalf("Unwrap after append: %v", e)
	}
	if n := testing.AllocsPerRun(100, func() { _ = c.Wrap(dst[:0], pkt) }); n != 0 {
		t.Errorf("Wrap allocates %v times", n)
	}
	if n := testing.AllocsPerRun(100, func() { _, _ = Unwrap(out[3:]) }); n != 0 {
		t.Errorf("Unwrap allocates %v times", n)
	}
}

// FuzzUnwrap feeds arbitrary datagrams to Unwrap: it never panics, an
// accepted datagram is exactly the opener of what it returns (Wrap of the
// result differs from it only in the transaction id and FINGERPRINT) and the
// result is a subslice shaped like a sealed packet.
func FuzzUnwrap(f *testing.F) {
	c := newCodec(f, RoleInitiator)
	peer, probe := sealedSeeds(f)
	for _, p := range append(peer, probe...) {
		f.Add(c.Wrap(nil, p))
	}
	f.Add([]byte{0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42})
	f.Fuzz(func(t *testing.T, data []byte) {
		inner, e := Unwrap(data)
		if e != OK {
			if inner != nil || (e != ErrShort && e != ErrForeign) {
				t.Fatalf("Unwrap = %v with %d bytes", e, len(inner))
			}
			return
		}
		if !Wrapped(data) || Wrapped(inner) || Precheck(inner, MinPeerPacket) != OK {
			t.Fatalf("accepted %d bytes around %d", len(data), len(inner))
		}
		again := c.Wrap(nil, inner)
		if len(again) != len(data) || !bytes.Equal(again[:8], data[:8]) ||
			!bytes.Equal(again[20:len(again)-4], data[20:len(data)-4]) {
			t.Fatal("accepted datagram is not the opener of its packet")
		}
	})
}

// FuzzWrap wraps arbitrary bytes shaped like sealed packets, of every length,
// and checks the round trip and the STUN framing.
func FuzzWrap(f *testing.F) {
	c := newCodec(f, RoleResponder)
	peer, probe := sealedSeeds(f)
	for _, p := range append(peer, probe...) {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < MinPeerPacket || len(data) > maxProbePacket {
			return
		}
		pkt := slices.Clone(data)
		pkt[0] = B0Min + pkt[0]%b0Count
		w := c.Wrap(nil, pkt)
		if mt, _, attrs, ok := parseSTUN(w); !ok || mt != stunBindingRequest || len(attrs) != 2 {
			t.Fatal("not a STUN Binding Request with two attributes")
		}
		if inner, e := Unwrap(w); e != OK || !bytes.Equal(inner, pkt) {
			t.Fatalf("round trip: %v", e)
		}
	})
}

func BenchmarkWrap(b *testing.B) {
	c := newCodec(b, RoleInitiator)
	h := headerFor(c, TPunch)
	pkt := mustSeal(b, c, &h, nil)
	dst := make([]byte, 0, MaxWrapped)
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for b.Loop() {
		dst = c.Wrap(dst[:0], pkt)
	}
}

func BenchmarkUnwrap(b *testing.B) {
	c := newCodec(b, RoleInitiator)
	h := headerFor(c, TPunch)
	w := c.Wrap(nil, mustSeal(b, c, &h, nil))
	b.SetBytes(int64(len(w)))
	b.ReportAllocs()
	for b.Loop() {
		if _, e := Unwrap(w); e != OK {
			b.Fatal(e)
		}
	}
}

package udpwire

import (
	"bytes"
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"
	"time"
)

// sealedSeeds returns one sealed packet of every type for fuzz corpora.
func sealedSeeds(tb testing.TB) (peer, probe [][]byte) {
	tb.Helper()
	for _, typ := range allTypes() {
		c := newCodec(tb, sendersOf(typ)[0])
		h, t := headerFor(c, typ), tlvsFor(typ)
		pkt := mustSeal(tb, c, &h, &t)
		if typ == TProbe {
			probe = append(probe, pkt)
		} else {
			peer = append(peer, pkt)
		}
	}
	return peer, probe
}

// fuzzCodecs returns one codec per role of the vector session.
func fuzzCodecs(tb testing.TB) (cs [RoleServer + 1]*Codec) {
	for _, role := range []Role{RoleInitiator, RoleResponder, RoleServer} {
		cs[role] = newCodec(tb, role)
	}
	return cs
}

// fuzzOpenCase runs one input through Open (probe false, initiator side) or
// OpenProbe (natprobe). Random datagrams never authenticate, so with mode
// bit 0 set data is instead a plaintext sealed under the session key, which
// fuzzes the header/TLV parser behind the AEAD; mode bit 1 then corrupts a
// probe's masked route. Checks: the class is one the receiver can produce
// and agrees with Precheck, a separate scratch leaves pkt untouched, a
// rejected packet leaves no fields behind, whatever is accepted re-seals to
// the same fields, and an overlapping scratch does not panic.
func fuzzOpenCase(t *testing.T, cs [RoleServer + 1]*Codec, data []byte, mode uint8, probe bool) {
	recv, minLen := cs[RoleInitiator], MinPeerPacket
	if probe {
		recv, minLen = cs[RoleServer], MinProbePacket
	}
	pkt := data
	authentic := mode&1 != 0
	if authentic {
		plain := append(bytes.Clone(data[:min(len(data), MaxPlaintext)]), make([]byte, max(HeaderSize-len(data), 0))...)
		pkt = sealPlain(recv, plain, probe, B0Min+(mode>>2)%b0Count)
		if probe && mode&2 != 0 {
			pkt[PeerOuterSize] ^= 1
			authentic = false
		}
	}
	pre := Precheck(pkt, minLen)
	orig := bytes.Clone(pkt)
	var h Header
	var tl TLVs
	e := open(recv, pkt, probe, &h, &tl)
	if pre != OK && e != pre {
		t.Fatalf("Precheck %v but open %v", pre, e)
	}
	if !bytes.Equal(pkt, orig) {
		t.Fatal("open with a separate scratch modified pkt")
	}
	switch {
	case authentic && e != OK && e != ErrPayload:
		t.Fatalf("authentic packet classified %v", e)
	case e == ErrRoute && !probe:
		t.Fatal("ErrRoute from Open")
	case e > ErrPayload || e == ErrRate:
		t.Fatalf("open returned %v", e)
	case e != OK && (h != Header{} || tl != TLVs{}):
		t.Fatalf("%v left fields set", e)
	case e == OK:
		if (h.Type == TProbe) != probe {
			t.Fatalf("type %d accepted in the wrong envelope", h.Type)
		}
		// Whatever Open accepts, the sender's Seal produces again (seq 0 is
		// left to the SeqWindow).
		if h.Seq != 0 {
			again, err := cs[h.Role].Seal(nil, &h, &tl, len(pkt)-minLen+HeaderSize)
			var h2 Header
			var t2 TLVs
			if err != nil || open(recv, again, probe, &h2, &t2) != OK || h2 != h || t2 != tl {
				t.Fatalf("accepted %+v %+v does not re-seal: %v", h, tl, err)
			}
		}
	}
	_ = open(recv, pkt, probe, nil, nil)
	if probe {
		_ = recv.OpenProbe(pkt, pkt[len(pkt)/2:], nil, nil)
	} else {
		_ = recv.Open(pkt, pkt[len(pkt)/2:], nil, nil)
	}
}

func FuzzOpen(f *testing.F) {
	peer, probe := sealedSeeds(f)
	for _, p := range append(peer, probe...) {
		f.Add(p, uint8(0))
		f.Add(p[PeerOuterSize:len(p)-TagSize], uint8(1))
	}
	for _, s := range foreignSamples() {
		f.Add(s, uint8(0))
	}
	f.Add(plaintext(TSuccess, RoleResponder, observedTLV(v4Mapped(192, 0, 2, 1), 9), 60, nil), uint8(1))
	cs := fuzzCodecs(f)
	f.Fuzz(func(t *testing.T, data []byte, mode uint8) { fuzzOpenCase(t, cs, data, mode, false) })
}

func FuzzOpenProbe(f *testing.F) {
	peer, probe := sealedSeeds(f)
	for _, p := range append(probe, peer...) {
		f.Add(p, uint8(0))
	}
	f.Add(plaintext(TProbe, RoleInitiator, []byte{tlvSandwich, 2, 1, 0}, 100, nil), uint8(1))
	f.Add(plaintext(TProbe, RoleResponder, nil, 100, nil), uint8(3))
	for _, s := range foreignSamples() {
		f.Add(s, uint8(0))
	}
	cs := fuzzCodecs(f)
	f.Fuzz(func(t *testing.T, data []byte, mode uint8) { fuzzOpenCase(t, cs, data, mode, true) })
}

// FuzzTLV parses arbitrary plaintexts (header and TLV region) for every
// type: no panic, and whatever parses re-encodes to an equivalent packet.
func FuzzTLV(f *testing.F) {
	f.Add(uint8(TProbeAck), append(observedTLV(v4Mapped(192, 0, 2, 1), 9), tlvExtraPort, 2, 1, 2, tlvCookie, 4, 1, 2, 3, 4))
	f.Add(uint8(TProbe), []byte{tlvSandwich, 2, 1, 1, 0, 0xFF})
	f.Add(uint8(TAccept), []byte{tlvRxCount, 4, 0, 0, 0, 9, 0x77, 1, 0})
	f.Add(uint8(TSuccess), []byte{tlvObserved, 18})
	f.Add(uint8(TPunch), []byte{0x80, 255})
	f.Add(uint8(TNominate), []byte{tlvPathSlot, 1, 3})
	f.Add(uint8(TAccept), []byte{tlvRxCount, 4, 0, 0, 0, 1, tlvPathSlot, 1, 7, tlvPaths, 1, 2})
	f.Add(uint8(TReady), []byte{tlvPaths, 1, 0x86, tlvPathSlot, 1, 0})
	f.Fuzz(func(t *testing.T, typ uint8, region []byte) {
		r, ok := ruleOf(Type(typ))
		if !ok {
			return
		}
		var tl TLVs
		if !parseTLVs(region, r.tlvs, &tl) {
			return
		}
		if !tl.valid(r.tlvs) {
			t.Fatalf("parsed TLVs %+v are not encodable", tl)
		}
		buf := make([]byte, tl.size(r.tlvs))
		if n := tl.put(buf, r.tlvs); n != len(buf) {
			t.Fatalf("put wrote %d of %d bytes", n, len(buf))
		}
		var again TLVs
		if !parseTLVs(buf, r.tlvs, &again) || again != tl {
			t.Fatalf("re-encoded TLVs %+v parse as %+v", tl, again)
		}

		// The same region behind a header of that type, as Open would see it.
		var h Header
		plain := plaintext(Type(typ), sendersOf(Type(typ))[0], region, 0, nil)
		if e := parse(plain, Type(typ) == TProbe, &h, &tl); e != OK {
			t.Fatalf("parse after successful parseTLVs: %v", e)
		}
	})
}

func FuzzUnmaskRoute(f *testing.F) {
	_, probe := sealedSeeds(f)
	for _, p := range probe {
		f.Add(p)
	}
	for _, s := range foreignSamples() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, pkt []byte) {
		route, e := UnmaskRoute(pkt)
		switch {
		case len(pkt) < MinProbePacket:
			if e != ErrShort {
				t.Fatalf("%d bytes: %v", len(pkt), e)
			}
			return
		case e != OK:
			if e != ErrForeign || route != ([RouteSize]byte{}) {
				t.Fatalf("%v with route %x", e, route)
			}
			return
		}
		mask := routeMask(pkt[1:PeerOuterSize])
		for i := range RouteSize {
			if route[i]^mask[i] != pkt[PeerOuterSize+i] {
				t.Fatal("masking the unmasked route does not give mroute back")
			}
		}
	})
}

// FuzzRoundTrip seals fuzzer-chosen fields of every type and requires
// Open/OpenProbe to return them (normalized as the wire normalizes them).
func FuzzRoundTrip(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint8(0), uint8(0), uint8(0), uint16(NoCand), uint16(0), uint32(1), uint32(0), uint32(0), uint32(0),
		[]byte{192, 0, 2, 1}, uint16(9), uint16(0), uint32(0), uint16(0), uint32(0), false, uint16(0))
	f.Add(uint8(THandoverAck-1), uint8(1), uint8(0xFF), uint8(9), uint8(0x85), uint16(0x3011), uint16(1), uint32(42), uint32(7), uint32(8), uint32(9),
		bytes.Repeat([]byte{0x20}, 16), uint16(443), uint16(5), uint32(6), uint16(0x0101), uint32(77), true, uint16(MaxPlaintext))
	codecs := fuzzCodecs(f)
	f.Fuzz(func(t *testing.T, typSel, roleSel, flags, round, sock uint8, cand, aux uint16, seq, ts, echoSeq, echoTS uint32,
		addr []byte, port, extraPort uint16, cookie uint32, sandwich uint16, rx uint32, hasRx bool, plainLen uint16) {
		typ := TProbe + Type(typSel)%THandoverAck
		senders := sendersOf(typ)
		c := codecs[senders[int(roleSel)%len(senders)]]
		rl, _ := ruleOf(typ)
		fl := flags & rl.flags
		if fl&(flagFA|flagFB) == flagFA|flagFB {
			fl &^= flagFB
		}
		h := Header{
			Type: typ, Role: c.role, LowTTL: flags&flagLowTTL != 0, Retx: flags&flagRetx != 0,
			FA: fl&flagFA != 0, FB: fl&flagFB != 0, FC: fl&flagFC != 0,
			Round: round, Sock: sock, Cand: cand, Aux: aux, Seq: max(seq, 1), TS: ts, EchoSeq: echoSeq, EchoTS: echoTS,
		}
		ip, ok := netip.AddrFromSlice(addr)
		if !ok || ip.Unmap().IsUnspecified() {
			ip = netip.AddrFrom4([4]byte{192, 0, 2, 1})
		}
		tl := TLVs{Observed: netip.AddrPortFrom(ip, max(port, 1)), ExtraPort: extraPort, Cookie: cookie, RxCount: rx, HasRx: hasRx,
			Slot: uint8(cookie>>8) % (maxPathSlot + 1), Paths: uint8(cookie >> 16)}
		tl.Sandwich.Round, tl.Sandwich.Phase, tl.Sandwich.Set = uint8(sandwich>>8), uint8(sandwich&1), sandwich&0x100 != 0
		tl = carried(rl.tlvs, tl)
		content := HeaderSize + tl.size(rl.tlvs)
		n := int(plainLen) % (MaxPlaintext + 1)
		if n != 0 || rl.length == lengthExplicit {
			n = max(n, content)
		}
		pkt, err := c.Seal(nil, &h, &tl, n)
		if err != nil {
			t.Fatalf("Seal(%+v, %+v, %d): %v", h, tl, n, err)
		}
		if pkt[0] < B0Min || pkt[0] > B0Max {
			t.Fatalf("b0 %#x", pkt[0])
		}
		if potential, long := quicBits(pkt[0]); potential || long {
			t.Fatalf("b0 %#x is a QUIC first byte", pkt[0])
		}
		var gh Header
		var gt TLVs
		if e := open(codecs[RoleServer], pkt, typ == TProbe, &gh, &gt); e != OK || gh != h || gt != received(tl) {
			t.Fatalf("%v\n got %+v %+v\nwant %+v %+v", e, gh, gt, h, received(tl))
		}
	})
}

// FuzzDropResidual feeds a fuzzer-chosen stream through DropResidual. Each
// script byte is one datagram: bits 0–1 pick residual-from-peer,
// random-from-peer, residual-from-elsewhere or random-from-elsewhere, bit 2
// sends a residual as an opener, the rest seed its content; 0xFF
// ends the window instead. Inside the window only
// residuals from the peer disappear; afterwards everything passes unchanged.
func FuzzDropResidual(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 0xFF, 0, 1})
	f.Add([]byte{0, 0, 0, 5, 9, 0x40})
	f.Add([]byte{4, 6, 0xFF, 4})
	f.Add([]byte{0xFF})
	ini := newCodec(f, RoleInitiator)
	f.Fuzz(func(t *testing.T, script []byte) {
		clk := newManualClock()
		resp, err := NewCodec(testToken(), testRoute(), RoleResponder, testPad, clk.Now)
		if err != nil {
			t.Fatal(err)
		}
		peer, other := udpAddr("192.0.2.10:5000"), udpAddr("192.0.2.10:5001")
		resp.BindPeers(peer.AddrPort())
		conn := &queueConn{}
		pc := DropResidual(conn, resp, time.Second)

		var want []datagram
		expired := false
		for i, op := range script {
			if op == 0xFF {
				clk.Advance(time.Second)
				expired = true
				continue
			}
			from := net.Addr(peer)
			if op&2 != 0 {
				from = other
			}
			var data []byte
			if op&1 == 0 {
				h := headerFor(ini, TReady)
				data = mustSeal(t, ini, &h, nil)
				if op&4 != 0 {
					data = ini.Wrap(nil, data)
				}
			} else {
				r := rand.New(rand.NewPCG(uint64(op), uint64(i)))
				data = make([]byte, r.IntN(300))
				for j := range data {
					data[j] = byte(r.Uint32())
				}
			}
			conn.push(data, from)
			if expired || op&3 != 0 {
				want = append(want, datagram{data: data, from: from})
			}
			got := readAll(t, pc)
			if len(got) != len(want) {
				t.Fatalf("op %d (%#x): %d datagrams passed, want %d", i, op, len(got), len(want))
			}
			for k := range want {
				if !bytes.Equal(got[k].data, want[k].data) || got[k].from.String() != want[k].from.String() {
					t.Fatalf("op %d: datagram %d changed", i, k)
				}
			}
			want = want[:0]
		}
	})
}

package udpwire

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/testkit"
)

func TestNewCodec(t *testing.T) {
	for _, role := range []Role{0, RoleServer + 1, 255} {
		if c, err := NewCodec(testToken(), testRoute(), role, testPad, nil); c != nil || !errors.Is(err, errBadRole) {
			t.Errorf("role %d: %v, %v", role, c, err)
		}
	}
	// The client-side clamp keeps lengths sendable whatever the server sent.
	if _, err := NewCodec(testToken(), testRoute(), RoleResponder, PadPolicy{}, nil); !errors.Is(err, errNoPad) {
		t.Errorf("zero PadPolicy for a client: %v", err)
	}
	if _, err := NewCodec(testToken(), testRoute(), RoleServer, PadPolicy{}, nil); err != nil {
		t.Errorf("server codec needs no PadPolicy: %v", err)
	}
	for _, c := range []struct{ in, want PadPolicy }{
		{PadPolicy{Max: 5}, PadPolicy{padMinLow, padMinLow}},
		{PadPolicy{Min: 100, Max: 50}, PadPolicy{100, 100}},
		{PadPolicy{Min: 2000, Max: 3000}, PadPolicy{MaxPlaintext, MaxPlaintext}},
		{PadPolicy{Min: 48, Max: 2000}, PadPolicy{48, MaxPlaintext}},
		{testPad, testPad},
	} {
		if got := newSessionCodec(t, testToken(), testRoute(), RoleInitiator, c.in).pad; got != c.want {
			t.Errorf("pad %+v clamped to %+v, want %+v", c.in, got, c.want)
		}
	}
	// Two codecs of one session share key and pacer stream but never their
	// nonce stream.
	a, b := newCodec(t, RoleInitiator), newCodec(t, RoleInitiator)
	h := headerFor(a, TPunch)
	pa, pb := mustSeal(t, a, &h, nil), mustSeal(t, b, &h, nil)
	if pa[0] != pb[0] || len(pa) != len(pb) {
		t.Error("same session and role should draw the same b0 and length")
	}
	if bytes.Equal(pa[1:PeerOuterSize], pb[1:PeerOuterSize]) {
		t.Error("two codecs produced the same nonce")
	}
	var gh Header
	var gt TLVs
	if e := b.Open(pa, nil, &gh, &gt); e != OK || gh != h {
		t.Errorf("codecs of one session disagree: %v", e)
	}
}

func TestNextSeqAndNow(t *testing.T) {
	clk := testkit.NewStepClock(t, clockStart)
	c, err := NewCodec(testToken(), testRoute(), RoleInitiator, testPad, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Now() != 0 {
		t.Errorf("Now at t0 = %d", c.Now())
	}
	clk.Advance(1500 * time.Millisecond)
	if c.Now() != 1500 {
		t.Errorf("Now = %d, want 1500", c.Now())
	}
	clk.Step(-time.Hour)
	if c.Now() != 0 {
		t.Errorf("Now before t0 = %d, want 0", c.Now())
	}
	srv, err := NewCodec(testToken(), testRoute(), RoleServer, PadPolicy{}, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint32(clk.Now().UnixMilli()); srv.Now() != want {
		t.Errorf("server Now = %d, want %d", srv.Now(), want)
	}

	const workers, each = 8, 500
	seen := make([][]uint32, workers)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for range each {
				seen[w] = append(seen[w], c.NextSeq())
			}
		})
	}
	wg.Wait()
	all := map[uint32]bool{}
	for _, s := range seen {
		for _, v := range s {
			all[v] = true
		}
	}
	for v := uint32(1); v <= workers*each; v++ {
		if !all[v] {
			t.Fatalf("seq %d missing; NextSeq must hand out 1..n exactly once", v)
		}
	}
}

func TestBindPeers(t *testing.T) {
	c := newCodec(t, RoleResponder)
	if c.Peers() != nil {
		t.Error("Peers before BindPeers")
	}
	in := []string{"[2001:db8::5]:7000", "[::ffff:192.0.2.7]:7001", "[fe80::1%en0]:7002", "198.51.100.4:7003"}
	want := []string{"[2001:db8::5]:7000", "192.0.2.7:7001", "[fe80::1]:7002", "198.51.100.4:7003"}
	var ps []netip.AddrPort
	for _, s := range in {
		ps = append(ps, netip.MustParseAddrPort(s))
	}
	c.BindPeers(ps...)
	got := c.Peers()
	if len(got) != len(want) {
		t.Fatalf("Peers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != netip.MustParseAddrPort(want[i]) {
			t.Errorf("Peers[%d] = %v, want %s", i, got[i], want[i])
		}
	}
	got[0] = netip.AddrPort{}
	if c.Peers()[0] != netip.MustParseAddrPort(want[0]) {
		t.Error("Peers returned the codec's own slice")
	}
	c.BindPeers(ps[3])
	if got := c.Peers(); len(got) != 1 || got[0] != ps[3] {
		t.Errorf("a second BindPeers left %v", got)
	}
}

func TestSealRejects(t *testing.T) {
	ini, srv := newCodec(t, RoleInitiator), newCodec(t, RoleServer)
	valid := func(c *Codec, typ Type) (*Header, *TLVs) {
		h, tl := headerFor(c, typ), tlvsFor(typ)
		return &h, &tl
	}
	cases := []struct {
		name  string
		c     *Codec
		edit  func(*Header, *TLVs)
		typ   Type
		n     int
		want  error
		nilH  bool
		nilTL bool
	}{
		{name: "nil header", c: ini, typ: TPunch, nilH: true, want: errNilHeader},
		{name: "type 0", c: ini, typ: TPunch, edit: func(h *Header, _ *TLVs) { h.Type = 0 }, want: errBadType},
		{name: "type past last", c: ini, typ: TPunch, edit: func(h *Header, _ *TLVs) { h.Type = THandoverAck + 1 }, want: errBadType},
		{name: "foreign role", c: ini, typ: TPunch, edit: func(h *Header, _ *TLVs) { h.Role = RoleResponder }, want: errRoleMismatch},
		{name: "server punch", c: srv, typ: TPunch, edit: func(h *Header, _ *TLVs) { h.Role = RoleServer }, want: errNotSender},
		{name: "initiator accept", c: ini, typ: TAccept, edit: func(h *Header, _ *TLVs) { h.Role = RoleInitiator }, want: errNotSender},
		{name: "FA on punch", c: ini, typ: TPunch, edit: func(h *Header, _ *TLVs) { h.FA = true }, want: errBadFlags},
		{name: "FC on probe", c: ini, typ: TProbe, edit: func(h *Header, _ *TLVs) { h.FC = true }, want: errBadFlags},
		{name: "FA and FB", c: ini, typ: TProbe, edit: func(h *Header, _ *TLVs) { h.FA, h.FB = true, true }, want: errBadFlags},
		{name: "zero seq", c: ini, typ: TPunch, edit: func(h *Header, _ *TLVs) { h.Seq = 0 }, want: errZeroSeq},
		{name: "ack without observed", c: srv, typ: TProbeAck, edit: func(_ *Header, t *TLVs) { t.Observed = netip.AddrPort{} }, n: MinAckPlaintext, want: errBadTLVs},
		{name: "ack nil TLVs", c: srv, typ: TProbeAck, nilTL: true, n: MinAckPlaintext, want: errBadTLVs},
		{name: "observed port 0", c: ini, typ: TSuccess, edit: func(_ *Header, t *TLVs) { t.Observed = netip.MustParseAddrPort("192.0.2.1:0") }, want: errBadTLVs},
		{name: "observed unspecified", c: ini, typ: TSuccess, edit: func(_ *Header, t *TLVs) { t.Observed = netip.MustParseAddrPort("[::ffff:0.0.0.0]:9") }, want: errBadTLVs},
		{name: "sandwich phase 4", c: ini, typ: TProbe, edit: func(_ *Header, t *TLVs) { t.Sandwich.Phase = 4 }, want: errBadTLVs},
		{name: "observed on punch", c: ini, typ: TPunch, edit: func(_ *Header, t *TLVs) { t.Observed = netip.MustParseAddrPort("192.0.2.1:9") }, want: errBadTLVs},
		{name: "cookie on success", c: ini, typ: TSuccess, edit: func(_ *Header, t *TLVs) { t.Cookie = 1 }, want: errBadTLVs},
		{name: "extra port on extra", c: srv, typ: TProbeExtra, edit: func(_ *Header, t *TLVs) { t.ExtraPort = 1 }, n: MinExtraPlaintext, want: errBadTLVs},
		{name: "rx count without HasRx", c: ini, typ: TSuccess, edit: func(_ *Header, t *TLVs) { t.HasRx = false }, want: errBadTLVs},
		{name: "rx count on probe", c: ini, typ: TProbe, edit: func(_ *Header, t *TLVs) { t.HasRx = true }, want: errBadTLVs},
		{name: "sandwich round without Set", c: ini, typ: TProbe, edit: func(_ *Header, t *TLVs) { t.Sandwich.Set = false }, want: errBadTLVs},
		{name: "sandwich on punch", c: ini, typ: TPunch, edit: func(_ *Header, t *TLVs) { t.Sandwich.Set = true }, want: errBadTLVs},
		{name: "path slot past the last", c: ini, typ: TNominate, edit: func(_ *Header, t *TLVs) { t.Slot = maxPathSlot + 1 }, want: errBadTLVs},
		{name: "path slot on ready", c: ini, typ: TReady, edit: func(_ *Header, t *TLVs) { t.Slot = 1 }, want: errBadTLVs},
		{name: "paths on nominate", c: ini, typ: TNominate, edit: func(_ *Header, t *TLVs) { t.Paths = 2 }, want: errBadTLVs},
		{name: "paths on handover_ack", c: newCodec(t, RoleResponder), typ: THandoverAck, edit: func(_ *Header, t *TLVs) { t.Paths = 2 }, want: errBadTLVs},
		{name: "reply without length", c: srv, typ: TProbeExtra, want: errNoLength},
		{name: "length below content", c: ini, typ: TSuccess, n: HeaderSize + 2 + observedSize + 2 + rxCountSize - 1, want: errBadLength},
		{name: "length above max", c: ini, typ: TPunch, n: MaxPlaintext + 1, want: errBadLength},
		{name: "negative length", c: ini, typ: TPunch, n: -1, want: errBadLength},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, tl := valid(tc.c, tc.typ)
			if tc.edit != nil {
				tc.edit(h, tl)
			}
			if tc.nilH {
				h = nil
			}
			if tc.nilTL {
				tl = nil
			}
			dst := []byte("prefix")
			got, err := tc.c.Seal(dst, h, tl, tc.n)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if string(got) != "prefix" {
				t.Fatalf("dst changed on error: %q", got)
			}
		})
	}
}

func TestSealAppends(t *testing.T) {
	c := newCodec(t, RoleInitiator)
	h := headerFor(c, TPunch)
	buf := make([]byte, 3, 2048)
	copy(buf, "abc")
	out, err := c.Seal(buf, &h, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[:3]) != "abc" || &out[0] != &buf[0] {
		t.Fatal("Seal must append in place when dst has capacity")
	}
	var gh Header
	var gt TLVs
	if e := c.Open(out[3:], nil, &gh, &gt); e != OK || gh != h {
		t.Fatalf("Open(appended) = %v", e)
	}
	// Without capacity Seal grows dst and keeps the prefix.
	out, err = c.Seal([]byte("xy"), &h, nil, 0)
	if err != nil || string(out[:2]) != "xy" {
		t.Fatalf("Seal(short dst): %q %v", out[:2], err)
	}
}

// TestLengthBounds checks the 53/69 minimum and 1053/1069 maximum datagrams
// of both envelopes and the Precheck classification around them.
func TestLengthBounds(t *testing.T) {
	ini := newCodec(t, RoleInitiator)
	for _, c := range []struct {
		typ      Type
		n, wire  int
		minLen   int
		openFunc func(pkt, scratch []byte, h *Header, t *TLVs) DecodeError
	}{
		{TPunch, HeaderSize, MinPeerPacket, MinPeerPacket, ini.Open},
		{TPunch, MaxPlaintext, maxPeerPacket, MinPeerPacket, ini.Open},
		{TProbe, HeaderSize, MinProbePacket, MinProbePacket, ini.OpenProbe},
		{TProbe, MaxPlaintext, maxProbePacket, MinProbePacket, ini.OpenProbe},
	} {
		h := headerFor(ini, c.typ)
		pkt, err := ini.Seal(nil, &h, nil, c.n)
		if err != nil || len(pkt) != c.wire {
			t.Fatalf("type %d plain %d: %d bytes, %v; want %d", c.typ, c.n, len(pkt), err, c.wire)
		}
		var gh Header
		var gt TLVs
		if e := c.openFunc(bytes.Clone(pkt), nil, &gh, &gt); e != OK || gh != h {
			t.Fatalf("open %d-byte packet: %v", c.wire, e)
		}
		if e := Precheck(pkt, c.minLen); e != OK {
			t.Errorf("Precheck(%d bytes) = %v", len(pkt), e)
		}
	}

	pkt := func(n int) []byte { p := make([]byte, n); p[0] = B0Min; return p }
	for _, c := range []struct {
		n, minLen int
		want      DecodeError
	}{
		{MinPeerPacket - 1, MinPeerPacket, ErrShort},
		{MinPeerPacket, MinPeerPacket, OK},
		{maxPeerPacket, MinPeerPacket, OK},
		{maxPeerPacket + 1, MinPeerPacket, ErrForeign},
		{MinProbePacket - 1, MinProbePacket, ErrShort},
		{MinProbePacket, MinProbePacket, OK},
		{maxProbePacket, MinProbePacket, OK},
		{maxProbePacket + 1, MinProbePacket, ErrForeign},
		{1, 0, OK},
		{1, -5, OK},
	} {
		if got := Precheck(pkt(c.n), c.minLen); got != c.want {
			t.Errorf("Precheck(%d bytes, min %d) = %v, want %v", c.n, c.minLen, got, c.want)
		}
	}
	// No minimum still never indexes an empty packet.
	for _, minLen := range []int{0, -1, MinPeerPacket} {
		if got := Precheck(nil, minLen); got != ErrShort {
			t.Errorf("Precheck(empty, %d) = %v", minLen, got)
		}
	}
	for _, b0 := range []byte{0, B0Min - 1, B0Max + 1, 0x40, 0xC0, 0xFF} {
		p := pkt(MinProbePacket)
		p[0] = b0
		if Precheck(p, MinPeerPacket) != ErrForeign || Precheck(p, MinProbePacket) != ErrForeign {
			t.Errorf("b0 %#x not foreign", b0)
		}
	}
}

// TestRoundTrip checks that every type, every sender role, every TLV and both
// address families survive Seal → Open/OpenProbe, lengths stay in the
// type's interval, and every first byte is in range and non-QUIC.
func TestRoundTrip(t *testing.T) {
	codecs := map[Role]*Codec{}
	for _, role := range []Role{RoleInitiator, RoleResponder, RoleServer} {
		codecs[role] = newCodec(t, role)
	}
	r := newRand(4)
	observed := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.200:1"),
		netip.MustParseAddrPort("[2001:db8::99]:65535"),
		netip.MustParseAddrPort("[::ffff:198.51.100.1]:4242"), // v4-mapped decodes unmapped
	}
	scratch := make([]byte, MaxPlaintext)
	n := iterations(1000000)
	for i := range n {
		typ := TProbe + Type(r.IntN(int(THandoverAck)))
		senders := sendersOf(typ)
		c := codecs[senders[r.IntN(len(senders))]]
		rl, _ := ruleOf(typ)
		h := Header{
			Type: typ, Role: c.role, LowTTL: r.IntN(2) == 0, Retx: r.IntN(2) == 0,
			Round: uint8(r.Uint32()), Sock: uint8(r.Uint32()), Cand: uint16(r.Uint32()), Aux: uint16(r.Uint32()),
			Seq: r.Uint32() | 1, TS: r.Uint32(), EchoSeq: r.Uint32(), EchoTS: r.Uint32(),
		}
		switch x := r.IntN(4); {
		case rl.flags&flagFA != 0 && x == 1:
			h.FA = true
		case rl.flags&flagFB != 0 && x == 2:
			h.FB = true
		}
		h.FC = rl.flags&flagFC != 0 && r.IntN(2) == 0
		tl := TLVs{Observed: observed[r.IntN(len(observed))], ExtraPort: uint16(r.Uint32()), Cookie: r.Uint32(), RxCount: r.Uint32(), HasRx: r.IntN(2) == 0,
			Slot: uint8(r.IntN(maxPathSlot + 1)), Paths: uint8(r.Uint32())}
		tl.Sandwich.Round, tl.Sandwich.Phase, tl.Sandwich.Set = uint8(r.Uint32()), uint8(r.IntN(2)), r.IntN(2) == 0
		tl = carried(rl.tlvs, tl)
		content := HeaderSize + tl.size(rl.tlvs)
		plainLen := 0
		if rl.length == lengthExplicit || r.IntN(4) == 0 {
			plainLen = content + r.IntN(MaxPlaintext-content+1)
		}
		pkt, err := c.Seal(nil, &h, &tl, plainLen)
		if err != nil {
			t.Fatalf("Seal %+v: %v", h, err)
		}

		outer := PeerOuterSize
		if typ == TProbe {
			outer = ProbeOuterSize
		}
		got := len(pkt) - outer - TagSize
		lo, hi := plainLen, plainLen
		if plainLen == 0 {
			switch {
			case typ == TProbe && (h.FA || h.FB):
				lo, hi = probeWantMin, probeWantMax
			case typ == TProbe:
				lo, hi = probeMin, probeMax
			default:
				lo, hi = int(testPad.Min), int(testPad.Max)
			}
			lo, hi = max(lo, content), max(hi, content)
		}
		if got < lo || got > hi {
			t.Fatalf("type %d plaintext %d outside [%d, %d]", typ, got, lo, hi)
		}
		if pkt[0] < B0Min || pkt[0] > B0Max {
			t.Fatalf("b0 %#x", pkt[0])
		}
		if potential, long := quicBits(pkt[0]); potential || long {
			t.Fatalf("b0 %#x looks like QUIC", pkt[0])
		}
		if typ == TProbe {
			if route, e := UnmaskRoute(pkt); e != OK || route != testRoute() {
				t.Fatalf("UnmaskRoute = %x, %v", route, e)
			}
		}

		want := received(tl)
		var gh Header
		var gt TLVs
		openFn := codecs[RoleServer].Open
		if typ == TProbe {
			openFn = codecs[RoleServer].OpenProbe
		}
		if e := openFn(pkt, scratch, &gh, &gt); e != OK || gh != h || gt != want {
			t.Fatalf("iteration %d: %v\n got %+v %+v\nwant %+v %+v", i, e, gh, gt, h, want)
		}
	}
}

// TestOpenScratch covers the buffer contract: a separate scratch leaves pkt
// untouched (also on failure), and a missing, short or overlapping scratch
// falls back to in-place decryption instead of panicking.
func TestOpenScratch(t *testing.T) {
	c := newCodec(t, RoleInitiator)
	h := headerFor(c, TPunch)
	sealed := mustSeal(t, c, &h, nil)
	plainLen := len(sealed) - PeerOuterSize - TagSize
	var gh Header
	var gt TLVs

	pkt := bytes.Clone(sealed)
	if e := c.Open(pkt, make([]byte, 0, plainLen), &gh, &gt); e != OK || gh != h || !bytes.Equal(pkt, sealed) {
		t.Fatalf("separate scratch: %v, pkt changed %v", e, !bytes.Equal(pkt, sealed))
	}
	bad := bytes.Clone(sealed)
	bad[len(bad)-1] ^= 1
	tampered := bytes.Clone(bad)
	if e := c.Open(bad, make([]byte, MaxPlaintext), &gh, &gt); e != ErrAuth || !bytes.Equal(bad, tampered) {
		t.Fatalf("auth failure with scratch must leave pkt intact: %v", e)
	}

	// buf holds pkt followed by spare room, so scratch can straddle its end.
	for name, scratch := range map[string]func(buf []byte, n int) []byte{
		"nil":            func([]byte, int) []byte { return nil },
		"short":          func([]byte, int) []byte { return make([]byte, plainLen-1) },
		"same start":     func(buf []byte, n int) []byte { return buf[:n] },
		"inside pkt":     func(buf []byte, n int) []byte { return buf[5:n] },
		"exact in-place": func(buf []byte, _ int) []byte { return buf[PeerOuterSize:PeerOuterSize] },
		"straddles end":  func(buf []byte, n int) []byte { return buf[n-4 : n-4] },
	} {
		buf := make([]byte, len(sealed)+MaxPlaintext)
		pkt := buf[:len(sealed)]
		copy(pkt, sealed)
		if e := c.Open(pkt, scratch(buf, len(pkt)), &gh, &gt); e != OK || gh != h {
			t.Fatalf("%s: %v", name, e)
		}
	}

	probeH := headerFor(c, TProbe)
	probe := mustSeal(t, c, &probeH, nil)
	if e := c.OpenProbe(probe, probe[3:], &gh, &gt); e != OK || gh != probeH {
		t.Fatalf("OpenProbe overlapping scratch: %v", e)
	}
}

// TestCheckRole checks the role check for every receiver, type and sender role.
func TestCheckRole(t *testing.T) {
	expect := func(recv Role, typ Type, from Role) DecodeError {
		r, _ := ruleOf(typ)
		if !r.senders.has(from) {
			return ErrRole
		}
		switch {
		case recv == RoleServer:
			if typ == TProbe {
				return OK
			}
		case typ == TProbe:
		case typ == TProbeAck || typ == TProbeExtra || typ == TProbeAlt:
			return OK // sender is necessarily the server
		case typ == THairpin:
			if from == recv {
				return OK
			}
		default:
			if from != recv {
				return OK
			}
		}
		return ErrRole
	}
	for _, recv := range []Role{RoleInitiator, RoleResponder, RoleServer} {
		c := newCodec(t, recv)
		for _, typ := range allTypes() {
			for from := Role(0); from <= RoleServer+1; from++ {
				h := Header{Type: typ, Role: from}
				if got, want := c.CheckRole(&h), expect(recv, typ, from); got != want {
					t.Errorf("receiver %d, type %d, sender %d: %v, want %v", recv, typ, from, got, want)
				}
			}
		}
		for _, typ := range []Type{0, THandoverAck + 1, 255} {
			if got := c.CheckRole(&Header{Type: typ, Role: RoleInitiator}); got != ErrPayload {
				t.Errorf("type %d: %v", typ, got)
			}
		}
	}
	// The concrete cases of the role rules.
	ini, resp := newCodec(t, RoleInitiator), newCodec(t, RoleResponder)
	for _, c := range []struct {
		c    *Codec
		h    Header
		want DecodeError
	}{
		{ini, Header{Type: TPunch, Role: RoleInitiator}, ErrRole},    // own punch reflected
		{ini, Header{Type: TPunch, Role: RoleResponder}, OK},         // peer's punch
		{ini, Header{Type: TAccept, Role: RoleResponder}, OK},        // accept reaches I
		{resp, Header{Type: TAccept, Role: RoleResponder}, ErrRole},  // own accept reflected
		{resp, Header{Type: TNominate, Role: RoleInitiator}, OK},     // nominate reaches R
		{ini, Header{Type: TNominate, Role: RoleInitiator}, ErrRole}, // own nominate reflected
		{ini, Header{Type: THairpin, Role: RoleInitiator}, OK},       // own hairpin returns
		{ini, Header{Type: THairpin, Role: RoleResponder}, ErrRole},  // peer's hairpin
		{ini, Header{Type: TProbeAck, Role: RoleServer}, OK},         // natprobe reply
		{ini, Header{Type: TProbe, Role: RoleResponder}, ErrRole},    // clients never take probes
		{newCodec(t, RoleServer), Header{Type: TPunch, Role: RoleInitiator}, ErrRole},
	} {
		if got := c.c.CheckRole(&c.h); got != c.want {
			t.Errorf("receiver %d %+v: %v, want %v", c.c.role, c.h, got, c.want)
		}
	}
}

func TestCandID(t *testing.T) {
	for _, c := range []struct {
		stage, index int
		want         uint16
		ok           bool
	}{
		{0, 0, 0, true},
		{3, 17, 3<<12 | 17, true},
		{maxCandStage, maxCandIndex, maxCandStage<<12 | maxCandIndex, true},
		{0, maxCandIndex + 1, NoCand, false},
		{maxCandStage + 1, 0, NoCand, false}, // stage 15 would reach NoCand
		{-1, 0, NoCand, false},
		{0, -1, NoCand, false},
	} {
		if got, ok := CandID(c.stage, c.index); got != c.want || ok != c.ok {
			t.Errorf("CandID(%d, %d) = %#x %v, want %#x %v", c.stage, c.index, got, ok, c.want, c.ok)
		}
	}
}

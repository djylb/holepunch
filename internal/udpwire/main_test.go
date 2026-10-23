package udpwire

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/testkit"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// testToken and testRoute are the KDF vector inputs (0x00..0x1f, 0x20..0x2f).
func testToken() (tok [32]byte) {
	for i := range tok {
		tok[i] = byte(i)
	}
	return tok
}

func testRoute() (r [RouteSize]byte) {
	for i := range r {
		r[i] = 0x20 + byte(i)
	}
	return r
}

// testPad is a session interval inside the protocol bounds.
var testPad = PadPolicy{Min: 100, Max: 220}

// newCodec returns a codec for the vector session in role.
func newCodec(tb testing.TB, role Role) *Codec {
	tb.Helper()
	return newSessionCodec(tb, testToken(), testRoute(), role, testPad)
}

func newSessionCodec(tb testing.TB, tok [32]byte, route [RouteSize]byte, role Role, pad PadPolicy) *Codec {
	tb.Helper()
	c, err := NewCodec(tok, route, role, pad, nil)
	if err != nil {
		tb.Fatalf("NewCodec(%d): %v", role, err)
	}
	return c
}

// randomSession returns a fresh token and route.
func randomSession(r *rand.Rand) (tok [32]byte, route [RouteSize]byte) {
	for i := range tok {
		tok[i] = byte(r.Uint32())
	}
	for i := range route {
		route[i] = byte(r.Uint32())
	}
	return tok, route
}

// headerFor returns a valid header of type typ sent by role.
func headerFor(c *Codec, typ Type) Header {
	h := Header{Type: typ, Role: c.role, Seq: c.NextSeq(), TS: c.Now(), Cand: NoCand}
	switch typ {
	case TNominate, TAccept, TReady, THandoverAck:
		h.Aux = 1
	case TProbe, TProbeAck, TProbeExtra, TProbeAlt, THairpin, TPunch, TSuccess:
		// Aux stays 0.
	}
	return h
}

// tlvsFor returns TLVs carrying every field typ can carry.
func tlvsFor(typ Type) TLVs {
	t := TLVs{RxCount: 7, HasRx: true, ExtraPort: 40001, Cookie: 0xC0FFEE, Slot: 3, Paths: 0b1010}
	t.Observed = netip.MustParseAddrPort("198.51.100.9:50000")
	t.Sandwich.Round, t.Sandwich.Phase, t.Sandwich.Set = 1, 1, true
	r, _ := ruleOf(typ)
	return carried(r.tlvs, t)
}

// carried keeps the fields of t that a type with carry set s transmits, in
// the form Seal accepts (absent SANDWICH/RX_COUNT fully zero).
func carried(s tlvSet, t TLVs) TLVs {
	var w TLVs
	if s.has(tlvObserved) {
		w.Observed = t.Observed
	}
	if s.has(tlvExtraPort) {
		w.ExtraPort = t.ExtraPort
	}
	if s.has(tlvCookie) {
		w.Cookie = t.Cookie
	}
	if s.has(tlvSandwich) && t.Sandwich.Set {
		w.Sandwich = t.Sandwich
	}
	if s.has(tlvRxCount) && t.HasRx {
		w.RxCount, w.HasRx = t.RxCount, true
	}
	if s.has(tlvPathSlot) {
		w.Slot = t.Slot
	}
	if s.has(tlvPaths) {
		w.Paths = t.Paths
	}
	return w
}

// received is what Open returns for sealed TLVs t: OBSERVED comes back
// unmapped and without a zone.
func received(t TLVs) TLVs {
	t.Observed = netaddr.Canon(t.Observed)
	return t
}

// sendersOf returns the roles that may send typ.
func sendersOf(typ Type) []Role {
	r, _ := ruleOf(typ)
	var out []Role
	for _, role := range []Role{RoleInitiator, RoleResponder, RoleServer} {
		if r.senders.has(role) {
			out = append(out, role)
		}
	}
	return out
}

// allTypes lists every valid packet type.
func allTypes() []Type {
	var out []Type
	for t := TProbe; t <= THandoverAck; t++ {
		out = append(out, t)
	}
	return out
}

// mustSeal seals a packet; reply types get their minimum legal length. A nil
// t means no TLVs, as for Seal.
func mustSeal(tb testing.TB, c *Codec, h *Header, t *TLVs) []byte {
	tb.Helper()
	if t == nil {
		t = &TLVs{}
	}
	n := 0
	if r, _ := ruleOf(h.Type); r.length == lengthExplicit {
		n = HeaderSize + t.size(r.tlvs)
	}
	pkt, err := c.Seal(nil, h, t, n)
	if err != nil {
		tb.Fatalf("Seal(%+v): %v", h, err)
	}
	return pkt
}

// open dispatches to Open or OpenProbe by envelope.
func open(c *Codec, pkt []byte, probe bool, h *Header, t *TLVs) DecodeError {
	scratch := make([]byte, MaxPlaintext)
	if probe {
		return c.OpenProbe(pkt, scratch, h, t)
	}
	return c.Open(pkt, scratch, h, t)
}

// sealPlain encrypts an arbitrary plaintext with c's key into the envelope of
// the caller's choice, bypassing every Seal check. It builds packets that only
// a key holder could produce, to exercise the post-AEAD checks.
func sealPlain(c *Codec, plain []byte, probe bool, b0 byte) []byte {
	var nonce [NonceSize]byte
	c.mu.Lock()
	_, _ = c.nonces.Read(nonce[:]) // ChaCha8.Read always fills p and returns nil
	c.mu.Unlock()
	pkt := append([]byte{b0}, nonce[:]...)
	if probe {
		mask := routeMask(nonce[:])
		for i := range RouteSize {
			pkt = append(pkt, c.route[i]^mask[i])
		}
	}
	return c.aead.Seal(pkt, nonce[:], plain, c.aad[b0-B0Min][:])
}

// gcmFor builds an AES-256-GCM from a raw key.
func gcmFor(tb testing.TB, key []byte) cipher.AEAD {
	tb.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		tb.Fatal(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		tb.Fatal(err)
	}
	return g
}

// countingAEAD counts Open calls of the wrapped AEAD.
type countingAEAD struct {
	cipher.AEAD
	mu    sync.Mutex
	opens int
}

func (a *countingAEAD) Open(dst, nonce, ct, aad []byte) ([]byte, error) {
	a.mu.Lock()
	a.opens++
	a.mu.Unlock()
	return a.AEAD.Open(dst, nonce, ct, aad)
}

func (a *countingAEAD) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.opens
}

// clockStart is the time the tests' fake clocks start at.
var clockStart = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// datagram is one packet queued in a queueConn.
type datagram struct {
	data []byte
	from net.Addr
}

// queueConn is a net.PacketConn that serves queued datagrams and then io.EOF.
type queueConn struct {
	mu     sync.Mutex
	queue  []datagram
	closed bool
}

func (q *queueConn) push(data []byte, from net.Addr) {
	q.mu.Lock()
	q.queue = append(q.queue, datagram{data: data, from: from})
	q.mu.Unlock()
}

func (q *queueConn) ReadFrom(p []byte) (int, net.Addr, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.queue) == 0 {
		return 0, nil, io.EOF
	}
	d := q.queue[0]
	q.queue = q.queue[1:]
	return copy(p, d.data), d.from, nil
}

func (q *queueConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

func (q *queueConn) Close() error {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	return nil
}

func (q *queueConn) LocalAddr() net.Addr              { return udpAddr("127.0.0.1:1") }
func (q *queueConn) SetDeadline(time.Time) error      { return nil }
func (q *queueConn) SetReadDeadline(time.Time) error  { return nil }
func (q *queueConn) SetWriteDeadline(time.Time) error { return nil }

func (q *queueConn) isClosed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.closed
}

func udpAddr(s string) *net.UDPAddr { return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s)) }

// newRand returns a deterministic generator for reproducible statistics.
func newRand(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15)) }

// iterations scales a statistical loop down under -short and -race.
func iterations(n int) int {
	if testing.Short() || testkit.RaceEnabled {
		return max(n/10, 1)
	}
	return n
}

// quicBits reports quic-go's classification of a first byte:
// IsPotentialQUICPacket (bit 6) and IsLongHeaderPacket (bit 7).
func quicBits(b byte) (potential, long bool) { return b&0x40 != 0, b&0x80 != 0 }

// chiSquare is Pearson's statistic of counts against a uniform expectation.
func chiSquare(counts []int, total int) float64 {
	exp := float64(total) / float64(len(counts))
	var x float64
	for _, c := range counts {
		d := float64(c) - exp
		x += d * d / exp
	}
	return x
}

// chiSquare11At01 is the χ² critical value for 11 degrees of freedom at
// p = 0.01: twelve equiprobable b0 values pass when the statistic is below it.
const chiSquare11At01 = 24.725

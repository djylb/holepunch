package natprobe

import (
	"crypto/rand"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// open decodes a reply as the client and checks it against the client's
// window over the server's seq.
func open(t *testing.T, c *client, b []byte) (udpwire.Header, udpwire.TLVs) {
	t.Helper()
	h, tl, ok := c.open(b)
	if !ok {
		t.Fatalf("reply does not open: % x", b[:8])
	}
	if !c.win.Accept(h.Seq) {
		t.Fatalf("reply seq %d replayed", h.Seq)
	}
	return h, tl
}

// The basic exchange: ack and extra, echoes, observed address, cookie, source.
func TestProbeReplies(t *testing.T) {
	r := newRig(t, rigOpts{})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	sock := nat.SocketID(protocol.FamilyUDP4, 0)
	pkt := c.probe(probeOpts{sock: sock, obs: 1, extra: true})
	var ph udpwire.Header
	var pt udpwire.TLVs
	cp := append([]byte(nil), pkt...)
	if newClient(t, tok(1), rt(1), udpwire.RoleServer).codec.OpenProbe(cp, make([]byte, len(cp)), &ph, &pt) != udpwire.OK {
		t.Fatal("cannot reopen the probe")
	}
	out := r.deliver(1, pkt, srcA)
	if len(out) != 2 {
		t.Fatalf("%d replies", len(out))
	}
	ack, extra := out[0], out[1]
	if ack.from != r.ls[1].adv || ack.to != srcA || extra.to != srcA || extra.from != netip.MustParseAddrPort("198.51.100.1:40999") {
		t.Fatalf("addresses ack %v→%v extra %v→%v", ack.from, ack.to, extra.from, extra.to)
	}
	if len(ack.b)+len(extra.b) > len(pkt) || len(ack.b) < 83 || len(extra.b) < 73 {
		t.Fatalf("lengths %d+%d for %d", len(ack.b), len(extra.b), len(pkt))
	}
	ah, at := open(t, c, ack.b)
	if ah.Type != udpwire.TProbeAck || ah.Role != udpwire.RoleServer || !ah.FA || ah.FB || ah.FC || ah.Sock != sock || ah.Aux != 1 ||
		ah.EchoSeq != ph.Seq || ah.EchoTS != ph.TS || ah.Cand != udpwire.NoCand || at.Observed != srcA || at.ExtraPort != 40999 || at.Cookie == 0 {
		t.Fatalf("ack %+v %+v", ah, at)
	}
	xh, xt := open(t, c, extra.b)
	if xh.Type != udpwire.TProbeExtra || xh.EchoSeq != ph.Seq || xt.Observed != srcA || xh.Seq == ah.Seq {
		t.Fatalf("extra %+v %+v", xh, xt)
	}
	h := &Handle{r: r.reg, e: r.reg.lookup(rt(1))}
	so := h.Observations(protocol.RoleInitiator)
	if len(so) != 1 || so[0].Socket != sock || so[0].Observer != 1 || so[0].Observed != srcA || so[0].First != srcA ||
		so[0].Cookie != at.Cookie || so[0].ExtraSent != 1 || so[0].Count != 1 || so[0].FirstSeq != ph.Seq || so[0].Alt || so[0].LAN ||
		!so[0].FirstAt.Equal(r.clk.Now()) {
		t.Fatalf("observations %+v", so)
	}
	if len(h.Observations(protocol.RoleResponder)) != 0 {
		t.Fatal("the other role has slots")
	}
	if r.stats.acks.Load() != 1 || r.stats.extras.Load() != 1 || r.stats.bytesOut.Load() > r.stats.bytesIn.Load() {
		t.Fatalf("stats acks %d extras %d out %d in %d", r.stats.acks.Load(), r.stats.extras.Load(), r.stats.bytesOut.Load(), r.stats.bytesIn.Load())
	}
}

// The reply length rules: a probe below 83 bytes gets no answer, the replies
// never total more bytes than the probe, and their lengths vary.
func TestReplyLengthRule(t *testing.T) {
	r := newRig(t, rigOpts{reg: RegistryConfig{ProbeBudgetPerRole: math.MaxUint16, SessionRate: Rate{PerSec: 1e6, Burst: 1e6}, ExtraQuotaPerRole: 255}})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	ackLens, pairLens, extraLens := map[int]bool{}, map[int]bool{}, map[int]bool{}
	for i := range 3000 {
		plain := 24 + i%200 // wire 69 … 268
		pkt := c.probe(probeOpts{obs: 0, extra: true, plainLen: plain})
		L := len(pkt)
		if i%250 == 249 { // the extra quota is per role: refresh it
			r.reg.lookup(rt(1)).roles[0].extraLeft = 255
		}
		out := r.deliver(0, pkt, srcA)
		total := 0
		for _, o := range out {
			total += len(o.b)
		}
		switch {
		case L < 83:
			if len(out) != 0 {
				t.Fatalf("L=%d answered", L)
			}
		case L < 156:
			if len(out) != 1 {
				t.Fatalf("L=%d: %d replies", L, len(out))
			}
			h, tl := open(t, c, out[0].b)
			if h.FA || tl.ExtraPort != 0 {
				t.Fatalf("L=%d: the ack declares an extra it could not send", L)
			}
		default:
			if len(out) != 2 {
				t.Fatalf("L=%d: %d replies", L, len(out))
			}
			if len(out[0].b) < 83 || len(out[1].b) < 73 {
				t.Fatalf("L=%d lengths %d %d", L, len(out[0].b), len(out[1].b))
			}
			if L == 268 {
				ackLens[len(out[0].b)] = true
				extraLens[len(out[1].b)] = true
				pairLens[total] = true
			}
		}
		if total > L {
			t.Fatalf("reply bytes exceed the probe: %d > %d", total, L)
		}
	}
	if len(ackLens) < 3 || len(pairLens) < 3 || len(extraLens) < 3 {
		t.Fatalf("reply lengths look fixed: %v %v %v", ackLens, pairLens, extraLens)
	}
	if r.stats.bytesOut.Load() > r.stats.bytesIn.Load() {
		t.Fatal("bytes_out > bytes_in")
	}
}

// Reply caps: lifetime budget 96, extra 8, alt 2, quota flag.
func TestReplyCaps(t *testing.T) {
	r := newRig(t, rigOpts{alt: true, reg: RegistryConfig{SessionRate: Rate{PerSec: 1e6, Burst: 1e6}}})
	h := register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	if h.ProbesLeft(protocol.RoleInitiator) != 96 || h.ProbesLeft(protocol.RoleServer) != 0 || (*Handle)(nil).ProbesLeft(protocol.RoleInitiator) != 0 {
		t.Fatal("ProbesLeft before any probe")
	}
	extras, alts, acks, quotaSeen := 0, 0, 0, false
	for i := range 200 {
		o := probeOpts{obs: uint8(i % 3)}
		switch i % 4 {
		case 0:
			o.extra = true
		case 1:
			o.alt = true
		}
		for _, rep := range r.deliver(i%3, c.probe(o), srcA) {
			h, _ := open(t, c, rep.b)
			switch h.Type {
			case udpwire.TProbeAck:
				acks++
				quotaSeen = quotaSeen || h.FC
			case udpwire.TProbeExtra:
				extras++
			case udpwire.TProbeAlt:
				alts++
				if rep.from.Addr() != netip.MustParseAddr("198.51.100.2") {
					t.Fatalf("alt from %v", rep.from)
				}
			default:
				t.Fatalf("reply type %d", h.Type)
			}
		}
	}
	if acks != 96 || extras != 8 || alts != 2 || !quotaSeen || r.stats.budget.Load() != 104 {
		t.Fatalf("acks %d extras %d alts %d quota %v budget %d", acks, extras, alts, quotaSeen, r.stats.budget.Load())
	}
	if left := h.ProbesLeft(protocol.RoleInitiator); left != 0 || h.ProbesLeft(protocol.RoleResponder) != 96 {
		t.Fatalf("ProbesLeft %d after the budget, responder %d", left, h.ProbesLeft(protocol.RoleResponder))
	}
	// the other role is not affected
	c2 := newClient(t, tok(1), rt(1), udpwire.RoleResponder)
	if out := r.deliver(0, c2.probe(probeOpts{extra: true}), srcA); len(out) != 2 {
		t.Fatalf("responder: %d replies", len(out))
	}
}

// WANT_ALT on the alt listener itself, and WANT_EXTRA with extras disabled,
// get a plain ack.
func TestNoSecondReplyCases(t *testing.T) {
	r := newRig(t, rigOpts{alt: true, noExtra: true})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	out := r.deliver(0, c.probe(probeOpts{obs: 0, extra: true}), srcA)
	if len(out) != 1 {
		t.Fatalf("%d replies with extras disabled", len(out))
	}
	if h, _ := open(t, c, out[0].b); h.FA || h.FC {
		t.Fatalf("ack %+v", h)
	}
	out = r.deliver(3, c.probe(probeOpts{obs: 8, alt: true}), srcA)
	if len(out) != 1 {
		t.Fatalf("%d replies on the alt listener", len(out))
	}
	if so := (&Handle{r: r.reg, e: r.reg.lookup(rt(1))}).Observations(protocol.RoleInitiator); len(so) != 2 || !so[1].Alt {
		t.Fatalf("observations %+v", so)
	}
	// no alt group at all
	r2 := newRig(t, rigOpts{})
	register(t, r2.reg, "s1", tok(1), rt(1))
	c2 := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	out = r2.deliver(0, c2.probe(probeOpts{obs: 0, alt: true}), srcA)
	if h, _ := open(t, c2, out[0].b); len(out) != 1 || h.FB {
		t.Fatalf("%d replies, ack %+v", len(out), h)
	}
}

// The (session, role) rate, 16 pps with a burst of 32.
func TestSessionRate(t *testing.T) {
	r := newRig(t, rigOpts{reg: RegistryConfig{ProbeBudgetPerRole: 1000}})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	accepted := 0
	for i := range 400 { // 200 pps for 2 s
		if i%10 == 0 && i > 0 {
			r.clk.Advance(50 * time.Millisecond)
		}
		if len(r.deliver(0, c.probe(probeOpts{}), srcA)) > 0 {
			accepted++
		}
	}
	if accepted > 16*2+32 || accepted < 16*2+30 {
		t.Fatalf("accepted %d", accepted)
	}
}

// The per-source rate limit, and unregistered routes are never decrypted.
func TestSourceRateAndUnknownRoutes(t *testing.T) {
	r := newRig(t, rigOpts{srcRate: Rate{PerSec: 512, Burst: 1024}})
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator) // never registered
	for range 1100 {
		if len(r.deliver(0, c.probe(probeOpts{}), srcA)) != 0 {
			t.Fatal("reply to an unknown route")
		}
	}
	if r.stats.unknownRoute.Load() != 1024 || r.stats.rateSrc.Load() != 76 || r.stats.badAuth.Load() != 0 {
		t.Fatalf("unknown %d rate %d auth %d", r.stats.unknownRoute.Load(), r.stats.rateSrc.Load(), r.stats.badAuth.Load())
	}
	// another /32 has its own bucket; another port of the same /32 does not
	if r.deliver(0, c.probe(probeOpts{}), netip.MustParseAddrPort("203.0.113.6:1")); r.stats.unknownRoute.Load() != 1025 {
		t.Fatal("another prefix limited")
	}
	r.deliver(0, c.probe(probeOpts{}), netip.MustParseAddrPort("203.0.113.5:9"))
	if r.stats.rateSrc.Load() != 77 {
		t.Fatal("the same /32 not limited")
	}
	// v6 /64 aggregation
	l := newSourceLimiter(Rate{PerSec: 1, Burst: 1}, 64)
	a1, a2, b := netip.MustParseAddr("2001:db8:1:2::1"), netip.MustParseAddr("2001:db8:1:2::ffff"), netip.MustParseAddr("2001:db8:1:3::1")
	if !l.allow(a1, 0) || l.allow(a2, 0) || !l.allow(b, 0) {
		t.Fatal("v6 /64 aggregation")
	}
	// 10⁴ random datagrams in the holepunch range: no reply, no AEAD attempt
	r2 := newRig(t, rigOpts{})
	register(t, r2.reg, "s1", tok(1), rt(1))
	buf := make([]byte, 200)
	for i := range 10000 {
		_, _ = rand.Read(buf)
		buf[0] = byte(udpwire.B0Min + i%12)
		if len(r2.deliver(0, buf[:69+i%130], srcA)) != 0 {
			t.Fatal("reply to random data")
		}
	}
	if r2.stats.unknownRoute.Load() != 10000 || r2.stats.badAuth.Load() != 0 {
		t.Fatalf("unknown %d auth %d", r2.stats.unknownRoute.Load(), r2.stats.badAuth.Load())
	}
	// short and foreign datagrams never reach the route lookup
	r2.deliver(0, buf[:68], srcA)
	buf[0] = 0x40
	r2.deliver(0, buf[:100], srcA)
	r2.deliver(0, make([]byte, 1100), srcA)
	r2.deliver(0, buf[:100], netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), 0))
	r2.deliver(0, buf[:100], netip.AddrPortFrom(netip.IPv4Unspecified(), 9))
	if r2.stats.short.Load() != 1 || r2.stats.foreign.Load() != 4 || r2.stats.unknownRoute.Load() != 10000 {
		t.Fatalf("short %d foreign %d", r2.stats.short.Load(), r2.stats.foreign.Load())
	}
}

// The source limiter's LRU: a full shard evicts its least recently used
// prefix, whose state starts over.
func TestSourceLimiterLRU(t *testing.T) {
	l := newSourceLimiter(Rate{PerSec: 1, Burst: 1}, srcShards) // one node per shard
	var a, b netip.Addr
	for i := 1; ; i++ { // two prefixes of the same shard
		x := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
		k := prefixKey(x)
		if !a.IsValid() {
			a = x
			continue
		}
		if (k.p*0x9E3779B97F4A7C15)>>60 == (prefixKey(a).p*0x9E3779B97F4A7C15)>>60 {
			b = x
			break
		}
	}
	if !l.allow(a, 0) || l.allow(a, 0) {
		t.Fatal("bucket of a")
	}
	if !l.allow(b, 0) || !l.allow(a, 0) {
		t.Fatal("the evicted prefix must start over")
	}
	var nilL *sourceLimiter
	if !nilL.allow(a, 0) {
		t.Fatal("a disabled limiter refuses")
	}
}

// Replay and old seq; no wall clock plays a role.
func TestReplay(t *testing.T) {
	r := newRig(t, rigOpts{reg: RegistryConfig{SessionRate: Rate{PerSec: 1e6, Burst: 1e6}, ProbeBudgetPerRole: 5000}})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	pkt := c.probe(probeOpts{seq: 5000})
	if len(r.deliver(0, append([]byte(nil), pkt...), srcA)) == 0 {
		t.Fatal("first copy refused")
	}
	if len(r.deliver(0, pkt, srcA)) != 0 || r.stats.replay.Load() != 1 {
		t.Fatal("replay answered")
	}
	if len(r.deliver(0, c.probe(probeOpts{seq: 5000 - 1024}), srcA)) != 0 || r.stats.replay.Load() != 2 {
		t.Fatal("a seq 1024 behind the top accepted")
	}
	if len(r.deliver(0, c.probe(probeOpts{seq: 5000 - 1023}), srcA)) == 0 {
		t.Fatal("a seq 1023 behind the top refused")
	}
	// the client's clock is irrelevant: codecs ±10 min off
	for _, skew := range []time.Duration{-10 * time.Minute, 10 * time.Minute} {
		cc, err := udpwire.NewCodec(tok(1), rt(1), udpwire.RoleInitiator, udpwire.PadPolicy{Min: 64, Max: 128},
			func() time.Time { return time.Now().Add(skew) })
		if err != nil {
			t.Fatal(err)
		}
		skewed := &client{t: t, codec: cc, role: udpwire.RoleInitiator}
		if len(r.deliver(0, skewed.probe(probeOpts{seq: 6000 + uint32(skew/time.Minute+20)}), srcA)) == 0 {
			t.Fatalf("refused with a client clock off by %v", skew)
		}
	}
	// a server clock that steps back restarts the session bucket, never stalls it
	r.clk.Advance(-10 * time.Minute)
	if len(r.deliver(0, c.probe(probeOpts{seq: 7000}), srcA)) == 0 {
		t.Fatal("refused after a backward clock step")
	}
}

// The observer id must match the listener; tampering; envelopes.
func TestRejections(t *testing.T) {
	r := newRig(t, rigOpts{})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	if len(r.deliver(1, c.probe(probeOpts{obs: 2}), srcA)) != 0 || r.stats.badObserver.Load() != 1 {
		t.Fatal("observer mismatch answered")
	}
	pkt := c.probe(probeOpts{obs: 0})
	pkt[len(pkt)-1] ^= 1
	if len(r.deliver(0, pkt, srcA)) != 0 || r.stats.badAuth.Load() != 1 {
		t.Fatal("tampered probe answered")
	}
	// a modified masked route finds no session, or not this one
	pkt = c.probe(probeOpts{obs: 0})
	pkt[udpwire.PeerOuterSize+3] ^= 1
	if len(r.deliver(0, pkt, srcA)) != 0 || r.stats.unknownRoute.Load() != 1 {
		t.Fatal("modified route answered")
	}
	// a non-probe type sealed with the session key (the wrong envelope) fails
	h := udpwire.Header{Type: udpwire.TPunch, Role: udpwire.RoleInitiator, Seq: c.codec.NextSeq(), Cand: udpwire.NoCand}
	punch, err := c.codec.Seal(nil, &h, nil, 120)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.deliver(0, append(punch, make([]byte, 20)...), srcA)) != 0 {
		t.Fatal("punch answered")
	}
	if r.stats.acks.Load() != 0 {
		t.Fatal("acks")
	}
}

// Cookies are renewed when the observed address changes; a role
// without a free slot still gets acks, with cookie 0.
func TestCookiesAndSlots(t *testing.T) {
	r := newRig(t, rigOpts{reg: RegistryConfig{SlotsPerRole: 2}})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	cookie := func(out []captured) uint32 {
		_, tl := open(t, c, out[0].b)
		return tl.Cookie
	}
	c1 := cookie(r.deliver(0, c.probe(probeOpts{sock: 0, obs: 0}), srcA))
	c2 := cookie(r.deliver(0, c.probe(probeOpts{sock: 0, obs: 0}), srcA))
	other := netip.MustParseAddrPort("203.0.113.5:40777")
	c3 := cookie(r.deliver(0, c.probe(probeOpts{sock: 0, obs: 0}), other))
	if c1 == 0 || c1 != c2 || c3 == c2 {
		t.Fatalf("cookies %d %d %d", c1, c2, c3)
	}
	so := (&Handle{r: r.reg, e: r.reg.lookup(rt(1))}).Observations(protocol.RoleInitiator)
	if len(so) != 1 || so[0].First != srcA || so[0].Observed != other || so[0].Changes != 1 || so[0].Count != 3 || so[0].Cookie != c3 {
		t.Fatalf("slot %+v", so)
	}
	cookie(r.deliver(1, c.probe(probeOpts{sock: 0, obs: 1}), srcA))
	if c := cookie(r.deliver(2, c.probe(probeOpts{sock: 0, obs: 2}), srcA)); c != 0 {
		t.Fatalf("the third slot got cookie %d", c)
	}
	// slots grow beyond their initial capacity
	r2 := newRig(t, rigOpts{reg: RegistryConfig{SessionRate: Rate{PerSec: 1e6, Burst: 1e6}}})
	register(t, r2.reg, "s1", tok(1), rt(1))
	for sock := range uint8(6) {
		for o := range 3 {
			r2.deliver(o, c.probe(probeOpts{sock: sock, obs: uint8(o)}), srcA)
		}
	}
	if n := len((&Handle{r: r2.reg, e: r2.reg.lookup(rt(1))}).Observations(protocol.RoleInitiator)); n != 18 {
		t.Fatalf("%d slots", n)
	}
}

// The forged-source case: a slot recorded for a third-party IP V can
// never be echoed by the attacker, who never sees the ack.
func TestForgedSourceNeverVerified(t *testing.T) {
	r := newRig(t, rigOpts{})
	h := register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleResponder)
	victim := netip.MustParseAddrPort("192.0.2.77:9")
	for o := range 3 {
		r.deliver(o, c.probe(probeOpts{sock: 0, obs: uint8(o)}), victim) // the acks go to the victim
	}
	rep := reportFor("s1", protocol.RoleResponder, protocol.FamilyUDP4, "10.0.0.2:5000",
		[]protocol.RowReport{{Observer: 0, Observed: victim, RTTMs: 10}, {Observer: 1}, {Observer: 2}})
	view, diag, err := h.Merge(protocol.RoleResponder, rep, nil, TraitsKey{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range view.Families[0].Endpoints {
		if e.Verified || e.Addr == victim {
			t.Fatalf("victim endpoint %+v", e)
		}
	}
	if diag.CookieMissing != 3 || view.Families[0].Traits.Samples != 3 {
		t.Fatalf("diag %+v traits %+v", diag, view.Families[0].Traits)
	}
}

func TestWriteErrors(t *testing.T) {
	r := newRig(t, rigOpts{})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	r.ls[0].conn.(*captureConn).fail = true
	r.ls[0].pool.conns[0].(*captureConn).fail = true
	if len(r.deliver(0, c.probe(probeOpts{extra: true}), srcA)) != 0 || r.stats.writeErrs.Load() != 2 {
		t.Fatalf("write errors %d", r.stats.writeErrs.Load())
	}
	if r.stats.acks.Load() != 0 || r.stats.extras.Load() != 0 || r.stats.bytesOut.Load() != 0 {
		t.Fatal("failed writes counted as sent")
	}
}

// Sandwich events queue (8), are delivered outside the reader's
// locks one session at a time and dropped when the queue is full; a blocked
// sink never blocks the other readers.
func TestSandwichQueue(t *testing.T) {
	r := newRig(t, rigOpts{reg: RegistryConfig{SessionRate: Rate{PerSec: 1e6, Burst: 1e6}}})
	h := register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	sw := &[2]uint8{1, nat.SandwichBefore}
	// before a sink: queued, then delivered by the attach
	r.deliver(0, c.probe(probeOpts{sandwich: sw}), srcA)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var mu sync.Mutex
	var got []nat.SandwichEvent
	h.setEventFunc(func(ev nat.SandwichEvent) {
		mu.Lock()
		got = append(got, ev)
		n := len(got)
		mu.Unlock()
		if n == 2 {
			entered <- struct{}{}
			<-release
		}
	})
	mu.Lock()
	if len(got) != 1 {
		t.Fatalf("the queued event was not delivered on attach: %d", len(got))
	}
	mu.Unlock()
	// reader 0 delivers and blocks in the sink on the second event
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.rds[0].process(c.probe(probeOpts{sandwich: sw}), srcA)
	}()
	<-entered
	// meanwhile reader 1 keeps answering; with the event in the sink, 7 more
	// fit the capacity of 8
	for range 12 {
		r.rds[1].process(c.probe(probeOpts{obs: 1, sandwich: sw}), srcA)
	}
	if r.stats.acks.Load() != 14 || r.stats.sandwichDropped.Load() != 5 {
		t.Fatalf("acks %d dropped %d", r.stats.acks.Load(), r.stats.sandwichDropped.Load())
	}
	close(release)
	<-done
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 9 || r.stats.sandwichEvents.Load() != 9 {
		t.Fatalf("delivered %d, events %d", n, r.stats.sandwichEvents.Load())
	}
	// a panicking sink is contained and counted
	h.setEventFunc(func(nat.SandwichEvent) { panic("sink") })
	r.deliver(0, c.probe(probeOpts{sandwich: sw}), srcA)
	if r.stats.panics.Load() != 1 {
		t.Fatalf("panics %d", r.stats.panics.Load())
	}
	// after Close: nothing is delivered or queued
	h.Close()
	h.setEventFunc(func(nat.SandwichEvent) { t.Error("sink after close") })
	var q sandwichQueue
	q.close()
	if ok, _ := q.offer(nat.SandwichEvent{}, 8); ok {
		t.Fatal("offer after close")
	}
	var nilH *Handle
	nilH.setEventFunc(nil)
}

// A GCRA state saturated at T is not reset by an event
// stamped slightly earlier than T, which is what a reader whose clock read
// lost the race for the bucket's lock passes. Only a step back of at least
// clockBackStep restarts the bucket.
func TestGCRAStaleTimestampDoesNotReset(t *testing.T) {
	r := Rate{PerSec: 512, Burst: 1024}
	var tat int64
	const T = int64(10 * time.Second)
	burst := 0
	for range 4000 {
		if gcra(&tat, T, r) {
			burst++
		}
	}
	if burst != r.Burst {
		t.Fatalf("burst %d, want %d", burst, r.Burst)
	}
	for _, back := range []time.Duration{time.Microsecond, time.Millisecond, 500 * time.Millisecond} {
		if gcra(&tat, T-int64(back), r) {
			t.Fatalf("an event stamped %v early was admitted from a full bucket", back)
		}
	}
	again := 0
	for range 4000 {
		if gcra(&tat, T, r) {
			again++
		}
	}
	if again != 0 {
		t.Fatalf("%d admitted again at T: the bucket was reset", again)
	}
	// a real clock step back restarts the bucket rather than stalling it
	if !gcra(&tat, T-int64(10*time.Minute), r) {
		t.Fatal("refused after a 10 min clock step back")
	}
}

// realClockPath is the packet path of a Server with n readers over the real
// clock, without sockets: what the readers of a started Server share.
func realClockPath(regCfg RegistryConfig, src Rate, n int) (*Registry, []*reader, *readerStats) {
	reg := NewRegistry(regCfg)
	s := &Server{cfg: ServerConfig{Registry: reg}, reg: reg, src: newSourceLimiter(src, 4096)}
	p := &pool{conns: []packetConn{discardConn{}}, ports: []uint16{40999}}
	st := &readerStats{}
	var rds []*reader
	for i := range n {
		l := &listener{id: uint8(i % 3), fam: protocol.FamilyUDP4, conn: discardConn{}, pool: p,
			adv: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(3478+i%3))}
		rds = append(rds, newReader(s, l, st))
	}
	return reg, rds, st
}

// floodFor runs every reader on its own goroutine over pkts[i] until d
// elapsed and returns the wall time it took.
func floodFor(rds []*reader, pkts [][]byte, src netip.AddrPort, d time.Duration) time.Duration {
	start := time.Now()
	var wg sync.WaitGroup
	for i, rd := range rds {
		wg.Go(func() {
			for time.Since(start) < d {
				rd.process(pkts[i%len(pkts)], src)
			}
		})
	}
	wg.Wait()
	return time.Since(start)
}

// Six readers (3 listeners × the default 2) flooding unknown routes
// from one source prefix pass the source limiter no more often than one
// reader may: Burst + PerSec·elapsed.
func TestSourceLimiterConcurrentReaders(t *testing.T) {
	for _, n := range []int{1, 6} {
		_, rds, st := realClockPath(RegistryConfig{}, Rate{PerSec: 512, Burst: 1024}, n)
		pkt := make([]byte, 160)
		_, _ = rand.Read(pkt)
		pkt[0] = 0x07
		el := floodFor(rds, [][]byte{pkt}, srcA, 300*time.Millisecond)
		bound := 1024 + int(512*el.Seconds()) + 1
		if passed := int(st.unknownRoute.Load()); passed > bound {
			t.Fatalf("%d readers: %d of %d packets passed the source limiter, bound %d", n, passed, st.packetsIn.Load(), bound)
		}
	}
}

// One (session, role) probing three listeners served by six
// readers is held to the session rate (16 pps, burst 32). Replays still pass
// through the session GCRA first, so a few probes sent in a loop measure it.
func TestSessionRateConcurrentReaders(t *testing.T) {
	for _, n := range []int{1, 6} {
		reg, rds, st := realClockPath(RegistryConfig{ProbeBudgetPerRole: 60000}, Rate{PerSec: -1}, n)
		if _, err := reg.Register(Registration{SessionID: "s1", Route: rt(1), Token: tok(1), TTL: time.Minute}); err != nil {
			t.Fatal(err)
		}
		c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
		pkts := make([][]byte, len(rds))
		for i, rd := range rds {
			pkts[i] = c.probe(probeOpts{obs: rd.l.id})
		}
		el := floodFor(rds, pkts, srcA, 500*time.Millisecond)
		bound := 32 + int(16*el.Seconds()) + 1
		if passed := int(st.packetsIn.Load() - st.rateSession.Load()); passed > bound {
			t.Fatalf("%d readers: the session limiter admitted %d in %v, bound %d", n, passed, el, bound)
		}
	}
}

// No sink call starts after Handle.Close returned, even when a reader
// or the attach is in the middle of delivering a queue.
func TestSandwichNoDeliveryAfterClose(t *testing.T) {
	r := newRig(t, rigOpts{reg: RegistryConfig{SessionRate: Rate{PerSec: 1e6, Burst: 1e6}}})
	h := register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	sw := &[2]uint8{1, nat.SandwichBefore}
	r.deliver(0, c.probe(probeOpts{sandwich: sw}), srcA)
	r.deliver(0, c.probe(probeOpts{sandwich: sw}), srcA)
	entered, release := make(chan struct{}), make(chan struct{})
	var closed atomic.Bool
	var calls, afterClose atomic.Int32
	sink := func(nat.SandwichEvent) {
		if closed.Load() {
			afterClose.Add(1)
		}
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); h.setEventFunc(sink) }() // coord's attach delivers the queue
	<-entered
	h.Close()
	closed.Store(true)
	close(release)
	<-done
	if afterClose.Load() != 0 || calls.Load() != 1 {
		t.Fatalf("%d sink call(s) started after Close (%d in all)", afterClose.Load(), calls.Load())
	}
}

// The capacity bounds every event the sink has not consumed, the one in
// the sink included: more than 8 unconsumed are dropped.
func TestSandwichQueueBoundCountsInFlight(t *testing.T) {
	r := newRig(t, rigOpts{reg: RegistryConfig{SessionRate: Rate{PerSec: 1e6, Burst: 1e6}}})
	h := register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	sw := &[2]uint8{1, nat.SandwichBefore}
	for range 8 {
		r.deliver(0, c.probe(probeOpts{sandwich: sw}), srcA)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var consumed atomic.Int32
	sink := func(nat.SandwichEvent) {
		if consumed.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); h.setEventFunc(sink) }()
	<-entered
	for range 8 {
		r.deliver(1, c.probe(probeOpts{obs: 1, sandwich: sw}), srcA)
	}
	queued, used := r.stats.sandwichEvents.Load(), consumed.Load()
	close(release)
	<-done
	if undelivered := int(queued) - int(used) + 1; undelivered > 8 {
		t.Fatalf("%d events not consumed (one in the sink) exceed the capacity 8", undelivered)
	}
	if r.stats.sandwichDropped.Load() != 8 {
		t.Fatalf("dropped %d, want all 8 offered while the queue was full", r.stats.sandwichDropped.Load())
	}
}

// A sink panic during the attach-time delivery is counted in
// ServerStats.Panics, exactly once, by the Server reading its stats.
func TestAttachSinkPanicCounted(t *testing.T) {
	r := newRig(t, rigOpts{})
	h := register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	r.deliver(0, c.probe(probeOpts{sandwich: &[2]uint8{1, nat.SandwichBefore}}), srcA)
	calls := 0
	nat.AttachSandwichSink(h, func(nat.SandwichEvent) { calls++; panic("sink") })
	if calls != 1 {
		t.Fatalf("sink calls %d", calls)
	}
	if st := r.s.Stats(); st.Panics != 1 {
		t.Fatalf("Panics %d, want 1", st.Panics)
	}
	if st := r.s.Stats(); st.Panics != 1 {
		t.Fatalf("Panics %d on a second read, want 1", st.Panics)
	}
}

// A sandwich probe of a session with an attached sink costs no
// allocation on the packet path, delivery included.
func TestSandwichZeroAlloc(t *testing.T) {
	bp := newBenchPath()
	token, route := protocol.NewToken(), protocol.NewRouteID()
	h, err := bp.reg.Register(Registration{SessionID: "sw", Route: route, Token: token, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	delivered := 0
	nat.AttachSandwichSink(h, func(nat.SandwichEvent) { delivered++ })
	c := newClient(t, token, route, udpwire.RoleInitiator)
	pkts := make([][]byte, 2000)
	for i := range pkts {
		pkts[i] = c.probe(probeOpts{sandwich: &[2]uint8{1, nat.SandwichAfter}})
	}
	i := 0
	if a := testing.AllocsPerRun(50, func() { bp.handle(pkts[i], srcA); i++ }); a != 0 {
		t.Fatalf("%v allocations per sandwich probe", a)
	}
	if delivered != i {
		t.Fatalf("delivered %d of %d", delivered, i)
	}
}

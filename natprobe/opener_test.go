package natprobe

import (
	"math"
	"testing"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// TestOpenerProbe checks the flow opener on the server: a probe that comes as
// an opener is answered like a plain one, every reply leaves as an opener too,
// the reply bytes still never exceed the request's (counting the openers), and
// a plain probe after it gets plain replies.
func TestOpenerProbe(t *testing.T) {
	r := newRig(t, rigOpts{reg: RegistryConfig{ProbeBudgetPerRole: math.MaxUint16, SessionRate: Rate{PerSec: 1e6, Burst: 1e6}, ExtraQuotaPerRole: 255}})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	sock := nat.SocketID(protocol.FamilyUDP4, 0)
	pairs := 0
	for i := range 400 {
		pkt := c.codec.Wrap(nil, c.probe(probeOpts{sock: sock, obs: 1, extra: true, plainLen: 96 + i%160}))
		if i%200 == 199 {
			r.reg.lookup(rt(1)).roles[0].extraLeft = 255
		}
		out := r.deliver(1, pkt, srcA)
		if len(out) == 0 {
			t.Fatalf("opener of %d bytes not answered", len(pkt))
		}
		total := 0
		for _, o := range out {
			total += len(o.b)
			inner, e := udpwire.Unwrap(o.b)
			if e != udpwire.OK {
				t.Fatalf("reply to an opener is not an opener: %v", e)
			}
			open(t, c, inner)
		}
		if len(out) == 2 {
			pairs++
		}
		if total > len(pkt) {
			t.Fatalf("amplification: %d reply bytes for a %d-byte opener", total, len(pkt))
		}
	}
	if pairs == 0 {
		t.Fatal("no opener got two replies")
	}
	out := r.deliver(1, c.probe(probeOpts{sock: sock, obs: 1}), srcA)
	if len(out) != 1 || udpwire.Wrapped(out[0].b) {
		t.Fatal("a plain probe got no plain reply")
	}
	if got := r.stats.openers.Load(); got != 400 {
		t.Fatalf("openers counted %d", got)
	}
}

// TestOpenerRejects checks that a malformed opener is counted as short or
// foreign before any lookup and never answered.
func TestOpenerRejects(t *testing.T) {
	r := newRig(t, rigOpts{})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	w := c.codec.Wrap(nil, c.probe(probeOpts{obs: 0}))
	bad := append([]byte(nil), w...)
	bad[len(bad)-1] ^= 1 // FINGERPRINT
	if out := r.deliver(0, bad, srcA); len(out) != 0 || r.stats.foreign.Load() != 1 {
		t.Fatalf("bad FINGERPRINT: %d replies, foreign %d", len(out), r.stats.foreign.Load())
	}
	if out := r.deliver(0, w[:40], srcA); len(out) != 0 || r.stats.short.Load() != 1 {
		t.Fatalf("truncated opener: %d replies, short %d", len(out), r.stats.short.Load())
	}
	if r.stats.unknownRoute.Load() != 0 || r.stats.badAuth.Load() != 0 {
		t.Fatal("a malformed opener reached the route lookup")
	}
}

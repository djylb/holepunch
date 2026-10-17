package coord

import (
	"context"
	"flag"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

var chaosSeeds = flag.Int("chaos.seeds", 500, "seeds of TestChaosRandom (a thorough run uses 10 000)")

// TestChaosRandom runs random scripts — frames of both sides in any order,
// clock steps, disconnects, injections, aborts and shutdowns — and checks
// four invariants for each seed: no panic escapes, the session ends,
// OnResult runs once, and nothing stays allocated.
func TestChaosRandom(t *testing.T) {
	seeds := *chaosSeeds
	if testing.Short() {
		seeds = 50
	}
	for seed := range seeds {
		rng := rand.New(rand.NewPCG(uint64(seed), 7))
		script := make([]byte, 8+rng.IntN(40))
		for i := range script {
			script[i] = byte(rng.Uint32())
		}
		ending := rng.IntN(3)
		ok := t.Run("", func(t *testing.T) {
			r := newRig(t)
			p := r.pair(SessionOptions{ClientKeys: [2]string{"vis", "prov"}})
			cx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			drained := make(chan struct{}, 2)
			for i := range 2 {
				go func() {
					defer func() { drained <- struct{}{} }()
					for {
						if _, _, err := p.cl[i].Next(cx); err != nil {
							return
						}
					}
				}()
			}
			for n, b := range script {
				arg := byte(0)
				if n+1 < len(script) {
					arg = script[n+1]
				}
				fuzzStep(cx, r, p, int(b&1), b>>1, arg, script[n:])
			}
			switch ending {
			case 0:
				p.s.Abort(protocol.ReasonCanceled, "chaos")
			case 1:
				_ = r.c.Close()
			default:
				for range 20 {
					r.clk.Advance(5 * time.Second)
					if p.s.Snapshot().State == StateClosed {
						break
					}
				}
				p.s.Abort(protocol.ReasonCanceled, "chaos")
			}
			res := r.wait(p.s)
			if !res.Reason.Known() && res.Reason != "" {
				t.Fatalf("unknown code %q", res.Reason)
			}
			if r.c.Len() != 0 || r.c.Stats().ActiveByKey != 0 {
				t.Fatalf("not released: %d sessions, %d keys", r.c.Len(), r.c.Stats().ActiveByKey)
			}
			select {
			case <-r.results:
			case <-time.After(waitLimit):
				t.Fatal("no OnResult")
			}
			select {
			case <-r.results:
				t.Fatal("second OnResult")
			default:
			}
			_ = p.cl[0].Close()
			_ = p.cl[1].Close()
			<-drained
			<-drained
		})
		if !ok {
			t.Fatalf("seed %d failed", seed)
		}
	}
}

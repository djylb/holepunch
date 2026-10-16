package e2e

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
	"testing"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// lenInterval returns the [min, max] packet length over the sockets of a
// session's shape purposes.
func lenInterval(socks []nattest.SocketStats) (lo, hi int, n uint64) {
	lo = math.MaxInt
	for _, s := range socks {
		if !slices.Contains(shapePurposes, s.Purpose) {
			continue
		}
		for l, c := range s.LenHistogram {
			if c == 0 {
				continue
			}
			lo, hi = min(lo, l), max(hi, l)
			n += c
		}
	}
	return lo, hi, n
}

// portsTo returns the destination ports a side sent to on the given IPs,
// without the ports of the peer's endpoints the summary listed (the Direct
// targets every session aims at).
func portsTo(sent map[netip.AddrPort]int, ips []netip.Addr, known []protocol.Endpoint) map[uint16]bool {
	out := map[uint16]bool{}
	for ap := range sent {
		if !slices.Contains(ips, ap.Addr()) {
			continue
		}
		if slices.ContainsFunc(known, func(e protocol.Endpoint) bool { return e.Addr == ap }) {
			continue
		}
		out[ap.Port()] = true
	}
	return out
}

// shapePair is a NAT pair of the shape test; sprayPorts checks the random
// port sets the first side sprays at the second.
type shapePair struct {
	name       string
	a, b       func() nattest.NATConfig
	sprayPorts bool
}

// TestShapeAcrossSessions checks packet lengths and random ports over two
// consecutive sessions of one NAT pair: the packet-length intervals differ
// between the sessions — on one side at least, since the extremes of a
// side's few dozen packets repeat by chance about once in a thousand pairs
// of sessions — and the random ports one side sprays at the other overlap
// no more than chance allows (a Poisson tail of sprayAlpha).
func TestShapeAcrossSessions(t *testing.T) {
	pairs := []shapePair{
		{name: "PRC-PRC", a: profPRC, b: profPRC},
		{name: "PRC-SYMRND", a: profPRC, b: profSYMRND, sprayPorts: true},
	}
	if suite().level == levelNightly {
		pairs = append(pairs, shapePair{name: "FC-SYMSEQ", a: profFC, b: profSYMSEQ})
	}
	t.Run("pairs", func(t *testing.T) {
		for _, p := range pairs {
			if !suite().selected("shape/" + p.name) {
				continue
			}
			t.Run(p.name, func(t *testing.T) {
				t.Parallel()
				release := acquireSlot()
				defer release()
				for _, e := range shapeAcross(t, p, cellSeed("shape/"+p.name, 0)) {
					t.Error(e)
				}
			})
		}
	})
	goleak.VerifyNone(t)
}

// sprayAlpha is the chance that two sessions' independent random ports
// share as many ports as the check tolerates: low enough that the check
// never fails by chance, while ports reused across sessions overlap by
// hundreds.
const sprayAlpha = 1e-6

// poissonLimit returns the smallest k with P(X ≥ k) ≤ alpha for X ~
// Poisson(mean). The overlap of two random port sets is hypergeometric,
// whose tail the Poisson one bounds.
func poissonLimit(mean, alpha float64) int {
	if mean <= 0 {
		return 1
	}
	pmf := func(j int) float64 {
		lg, _ := math.Lgamma(float64(j + 1))
		return math.Exp(float64(j)*math.Log(mean) - mean - lg)
	}
	for k := max(int(mean), 1); ; k++ {
		// P(X ≥ k): the terms past the mode only shrink.
		tail := 0.0
		for j := k; ; j++ {
			q := pmf(j)
			tail += q
			if q <= tail*1e-12 {
				break
			}
		}
		if tail <= alpha {
			return k
		}
	}
}

// shapeAcross runs the two sessions and returns the violations.
func shapeAcross(t *testing.T, p shapePair, seed int64) (v []string) {
	w := newWorld(t, worldConfig{seed: seed})
	defer func() {
		if err := w.close(); err != nil {
			v = append(v, err.Error())
		}
	}()
	sides := [2]*side{w.behind([]nattest.NATConfig{p.a()}), w.behind([]nattest.NATConfig{p.b()})}
	type session struct {
		lo, hi [2]int
		ports  map[uint16]bool
	}
	var got [2]session
	var opened [2]int
	for k := range got {
		for _, s := range sides {
			s.net.record()
		}
		r, err := newRun(w, sides, sessionSpec{ablation: ablation.Set{}})
		if err != nil {
			return append(v, err.Error())
		}
		r.execute()
		for i := range 2 {
			socks := r.out[i].host.Sockets[opened[i]:]
			opened[i] = len(r.out[i].host.Sockets)
			lo, hi, n := lenInterval(socks)
			if n == 0 {
				v = append(v, fmt.Sprintf("session %d %s: no packet", k+1, roles[i]))
			}
			got[k].lo[i], got[k].hi[i] = lo, hi
		}
		if s := view(r.taps[0]).summary; s != nil && len(s.Peer.Families) > 0 {
			got[k].ports = portsTo(sides[0].net.sentTo(), sides[1].publicIPs(), s.Peer.Families[0].Endpoints)
		}
		if err := r.closeSessions(); err != nil {
			v = append(v, err.Error())
		}
	}
	if got[0].lo == got[1].lo && got[0].hi == got[1].hi {
		v = append(v, fmt.Sprintf("the same length intervals in two sessions: %s [%d, %d], %s [%d, %d]",
			roles[0], got[0].lo[0], got[0].hi[0], roles[1], got[0].lo[1], got[0].hi[1]))
	}
	if p.sprayPorts {
		a, b := got[0].ports, got[1].ports
		if len(a) == 0 || len(b) == 0 {
			v = append(v, fmt.Sprintf("no random ports sprayed (%d, %d)", len(a), len(b)))
			return v
		}
		common := 0
		for port := range a {
			if b[port] {
				common++
			}
		}
		exp := float64(len(a)) * float64(len(b)) / portSpace
		if limit := poissonLimit(exp, sprayAlpha); common >= limit {
			v = append(v, fmt.Sprintf("random ports of two sessions share %d of %d/%d, expectation %.1f; %d or more happen by chance with probability ≤ %g",
				common, len(a), len(b), exp, limit, sprayAlpha))
		}
		t.Logf("random ports: %d and %d, %d in common (expectation %.2f)", len(a), len(b), common, exp)
	}
	return v
}

// TestPoissonLimit checks the spray threshold against the Poisson tail
// computed term by term: the limit is the first k whose tail is within alpha.
func TestPoissonLimit(t *testing.T) {
	tail := func(mean float64, k int) float64 {
		p, cdf := math.Exp(-mean), 0.0
		for j := range k {
			cdf += p
			p *= mean / float64(j+1)
		}
		return 1 - cdf
	}
	for _, mean := range []float64{0.15, 1, 2.47, 10, 40} {
		k := poissonLimit(mean, sprayAlpha)
		if tail(mean, k) > sprayAlpha || k > 1 && tail(mean, k-1) <= sprayAlpha {
			t.Errorf("mean %v: limit %d, P(X ≥ %d) = %g, P(X ≥ %d) = %g", mean, k, k, tail(mean, k), k-1, tail(mean, k-1))
		}
	}
	if k := poissonLimit(2000, sprayAlpha); k < 2000 || k > 2300 {
		t.Errorf("mean 2000: limit %d", k)
	}
}

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
// consecutive sessions of one NAT pair: the packet-length
// interval of each side differs between the sessions, and the random ports
// one side sprays at the other overlap no more than chance allows
// (expectation + 3σ).
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

// shapeAcross runs the two sessions and returns the violations.
func shapeAcross(t *testing.T, p shapePair, seed int64) []string {
	var v []string
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
	for i := range 2 {
		if got[0].lo[i] == got[1].lo[i] && got[0].hi[i] == got[1].hi[i] {
			v = append(v, fmt.Sprintf("%s: the same length interval [%d, %d] in two sessions", roles[i], got[0].lo[i], got[0].hi[i]))
		}
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
		if limit := exp + 3*math.Sqrt(exp); float64(common) > math.Max(limit, 1) {
			v = append(v, fmt.Sprintf("random ports of two sessions share %d of %d/%d, expectation %.1f + 3σ = %.1f", common, len(a), len(b), exp, limit))
		}
		t.Logf("random ports: %d and %d, %d in common (expectation %.2f)", len(a), len(b), common, exp)
	}
	return v
}

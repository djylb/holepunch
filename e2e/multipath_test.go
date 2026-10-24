package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/nattest"
)

// The cells of multiple confirmed paths: two clients
// allowed two paths each, on pairs where two paths carry the peer's packets
// in the first round — one per family behind dual-stack NATs, or a LAN and
// a public path through one hairpinning NAT. Every run must hand over both
// paths on both sides, the same ones, each carrying datagrams afterwards.

// handedSockets is how many distinct sockets a Session holds: the primary
// path's and those of the extra paths that do not share it.
func handedSockets(s *holepunch.Session) int {
	return len(s.PacketConns())
}

// twoPaths sets both clients to two paths.
func twoPaths(s *sessionSpec, _ *world, _ [2]*side) { s.maxPaths = 2 }

// multipathCells are the multipath cells.
func multipathCells() []*cell {
	dual := func(w *world) *side { return w.behind([]nattest.NATConfig{withV6(profPRC(), nattest.APDF)}) }
	return []*cell{
		{name: "multipath/PRC+FW6-PRC+FW6", group: "multipath", class: classMust, world: dualStack,
			build: pair(dual, dual), session: twoPaths, check: checkTwoPaths},
		{name: "multipath/PRC-hairpin-true", group: "multipath", class: classMust, session: twoPaths, check: checkTwoPaths,
			build: func(w *world) [2]*side {
				c := profPRC()
				c.Hairpin = true
				a := w.behind([]nattest.NATConfig{c})
				return [2]*side{a, w.on(a.nats)}
			}},
	}
}

// checkTwoPaths wants two paths on both sides, the same ones seen from
// either end (family and kind), reported to the coordinator, and a datagram
// through the extra path each way after the handover.
func checkTwoPaths(cr *cellRun) error {
	if !cr.m.OK {
		return errNotSucceeded
	}
	r := cr.r
	var paths [2][]holepunch.Path
	for i := range 2 {
		res := r.out[i].sess.Result()
		paths[i] = append([]holepunch.Path{res.Path}, res.ExtraPaths...)
		if len(paths[i]) != 2 {
			return fmt.Errorf("%s: %d paths %+v, want 2", roles[i], len(paths[i]), paths[i])
		}
		if !r.resOK || r.res.Winner == nil || len(r.res.Winner.ExtraPaths[i]) != 1 {
			return fmt.Errorf("%s: the coordinator's result does not report the extra path", roles[i])
		}
	}
	for k := range 2 {
		if paths[0][k].Family != paths[1][k].Family || paths[0][k].Kind != paths[1][k].Kind {
			return fmt.Errorf("path %d: %s/%s and %s/%s", k, paths[0][k].Family, paths[0][k].Kind, paths[1][k].Family, paths[1][k].Kind)
		}
	}
	if paths[0][0].Family == paths[0][1].Family && paths[0][0].Kind == paths[0][1].Kind {
		return fmt.Errorf("duplicate paths %+v", paths[0])
	}
	for from := range 2 {
		to := 1 - from
		src, dst := r.out[from].extra[0], r.out[to].extra[0]
		if src == nil {
			src = r.out[from].handed
		}
		if dst == nil {
			dst = r.out[to].handed
		}
		if err := datagramOver(src, dst, paths[from][1]); err != nil {
			return fmt.Errorf("%s → %s over the extra path: %w", roles[from], roles[to], err)
		}
	}
	return nil
}

// datagramOver sends datagrams over path p until one arrives on dst.
func datagramOver(src, dst nattest.Conn, p holepunch.Path) error {
	d, ok := dst.(interface{ SetReadDeadline(time.Time) error })
	if !ok {
		return fmt.Errorf("no read deadline on %T", dst)
	}
	msg := []byte("e2e-extra-path " + p.LocalAddr.String())
	buf := make([]byte, 2048)
	defer func() { _ = d.SetReadDeadline(time.Time{}) }()
	for range 10 {
		if _, err := src.WriteToUDPAddrPort(msg, p.RemoteAddr); err != nil {
			return err
		}
		_ = d.SetReadDeadline(time.Now().Add(scaled(100 * time.Millisecond)))
		for {
			n, _, err := dst.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			if string(buf[:n]) == string(msg) {
				return nil
			}
		}
	}
	return fmt.Errorf("no datagram to %v", p.RemoteAddr)
}

// multipathRuns is how many runs TestMultiPath makes of each cell.
const multipathRuns = 5

// TestMultiPath runs the multipath cells: every run connects with both
// paths, without a violation of the per-run invariants.
func TestMultiPath(t *testing.T) {
	var cs []*cell
	for _, c := range multipathCells() {
		if suite().selected(c.name) {
			cs = append(cs, c)
		}
	}
	if len(cs) == 0 {
		t.Skip("no multipath cell selected")
	}
	t.Run("cells", func(t *testing.T) {
		for _, c := range cs {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				release := acquireSlot()
				defer release()
				for i := range multipathRuns {
					seed := cellSeed(c.name, i)
					if _, v := runOnce(t, c, seed, ablation.Set{}, false); len(v) > 0 {
						t.Errorf("seed %d: %v", seed, v)
					}
				}
			})
		}
	})
	goroutines.VerifyNone(t)
}

package holepunch

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// freshPlan aims the initiator (behind a port-restricted cone) at four
// fresh sockets of the responder, whose NAT keeps a fresh socket's port for
// its first mapping; the responder's fresh sockets aim at the initiator's
// verified endpoint.
func freshPlan(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
	peer := views[1-roleIndex(r)].Families[0].Endpoints[0].Addr
	side := protocol.FamilySide{Family: protocol.FamilyUDP4, Role: protocol.SideBoth, Sockets: 1, MaxPackets: 12,
		MaxPPS: 80, MaxNewPerSec: 100, MaxDistinctPorts: 4}
	if r == protocol.RoleInitiator {
		side.Stages = []protocol.Stage{{Kind: protocol.StageFreshPeer, IP: peer.Addr(), Count: 4, Repeats: 3}}
	} else {
		side.Stages = []protocol.Stage{{Kind: protocol.StageFresh, Targets: []netip.AddrPort{peer}, Count: 4, Repeats: 3}}
	}
	return protocol.RoundPlan{Round: uint8(k), Variant: "test_fresh", Budget: protocol.BudgetBalanced, WindowMs: 1500, Seed: uint32(k),
		Sides: []protocol.FamilySide{side}}
}

// failFresh refuses the first n binds of fresh sockets, as a port taken on
// the host would.
type failFresh struct {
	Network
	mu sync.Mutex
	n  int
}

func (f *failFresh) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	f.mu.Lock()
	refuse := purpose == PurposeFresh && f.n > 0
	if refuse {
		f.n--
	}
	f.mu.Unlock()
	if refuse {
		return nil, syscall.EADDRINUSE
	}
	return f.Network.ListenPacket(ctx, network, laddr, purpose)
}

// TestFreshSockets: the responder binds its fresh sockets at the ports both
// sides draw, the initiator aims at exactly those, and the pair connects in
// the first round; a fresh socket it cannot bind is reported in
// round_result.bind_failed, and the fresh sockets that did not win are
// closed when the round ends.
func TestFreshSockets(t *testing.T) {
	t.Parallel()
	for _, failures := range []int{0, 1} {
		w := newWorld(t)
		ps := &pairScript{w: w, timeouts: testTimeouts(), round: freshPlan}
		var fail *failFresh
		pr := runPair(t, w, [2]*nattest.NATConfig{prc(), natCfg(nattest.SymmetricPreserveRandom())}, ps, func(i int, o *Options) {
			if i == 1 {
				fail = &failFresh{Network: o.Network, n: failures}
				o.Network = fail
			}
		})
		wantSuccess(t, pr)
		st := pr.hosts[1].Stats()
		if st.SocketsByPurpose[PurposeFresh] != uint64(4-failures) {
			t.Fatalf("%d failures: fresh sockets %v", failures, st.SocketsByPurpose)
		}
		res := pr.res[1].sess.Result()
		if res.Rounds != 1 || res.Path.LocalAddr.Port() < 10000 {
			t.Fatalf("%d failures: won on %v after %d rounds", failures, res.Path.LocalAddr, res.Rounds)
		}
		if n := pr.hosts[1].OpenSockets(); n != 1 {
			t.Fatalf("%d failures: %d sockets open beside the winner's", failures, n-1)
		}
		if rr := ps.rounds[1]; len(rr) == 0 || int(rr[0].Families[0].BindFailed) != failures {
			t.Fatalf("%d failures: round results %+v", failures, rr)
		}
		pr.closeAll()
		if n := pr.hosts[1].OpenSockets(); n != 0 {
			t.Fatalf("%d sockets open after Close", n)
		}
	}
}

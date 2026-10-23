package holepunch

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// The Background session mode on the client.

// TestAcceptedMode: the client runs Background only when the server
// offered it and the caller accepts it.
func TestAcceptedMode(t *testing.T) {
	bg := protocol.ModeBackground
	for _, c := range []struct {
		offer  protocol.SessionMode
		accept bool
		want   protocol.SessionMode
	}{
		{bg, true, bg}, {bg, false, ""}, {"", true, ""}, {protocol.ModeInteractive, true, ""},
	} {
		if got := acceptedMode(c.offer, c.accept); got != c.want {
			t.Errorf("offer %q accept %v: %q, want %q", c.offer, c.accept, got, c.want)
		}
	}
	rt := newTestRuntime(t, nil, nil)
	rt.summary.Plan.Advice = protocol.AdviceBackgroundViable
	if e := rt.newError(fail(protocol.ReasonCandidateTimeout, "", nil), protocol.PhasePunching, nil); e.Advice != protocol.AdviceBackgroundViable {
		t.Fatalf("advice %q", e.Advice)
	}
}

// pacedPlan has the initiator open its sockets beyond the primary at 50 a
// second, each sending to the responder's endpoint, in a background-class
// round; the responder only answers.
func pacedPlan(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
	side := protocol.FamilySide{Family: protocol.FamilyUDP4, Role: protocol.SideReplyOnly, Sockets: 1, Stages: []protocol.Stage{{Kind: protocol.StageReplyOnly}}}
	if r == protocol.RoleInitiator {
		side = protocol.FamilySide{Family: protocol.FamilyUDP4, Role: protocol.SideBoth, Sockets: 12, OpenPerSec: 50, MaxPackets: 36,
			MaxPPS: 64, MaxNewPerSec: 25, MaxDistinctPorts: 1,
			Stages: []protocol.Stage{{Kind: protocol.StageDirect, Targets: []netip.AddrPort{peerAddr(r, views)}, Repeats: 3}}}
	}
	return protocol.RoundPlan{Round: uint8(k), Variant: "test_paced", Budget: protocol.BudgetBackground, WindowMs: 1000, Seed: uint32(k), Final: true,
		Sides: []protocol.FamilySide{side}}
}

// failBirthday refuses every bind of a paced (birthday-purpose) socket.
type failBirthday struct{ Network }

func (f failBirthday) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	if purpose == PurposeBirthday {
		return nil, syscall.EADDRINUSE
	}
	return f.Network.ListenPacket(ctx, network, laddr, purpose)
}

// countBinds counts the binds of paced sockets and when they happen.
type countBinds struct {
	Network
	mu sync.Mutex
	at []time.Time
}

func (c *countBinds) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	if purpose == PurposeBirthday {
		c.mu.Lock()
		c.at = append(c.at, time.Now())
		c.mu.Unlock()
	}
	return c.Network.ListenPacket(ctx, network, laddr, purpose)
}

// TestPacedSockets: a side with OpenPerSec opens its sockets beyond the
// primary over the round, at most that many a second, and closes them when
// the round ends; a run of bind failures in a background round halts it,
// reported in round_result.
func TestPacedSockets(t *testing.T) {
	t.Parallel()
	to := testTimeouts()
	to.MaxRounds = 1
	// The responder filters the initiator's packets (port-restricted, and
	// it never sends): the round runs its whole window.
	w := newWorld(t)
	var goAt time.Time
	ps := &pairScript{w: w, timeouts: to, round: pacedPlan, beforeGo: func(int) { goAt = time.Now() }}
	var binds *countBinds
	pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(i int, o *Options) {
		if i == 0 {
			binds = &countBinds{Network: o.Network}
			o.Network = binds
		}
	})
	pr.closeAll()
	binds.mu.Lock()
	at := binds.at
	binds.mu.Unlock()
	if len(at) != 11 {
		t.Fatalf("%d paced sockets bound, want 11", len(at))
	}
	// Slot j opens j/50 s after the round fires, or later when the sender
	// runs late; then the slots after it catch up, so the span from the
	// first bind to the last says nothing. The round fires after the go
	// was written, so the last slot cannot open within 220 ms of it.
	if after := at[len(at)-1].Sub(goAt); after < 220*time.Millisecond {
		t.Fatalf("last of 11 paced sockets bound %v after the go: not paced at 50 a second", after)
	}
	if rr := ps.rounds[0]; len(rr) == 0 || rr[0].Families[0].Halted || rr[0].Families[0].BindFailed != 0 {
		t.Fatalf("round results %+v", rr)
	}
	if n := pr.hosts[0].OpenSockets(); n != 0 {
		t.Fatalf("%d sockets open after the session", n)
	}

	w = newWorld(t)
	ps = &pairScript{w: w, timeouts: to, round: pacedPlan}
	pr = runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(i int, o *Options) {
		if i == 0 {
			o.Network = failBirthday{o.Network}
		}
	})
	pr.closeAll()
	f := ps.rounds[0][0].Families[0]
	if !f.Halted || int(f.BindFailed) != haltBindRun {
		t.Fatalf("bind failures: halted %v, bind_failed %d, want true, %d", f.Halted, f.BindFailed, haltBindRun)
	}
}

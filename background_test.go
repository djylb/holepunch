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
// offered it and the caller asked for it; an unknown mode is refused.
func TestAcceptedMode(t *testing.T) {
	bg := protocol.ModeBackground
	for _, c := range []struct{ offer, local, want protocol.SessionMode }{
		{bg, bg, bg}, {bg, "", ""}, {"", bg, ""}, {bg, protocol.ModeInteractive, ""},
	} {
		if got := acceptedMode(c.offer, c.local); got != c.want {
			t.Errorf("offer %q local %q: %q, want %q", c.offer, c.local, got, c.want)
		}
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if e := validateOptions(a, &Options{ControlSecurity: protocol.ControlSecurityDeclared, Mode: "lazy"}); e == nil || e.Detail != "mode" {
		t.Fatalf("unknown mode: %v", e)
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
		peer := views[1].Families[0].Endpoints[0].Addr
		side = protocol.FamilySide{Family: protocol.FamilyUDP4, Role: protocol.SideBoth, Sockets: 12, OpenPerSec: 50, MaxPackets: 36,
			MaxPPS: 64, MaxNewPerSec: 25, MaxDistinctPorts: 1, Stages: []protocol.Stage{{Kind: protocol.StageDirect, Targets: []netip.AddrPort{peer}, Repeats: 3}}}
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
	ps := &pairScript{w: w, timeouts: to, round: pacedPlan}
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
	if span := at[len(at)-1].Sub(at[0]); span < 150*time.Millisecond {
		t.Fatalf("11 paced sockets bound within %v: not paced at 50 a second", span)
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

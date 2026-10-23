package holepunch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// portRun.then follows the definition the limit is measured with: a repeat
// neither extends nor breaks a run, a reversal starts a run of two, a pause
// of 10 s starts a new run.
func TestPortRunThen(t *testing.T) {
	t0 := time.Unix(1000, 0)
	var r portRun
	for i, c := range []struct {
		port uint16
		at   time.Duration
		n    int
	}{
		{100, 0, 1}, {101, 0, 2}, {101, 0, 2}, {102, 0, 3}, {103, 0, 4}, // repeat neutral
		{102, 0, 2}, {101, 0, 3}, // reversal
		{50, 0, 1}, {51, 0, 2},
		{52, 9 * time.Second, 3},  // within 10 s of the last packet
		{53, 20 * time.Second, 1}, // pause: a new run
		{53, 31 * time.Second, 1},
	} {
		r = r.then(c.port, t0.Add(c.at))
		if r.n != c.n {
			t.Fatalf("step %d (port %d): run %d, want %d", i, c.port, r.n, c.n)
		}
	}
	// Without pauses, the longest run equals plan.MaxConsecutiveRun of the
	// sequence with repeats collapsed.
	rng := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		var seq, col []uint16
		var r portRun
		best := 0
		for range 1 + rng.IntN(24) {
			p := uint16(1000 + rng.IntN(6))
			seq = append(seq, p)
			if len(col) == 0 || col[len(col)-1] != p {
				col = append(col, p)
			}
			r = r.then(p, t0)
			best = max(best, r.n)
		}
		if want := plan.MaxConsecutiveRun(col); best != want {
			t.Fatalf("%v: run %d, want %d", seq, best, want)
		}
	}
}

// guardRig is a gate rig with an observer, a Direct target of the round and
// helpers for every class.
type guardRig struct {
	*gateRig
}

// newGuardRig has rates high enough that no send of a test waits for
// tokens on the fake clock.
func newGuardRig(t *testing.T) *guardRig {
	b, side := bigBudget(), bigSide()
	b.MaxPPS, side.MaxPPS = 60000, 60000
	side.Stages = []protocol.Stage{{Kind: protocol.StageDirect, Targets: []netip.AddrPort{netipAP("198.51.100.1", 9100)}}}
	g := newGateRig(t, b, side, 0)
	g.rt.observers = map[netip.AddrPort]bool{}
	for p := 3478; p < 3482; p++ {
		g.rt.observers[netipAP("198.51.100.1", p)] = true
	}
	return &guardRig{g}
}

func (g *guardRig) to(port int) string { return netipAP("198.51.100.1", port).String() }

func (g *guardRig) answer(class sendClass, port int) error {
	to := netipAP("198.51.100.1", port)
	h, stage := udpwire.Header{Type: udpwire.TNominate, Aux: 1, Cand: udpwire.NoCand}, txHandshake
	var tl *udpwire.TLVs
	if class == classReply {
		h, stage, tl = udpwire.Header{Type: udpwire.TSuccess, EchoSeq: 1}, txReply, &udpwire.TLVs{Observed: to}
	}
	return g.rt.sender.Send(context.Background(), g.sock, to, &h, tl, sendOpt{class: class, stage: stage})
}

func (g *guardRig) raw(port int) error {
	return g.rt.sender.SendRaw(context.Background(), g.sock, netipAP("198.51.100.1", port), make([]byte, udpwire.MinProbePacket))
}

func (g *guardRig) want(step string, err error, ok bool) {
	g.t.Helper()
	switch {
	case ok && err != nil:
		g.t.Fatalf("%s: %v", step, err)
	case !ok && !errors.Is(err, errRun):
		g.t.Fatalf("%s: %v, want errRun", step, err)
	}
}

// What the session opens may bring a run to two; a third port is held
// back without spending anything, and leaves once another port broke the
// run. Repeats are free.
func TestRunGuardOpeners(t *testing.T) {
	g := newGuardRig(t)
	g.want("9000", g.punch(g.to(9000)), true)
	g.want("9001", g.punch(g.to(9001)), true)
	g.want("9001 again", g.punch(g.to(9001)), true)
	sent, initiated := g.m.sent, g.rt.sender.initiated
	g.want("9002", g.punch(g.to(9002)), false)
	if g.m.sent != sent || g.rt.sender.initiated != initiated || len(g.rt.sender.sentPorts(netip.MustParseAddr("198.51.100.1"))) != 2 {
		t.Fatal("a held-back packet was counted")
	}
	g.want("9000 (reversal)", g.punch(g.to(9000)), true)
	g.want("8999", g.punch(g.to(8999)), false)
	g.want("9020", g.punch(g.to(9020)), true)
	g.want("9002 after the break", g.punch(g.to(9002)), true)
	g.want("other IP", g.punch("198.51.100.2:9003"), true)
	if got := g.rt.fam(protocol.FamilyUDP4).cnt.tx.Load(); got != 7 {
		t.Fatalf("tx %d", got)
	}
	// a pause of 10 s starts a new run
	g.want("9003", g.punch(g.to(9003)), true)
	g.want("9004", g.punch(g.to(9004)), false)
	g.clk.Advance(portWindow)
	g.want("9004 after a pause", g.punch(g.to(9004)), true)
}

// An opener's run of two may not point at a known port — a Direct target
// of the round or an address that answered — unless its own port is known.
func TestRunGuardKnownPorts(t *testing.T) {
	g := newGuardRig(t)
	g.want("9098", g.punch(g.to(9098)), true)
	g.want("9099 towards the Direct target", g.punch(g.to(9099)), false)
	g.want("9100", g.punch(g.to(9100)), true)
	g.want("9101", g.punch(g.to(9101)), true) // its own continuation 9102 is unknown
	g.rt.punch.notePeer(protocol.FamilyUDP4, g.sock.local, netipAP("198.51.100.1", 9200), false)
	g.rt.punch.notePeer(protocol.FamilyUDP4, g.sock.local, netipAP("198.51.100.1", 9301), false)
	g.want("9202", g.punch(g.to(9202)), true)
	g.want("9201 towards an answered address", g.punch(g.to(9201)), false)
	g.want("9300", g.punch(g.to(9300)), true)
	g.want("9301, known itself", g.punch(g.to(9301)), true)
	g.want("9302", g.punch(g.to(9302)), false)
	// the edges of the port range point nowhere
	g.want("65534", g.punch(g.to(65534)), true)
	g.want("65535", g.punch(g.to(65535)), true)
}

// Answers may bring a run to three, never to four; observers are recorded
// but never held back; the hairpin probe opens like a punch.
func TestRunGuardAnswersAndProbes(t *testing.T) {
	g := newGuardRig(t)
	g.want("punch 9000", g.punch(g.to(9000)), true)
	g.want("punch 9001", g.punch(g.to(9001)), true)
	g.want("reply 9002", g.answer(classReply, 9002), true)
	g.want("handshake 9003", g.answer(classHandshake, 9003), false)
	g.want("reply 9003", g.answer(classReply, 9003), false)
	g.want("handshake 9002 (repeat)", g.answer(classHandshake, 9002), true)
	g.clk.Advance(30 * time.Millisecond)
	g.want("reply 9001 (reversal)", g.answer(classReply, 9001), true)
	g.want("reply 9000", g.answer(classReply, 9000), true)
	g.want("handshake 8999", g.answer(classHandshake, 8999), false)

	for p := 3478; p < 3482; p++ {
		g.want("observer", g.raw(p), true)
	}
	g.want("punch after the observers", g.punch(g.to(3482)), false)
	g.want("hairpin 7000", g.raw(7000), true)
	g.want("hairpin 7001", g.raw(7001), true)
	g.want("hairpin 7002", g.raw(7002), false)
	if got := g.rt.fam(protocol.FamilyUDP4).cnt.byStage[txProbe].Load(); got != 6 {
		t.Fatalf("probes %d", got)
	}
}

// The lane orders concurrent senders: whatever the goroutines race for, the
// sequence that leaves the host towards one IP keeps the limit (measured by
// the simulator, independently of the guard's own bookkeeping), and a send
// waiting for its tokens holds the lane without blocking the cancellation.
func TestRunGuardConcurrentSenders(t *testing.T) {
	g := newGuardRig(t)
	host := g.rt.netw.(*nattest.Host)
	var wg sync.WaitGroup
	for i := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(i), 7))
			for range 40 {
				port := 9000 + rng.IntN(6)
				switch i % 3 {
				case 0:
					_ = g.punch(g.to(port))
				case 1:
					_ = g.answer(classReply, port)
				default:
					_ = g.answer(classHandshake, port)
				}
			}
		}()
	}
	wg.Wait()
	st := host.Stats()
	c := g.rt.fam(protocol.FamilyUDP4).cnt.snapshot()
	if c.TxByStage["direct"] == 0 || c.TxByStage["reply"] == 0 || c.TxByStage["handshake"] == 0 || st.MaxConsecutiveRun > maxAnswerRun {
		t.Fatalf("sent %v, longest run %d", c.TxByStage, st.MaxConsecutiveRun)
	}
}

// The limit holds on the sequence that actually leaves each host, whatever
// the plan, the NATs and the timing. The plans crowd
// one peer IP with neighbouring ports from every source a round has —
// Direct targets next to the peer's endpoint, a predict spray around it, a
// random stage over a small pool around it, several sockets, low TTL —
// and the script pushes peer_targets next to it and a port window over it
// with every go; replies, follow-ups and the handshake interleave as the
// NATs and links let them. Half the sessions run the DefaultPlanner's
// ladder instead, whose predict stages spray around the Direct target's
// port (the e2e v4/FC-PUB failure). The simulator measures the sequence
// independently of the guard.
func TestSendSequenceKeepsRunLimit(t *testing.T) {
	t.Parallel()
	profiles := []func() nattest.NATConfig{
		nattest.PublicOpen, nattest.FullCone, nattest.RestrictedCone, nattest.PortRestricted,
		func() nattest.NATConfig { return nattest.SymmetricSeq(1) },
	}
	for seed := range 12 {
		t.Run(strconv.Itoa(seed), func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewPCG(uint64(seed), 0x72756e73))
			w := newWorld(t, nattest.WithSeed(int64(seed)),
				nattest.WithCoreLink(nattest.LinkConfig{Delay: time.Duration(rng.IntN(30)) * time.Millisecond}))
			var cfg [2]*nattest.NATConfig
			for i := range cfg {
				c := profiles[rng.IntN(len(profiles))]()
				c.Uplink = nattest.LinkConfig{Delay: time.Duration(5+rng.IntN(16)) * time.Millisecond}
				cfg[i] = &c
			}
			ps := &pairScript{w: w, timeouts: testTimeouts()}
			if seed%2 == 0 {
				var peers [2]netip.AddrPort
				ps.round = func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
					p := crowdedPlan(rng, k, r, views)
					peers[roleIndex(r)] = p.Sides[0].Stages[0].Targets[0]
					return p
				}
				ps.assistHook = func(k, i int) []protocol.Assist { return crowdingTargets(rng, k, peers[i]) }
			} else {
				ps.round = func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
					return ps.plannerPlan(k, r, views, pairFacts(views))
				}
			}
			pr := runPair(t, w, cfg, ps, nil)
			defer pr.closeAll()
			for i, h := range pr.hosts {
				st := h.Stats()
				if st.PacketsSent == 0 {
					t.Fatalf("client %d sent nothing", i)
				}
				if st.MaxConsecutiveRun > maxAnswerRun {
					t.Errorf("client %d (%s): run of %d consecutive ports; sent %v",
						i, cfg[i].Name, st.MaxConsecutiveRun, sentPorts(t, w.n, h))
				}
			}
		})
	}
}

// crowdedPlan is round k of role r: one side of the peer's first verified
// endpoint P, with Direct targets P and some of P±1, P±2, a predict stage
// anchored at P, now and then a random stage over P±24, and 1–3 sockets.
func crowdedPlan(rng *rand.Rand, k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
	peer := peerAddr(r, views)
	ip, p := peer.Addr(), int(peer.Port())
	near := func(d int) netip.AddrPort { return netip.AddrPortFrom(ip, uint16(min(max(p+d, 1024), 65535))) }
	targets := []netip.AddrPort{peer}
	for _, d := range []int{-2, -1, 1, 2} {
		if rng.IntN(2) == 0 {
			targets = append(targets, near(d))
		}
	}
	rng.Shuffle(len(targets)-1, func(i, j int) { targets[i+1], targets[j+1] = targets[j+1], targets[i+1] })
	var ttl uint8
	if rng.IntN(3) == 0 {
		ttl = 4
	}
	stages := []protocol.Stage{
		{Kind: protocol.StageDirect, Targets: targets, Repeats: uint8(2 + rng.IntN(4)), TTL: ttl},
		{Kind: protocol.StagePredict, IP: ip, Anchor: uint16(p), Steps: []int16{[]int16{1, -1, 2}[rng.IntN(3)]},
			Span: uint16(6 + rng.IntN(16)), AtMs: uint16(rng.IntN(40))},
	}
	if rng.IntN(2) == 0 {
		stages = append(stages, protocol.Stage{Kind: protocol.StageRandom, IP: ip, Lo: near(-24).Port(), Hi: near(24).Port(),
			Count: uint16(8 + rng.IntN(24)), AtMs: uint16(rng.IntN(60))})
	}
	return protocol.RoundPlan{Round: uint8(k), Variant: "test_crowded", Budget: protocol.BudgetBalanced, WindowMs: 1000, Seed: rng.Uint32(),
		Sides: []protocol.FamilySide{{Family: protocol.FamilyUDP4, Role: protocol.SideBoth, Sockets: uint16(1 + rng.IntN(3)),
			MaxPackets: 400, MaxPPS: uint16(200 + rng.IntN(400)), MaxNewPerSec: 200, MaxDistinctPorts: 64, Stages: stages}}}
}

// crowdingTargets is the peer_targets assist of round k next to the peer
// endpoint P a client punches: targets P±3 and, every other round, the
// window P-4..P+4.
func crowdingTargets(rng *rand.Rand, k int, peer netip.AddrPort) []protocol.Assist {
	if !peer.IsValid() {
		return nil
	}
	ip, p := peer.Addr(), int(peer.Port())
	a := protocol.Assist{Kind: protocol.AssistPeerTargets, Round: uint8(k), Family: protocol.FamilyUDP4, From: protocol.RoleServer,
		Source: protocol.TargetsInject, Targets: []netip.AddrPort{netip.AddrPortFrom(ip, uint16(p+3)), netip.AddrPortFrom(ip, uint16(p-3))}}
	if k%2 == 1 || rng.IntN(2) == 0 {
		a.Window = &protocol.PortWindow{IP: ip, Lo: uint16(p - 4), Hi: uint16(p + 4)}
	}
	return []protocol.Assist{a}
}

// sentPorts is the destination ports host h sent to, per destination IP,
// in the order the simulator saw the writes (its event log).
func sentPorts(t *testing.T, n *nattest.Network, h *nattest.Host) map[netip.Addr][]uint16 {
	t.Helper()
	var buf bytes.Buffer
	if err := n.Dump(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Events []struct {
			Kind     string
			Src, Dst netip.AddrPort
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	own := map[netip.Addr]bool{}
	for _, a := range h.Addrs() {
		own[a] = true
	}
	out := map[netip.Addr][]uint16{}
	for _, e := range doc.Events {
		if e.Kind == "send" && own[e.Src.Addr()] {
			out[e.Dst.Addr()] = append(out[e.Dst.Addr()], e.Dst.Port())
		}
	}
	return out
}

// The seams of a round, deterministically: two Direct targets P, P+1 are
// due at the fire instant together with two one-port random stages P+2 and
// P+3, which the round sends in stage order — P, P+1, P+2, P+3 without the
// guard. With it, P+2 waits behind P+3, and behind the next Direct repeat to
// P or P+1 too (after P+3 its run of two would point at the Direct target
// P+1), and leaves right after whichever packet next breaks the run. A held
// packet needs such a packet after it; a second Direct stage towards Q, far
// from P, provides the last one (its repeats run longest), so nothing is
// lost however late the round goroutine runs.
func TestRunGuardRoundSeams(t *testing.T) {
	t.Parallel()
	peer := netip.MustParseAddrPort(silentPeer)
	at := func(d int) netip.AddrPort { return netip.AddrPortFrom(peer.Addr(), peer.Port()+uint16(d)) }
	one := func(d int) protocol.Stage {
		return protocol.Stage{Kind: protocol.StageRandom, IP: peer.Addr(), Lo: at(d).Port(), Hi: at(d).Port(), Count: 1}
	}
	so, _, rr := soloRound(t, nil, nil, func(r *protocol.RoundPlan) {
		r.Sides[0].Stages = []protocol.Stage{
			{Kind: protocol.StageDirect, Targets: []netip.AddrPort{at(0), at(1)}, Repeats: 2}, one(2), one(3),
			{Kind: protocol.StageDirect, Targets: []netip.AddrPort{at(100)}, Repeats: 4, AtMs: 30}}
	}, nil)
	if f := rr.Families[0]; f.Sent != 10 || f.BudgetHit {
		t.Fatalf("family %+v", f)
	}
	sent := sentPorts(t, so.w.n, so.host)[peer.Addr()]
	if st := so.host.Stats(); st.MaxConsecutiveRun > maxAnswerRun {
		t.Fatalf("run of %d: %v", st.MaxConsecutiveRun, sent)
	}
	got := map[uint16]int{}
	for _, p := range sent {
		got[p]++
	}
	for d, n := range map[int]int{0: 2, 1: 2, 2: 1, 3: 1, 100: 4} {
		if got[at(d).Port()] != n {
			t.Fatalf("sent %v", sent)
		}
	}
}

// A send waiting for a busy lane gives up when its context ends.
func TestLaneAcquireCanceled(t *testing.T) {
	l := newLane()
	if err := l.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire on a busy lane with a canceled context: %v", err)
	}
	l.release()
	if err := l.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
}

package holepunch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/internal/nat"
	engine "github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// testTimeouts are short protocol timeouts that keep every wait of a test
// session within a few seconds.
func testTimeouts() protocol.Timeouts {
	return protocol.Timeouts{
		ProbeTimeoutMs: 600, SummaryWaitMs: 3000, GoWaitMs: 1500, HandshakeTimeoutMs: 4000,
		HandoverTimeoutMs: 1500, TransportTimeoutMs: 5000, MaxRounds: 3,
	}
}

// world is a simulated Internet with a natprobe observer on a public host.
type world struct {
	t      *testing.T
	n      *nattest.Network
	server *nattest.Host
	reg    *natprobe.Registry
	srv    *natprobe.Server
}

func newWorld(t *testing.T, opts ...nattest.Option) *world {
	t.Helper()
	n := nattest.NewNetwork(opts...)
	server := n.PublicHost(netip.IPv4Unspecified())
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	srv, err := natprobe.NewServer(natprobe.ServerConfig{
		Registry: reg, Groups: []natprobe.ObserverGroup{{Bind: server.Addrs()[0]}}, Listen: server.Listen,
		SourceRate: natprobe.Rate{PerSec: -1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, n: n, server: server, reg: reg, srv: srv}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = n.Close()
	})
	return w
}

// host returns a client host behind a NAT of cfg, or a public host when
// cfg is nil.
func (w *world) host(cfg *nattest.NATConfig) *nattest.Host {
	if cfg == nil {
		return w.n.PublicHost(netip.IPv4Unspecified())
	}
	return w.n.NAT(*cfg).Host()
}

// pipe connects a client host to the server host.
func (w *world) pipe(h *nattest.Host, delay time.Duration) (client, server *nattest.PipeConn) {
	return w.n.Pipe(nattest.PipeConfig{A: h, B: w.server, DelayAB: delay, DelayBA: delay})
}

// clientOpts are the options of a test client on host h.
func clientOpts(h *nattest.Host) Options {
	return Options{ControlSecurity: protocol.ControlSecurityInsecureForTesting, Network: h, TransportMode: "quic"}
}

// srvLink is the server end of one control link, driven by a test script.
type srvLink struct {
	t    *testing.T
	conn *controlwire.Conn

	frames chan controlwire.Frame // closed when the link ends

	done     chan struct{} // closed by close: a reader nobody drains stops
	doneOnce sync.Once
}

func newSrvLink(t *testing.T, nc net.Conn) *srvLink {
	t.Helper()
	l := &srvLink{t: t, frames: make(chan controlwire.Frame, 256), done: make(chan struct{})}
	c, err := controlwire.NewConn(nc, controlwire.ConnOptions{Side: controlwire.SideServer, WriteTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	l.conn = c
	go func() {
		defer close(l.frames)
		for {
			f, err := c.ReadFrame(context.Background())
			if err != nil {
				return
			}
			select {
			case l.frames <- f:
			default: // full: wait for a reader, unless the link was closed
				select {
				case l.frames <- f:
				case <-l.done:
					return
				}
			}
		}
	}()
	return l
}

func (l *srvLink) send(m protocol.Message) {
	l.t.Helper()
	fr, err := msgframe.Encode(m)
	if err != nil {
		l.t.Errorf("marshal %T: %v", m, err)
		return
	}
	_ = l.conn.Send(fr)
}

// next returns the next frame of one of the given types, skipping pong,
// progress and others; ok is false when the link ended or d passed.
func (l *srvLink) next(d time.Duration, types ...protocol.MessageType) (protocol.Message, bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case f, ok := <-l.frames:
			if !ok {
				return nil, false
			}
			for _, want := range types {
				if protocol.MessageType(f.Type) == want {
					m, err := msgframe.Decode(f)
					if err != nil {
						l.t.Errorf("decode %v: %v", want, err)
						return nil, false
					}
					return m, true
				}
			}
		case <-t.C:
			return nil, false
		}
	}
}

func (l *srvLink) close() {
	l.doneOnce.Do(func() { close(l.done) })
	_ = l.conn.Close()
}

// session is the identity of one test session.
type session struct {
	sid   string
	token protocol.Token
	wire  protocol.WireSpec
	h     nat.ProbeHandle
}

func (w *world) newSession() *session {
	s := &session{sid: protocol.NewSessionID(), token: protocol.NewToken(), wire: protocol.NewWireSpec()}
	h, err := nat.RegisterProbe(w.reg, nat.Registration{SessionID: s.sid, Route: s.wire.RouteID, Token: s.token, TTL: time.Minute})
	if err != nil {
		w.t.Fatal(err)
	}
	s.h = h
	w.t.Cleanup(h.Close)
	return s
}

// startFor is the punch_start of role r.
func (w *world) startFor(s *session, r protocol.Role, to protocol.Timeouts, pol *protocol.Policy) protocol.PunchStart {
	return protocol.PunchStart{
		SessionID: s.sid, Role: r, Token: s.token, Wire: s.wire, Control: protocol.DefaultControlSpec(),
		Probe:    protocol.ProbeSpec{V: protocol.ProbeSpecVersion, Observers: w.srv.Observers(protocol.FamilyUDP4), ExtraReply: true},
		Timeouts: to, Policy: pol,
	}
}

// attachResult is what a client's Punch returned.
type attachResult struct {
	sess *Session
	err  error
	at   time.Time
}

// runClient starts Punch on its own goroutine.
func runClient(ctx context.Context, nc net.Conn, o Options) <-chan attachResult {
	ch := make(chan attachResult, 1)
	go func() {
		s, err := Punch(ctx, nc, o)
		ch <- attachResult{s, err, time.Now()}
	}()
	return ch
}

// pairScript plays the coordinator for two clients: probing, a summary
// with the DefaultPlanner's ladder, rounds, peer_seen relaying and the
// results. Fields alter its behaviour for failure tests.
type pairScript struct {
	w        *world
	timeouts protocol.Timeouts
	policy   *protocol.Policy
	// round overrides the planner: it returns the plan of role r in round k.
	round func(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan
	// noRelay drops peer_seen instead of relaying it.
	noRelay bool
	// stopAfterConfirm closes both links once a round_result{confirmed} arrived.
	stopAfterConfirm bool
	// resultWait, when set, bounds the wait for the punch_results once both
	// sides confirmed: a client that fails to write its result does not hold
	// the script until its deadline.
	resultWait time.Duration
	// mutateStart edits the punch_start of client i before it is sent.
	mutateStart func(i int, s *protocol.PunchStart)
	// assistHook returns assists sent to client i right after the go of round k.
	assistHook func(k, i int) []protocol.Assist
	// beforeGo runs right before the go of round k is written.
	beforeGo func(k int)
	// pair edits the pair facts and views of the summary.
	pair func(p *protocol.PairFacts, views *[2]protocol.PeerView, reports [2]protocol.ProbeReport)

	results  [2]*protocol.PunchResult
	rounds   [2][]protocol.RoundResult
	confirms int
	sess     *session // the session run registered with natprobe
}

func roleIndex(r protocol.Role) int {
	if r == protocol.RoleResponder {
		return 1
	}
	return 0
}

type linkEvent struct {
	idx int
	m   protocol.Message
	err error
}

// run drives one session over the two server ends (index 0 initiator).
func (ps *pairScript) run(ctx context.Context, ends [2]net.Conn) error {
	w := ps.w
	s := w.newSession()
	ps.sess = s
	roles := [2]protocol.Role{protocol.RoleInitiator, protocol.RoleResponder}
	var links [2]*srvLink
	defer func() {
		for i := len(links) - 1; i >= 0; i-- { // the reverse order of creation
			if links[i] != nil {
				links[i].close()
			}
		}
	}()
	for i := range links {
		links[i] = newSrvLink(w.t, ends[i])
		start := w.startFor(s, roles[i], ps.timeouts, ps.policy)
		if ps.mutateStart != nil {
			ps.mutateStart(i, &start)
		}
		links[i].send(start)
		links[i].send(protocol.Ping{Seq: 1})
	}
	var views [2]protocol.PeerView
	var reports [2]protocol.ProbeReport
	for i, l := range links {
		m, ok := l.next(10*time.Second, protocol.MsgProbeReport, protocol.MsgPunchResult)
		if !ok {
			return fmt.Errorf("no report from %s", roles[i])
		}
		rep, isRep := m.(*protocol.ProbeReport)
		if !isRep {
			pr := m.(*protocol.PunchResult)
			ps.results[i] = pr
			return fmt.Errorf("%s failed probing: %s", roles[i], pr.Reason)
		}
		reports[i] = *rep
		res, err := s.h.Merge(roles[i], *rep, nil, "", false)
		if err != nil {
			return err
		}
		views[i] = res.View
	}
	pair := pairFacts(views)
	if ps.pair != nil {
		ps.pair(&pair, &views, reports)
	}
	plans := [2]protocol.RoundPlan{ps.roundPlan(1, roles[0], views), ps.roundPlan(1, roles[1], views)}
	for i, l := range links {
		peer := views[1-i]
		l.send(protocol.ProbeSummary{
			SessionID: s.sid, Self: views[i], Peer: peer, Pair: pair,
			Transport: protocol.TransportPick{Mode: "quic", PeerData: reports[1-i].Transport.Data},
			Timeouts:  ps.timeouts,
			Plan: protocol.PlanSpec{ID: "p1", PairClass: "test", RoundsMax: ps.timeouts.MaxRounds,
				Budget: protocol.DefaultBudget(), Round1: plans[i]},
		})
	}
	for i, l := range links {
		if _, ok := l.next(10*time.Second, protocol.MsgPunchReady); !ok {
			return fmt.Errorf("no ready from %s", roles[i])
		}
	}
	events := make(chan linkEvent, 64)
	var wg sync.WaitGroup
	for i, l := range links {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				m, ok := l.next(time.Hour, protocol.MsgRoundResult, protocol.MsgPunchResult, protocol.MsgAssist)
				if !ok {
					events <- linkEvent{idx: i, err: errors.New("link ended")}
					return
				}
				events <- linkEvent{idx: i, m: m}
			}
		}()
	}
	defer func() {
		for _, l := range links {
			l.close()
		}
		go func() { wg.Wait(); close(events) }()
		for range events {
		}
	}()
	round := 1
	if ps.beforeGo != nil {
		ps.beforeGo(1)
	}
	for i, l := range links {
		l.send(protocol.PunchGo{SessionID: s.sid, Round: 1, DelayMs: 20, WindowMs: plans[i].WindowMs})
	}
	ps.sendAssists(links, s.sid, 1)
	got := [2]bool{}
	ended := [2]bool{}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	var results <-chan time.Time // armed by resultWait once both sides confirmed
	for !(ended[0] && ended[1]) {
		select {
		case ev := <-events:
			if ev.err != nil {
				ended[ev.idx] = true
				continue
			}
			switch m := ev.m.(type) {
			case *protocol.PunchResult:
				ps.results[ev.idx] = m
				ended[ev.idx] = true
				if !m.OK && !ended[1-ev.idx] {
					links[1-ev.idx].send(protocol.Abort{SessionID: s.sid, By: roles[ev.idx], Reason: m.Reason})
				}
			case *protocol.Assist:
				if !ps.noRelay {
					links[1-ev.idx].send(m.Relayed(roles[ev.idx]))
				}
			case *protocol.RoundResult:
				ps.rounds[ev.idx] = append(ps.rounds[ev.idx], *m)
				if m.Status == protocol.RoundConfirmed {
					ps.confirms++
					if ps.resultWait > 0 && ps.confirms == 2 {
						results = time.After(ps.resultWait)
					}
					if ps.stopAfterConfirm {
						links[0].close()
						links[1].close()
					}
					continue
				}
				if int(m.Round) != round {
					continue
				}
				got[ev.idx] = true
				if got[0] && got[1] && ps.confirms == 0 && round < int(ps.timeouts.MaxRounds) {
					round++
					got = [2]bool{}
					if ps.beforeGo != nil {
						ps.beforeGo(round)
					}
					for i, l := range links {
						p := ps.roundPlan(round, roles[i], views)
						l.send(protocol.PunchGo{SessionID: s.sid, Round: uint8(round), DelayMs: 20, WindowMs: p.WindowMs, Plan: &p})
					}
					ps.sendAssists(links, s.sid, round)
				}
			}
		case <-results:
			return nil
		case <-deadline.C:
			return errors.New("script deadline")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (ps *pairScript) sendAssists(links [2]*srvLink, sid string, k int) {
	if ps.assistHook == nil {
		return
	}
	for i, l := range links {
		for _, a := range ps.assistHook(k, i) {
			a.SessionID = sid
			l.send(a)
		}
	}
}

// pairFacts derives what a coordinator would: the shared family, the same
// public IP and, when the LAN addresses also share a /24, the same LAN.
func pairFacts(views [2]protocol.PeerView) protocol.PairFacts {
	f := protocol.FamilyUDP4
	pair := protocol.PairFacts{SharedFamilies: []protocol.Family{f}, SamePublicIP: map[protocol.Family]bool{}, LikelySameLAN: map[protocol.Family]bool{}}
	if len(views[0].Families) == 0 || len(views[1].Families) == 0 ||
		views[0].Families[0].Traits.PublicIP != views[1].Families[0].Traits.PublicIP {
		return pair
	}
	pair.SamePublicIP[f] = true
	for _, a := range views[0].Families[0].Endpoints {
		for _, b := range views[1].Families[0].Endpoints {
			if a.Source == protocol.EndpointLAN && b.Source == protocol.EndpointLAN {
				pa, _ := a.Addr.Addr().Prefix(24)
				if pa.Contains(b.Addr.Addr()) {
					pair.LikelySameLAN[f] = true
				}
			}
		}
	}
	return pair
}

// roundPlan is the plan of role r in round k: the override, or the
// DefaultPlanner's ladder for the two merged views.
func (ps *pairScript) roundPlan(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
	if ps.round != nil {
		return ps.round(k, r, views)
	}
	return ps.plannerPlan(k, r, views, protocol.PairFacts{SharedFamilies: []protocol.Family{protocol.FamilyUDP4}})
}

// plannerPlan is the DefaultPlanner's plan of role r in round k for the two
// merged views and the pair facts.
func (ps *pairScript) plannerPlan(k int, r protocol.Role, views [2]protocol.PeerView, pair protocol.PairFacts) protocol.RoundPlan {
	var pl engine.DefaultPlanner
	pol := protocol.Policy{Budget: protocol.DefaultBudget()}
	cls := pl.Classify(plan.ClassifyInput{Initiator: views[0], Responder: views[1], Policy: pol, Timeouts: ps.timeouts, Pair: pair})
	dec := pl.Round(plan.RoundInput{
		Round: k, Class: cls, Views: views, Pair: pair, Policy: pol, MaxRounds: int(ps.timeouts.MaxRounds),
		Remaining: 3 * time.Second, D: 100 * time.Millisecond, BudgetLeft: [2]int{3000, 3000},
		HandshakeMs: ps.timeouts.HandshakeTimeoutMs,
	})
	return protocol.RoundPlan{Round: uint8(k), Variant: dec.VariantName, Budget: dec.Budget,
		WindowMs: uint16(dec.Window / time.Millisecond), Seed: uint32(k * 7919), Sides: dec.Sides[roleIndex(r)]}
}

// directPlan is a plain direct round on the peer's verified endpoints.
func directPlan(k int, r protocol.Role, views [2]protocol.PeerView) protocol.RoundPlan {
	var targets []netip.AddrPort
	for _, f := range peerOf(r, views).Families {
		for _, e := range f.Endpoints {
			if e.Verified && len(targets) < 8 {
				targets = append(targets, e.Addr)
			}
		}
	}
	return protocol.RoundPlan{Round: uint8(k), Variant: "test_direct", Budget: protocol.BudgetLight, WindowMs: 1200, Seed: uint32(k),
		Sides: []protocol.FamilySide{{Family: protocol.FamilyUDP4, Role: protocol.SideBoth, Sockets: 1, MaxPackets: 60,
			MaxPPS: 80, MaxNewPerSec: 100, MaxDistinctPorts: 16,
			Stages: []protocol.Stage{{Kind: protocol.StageDirect, Targets: targets, Repeats: 5}}}}}
}

// pairRun is a whole two-client session in a world.
type pairRun struct {
	script  *pairScript
	res     [2]attachResult
	hosts   [2]*nattest.Host
	opts    [2]Options
	scriptE error
}

// runPair runs both clients, each behind its own NAT (nil: public), against
// the script and waits for everything.
func runPair(t *testing.T, w *world, cfg [2]*nattest.NATConfig, ps *pairScript, tweak func(i int, o *Options)) *pairRun {
	t.Helper()
	return runPairHosts(t, w, [2]*nattest.Host{w.host(cfg[0]), w.host(cfg[1])}, ps, tweak)
}

// runPairHosts runs both clients on the given hosts.
func runPairHosts(t *testing.T, w *world, hosts [2]*nattest.Host, ps *pairScript, tweak func(i int, o *Options)) *pairRun {
	t.Helper()
	pr := &pairRun{script: ps, hosts: hosts}
	var ends [2]net.Conn
	var chans [2]<-chan attachResult
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for i := range 2 {
		c, s := w.pipe(pr.hosts[i], 5*time.Millisecond)
		ends[i] = s
		pr.opts[i] = clientOpts(pr.hosts[i])
		if tweak != nil {
			tweak(i, &pr.opts[i])
		}
		chans[i] = runClient(ctx, c, pr.opts[i])
	}
	pr.scriptE = ps.run(ctx, ends)
	for i := range 2 {
		pr.res[i] = <-chans[i]
	}
	return pr
}

// closeAll closes the sessions of a pair run.
func (pr *pairRun) closeAll() {
	for _, r := range pr.res {
		if r.sess != nil {
			_ = r.sess.Close()
		}
	}
}

package coord

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/nat"
	engine "github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/internal/probe"
	"github.com/djylb/holepunch/internal/probetest"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// udpClient is a client's UDP side for the natprobe tests: sockets on a
// simulated public host, the session codec and read pumps that hand replies
// to a prober.
type udpClient struct {
	t     *testing.T
	host  *nattest.Host
	codec *udpwire.Codec
	mu    sync.Mutex
	win   udpwire.SeqWindow
	p     *probe.Prober
	wg    sync.WaitGroup
	conns []net.PacketConn
}

type udpSock struct {
	id   uint8
	conn nattest.Conn
}

func (s *udpSock) ID() uint8             { return s.id }
func (s *udpSock) Local() netip.AddrPort { return s.conn.LocalAddr().(*net.UDPAddr).AddrPort() }
func (s *udpSock) WriteTo(b []byte, to netip.AddrPort) error {
	_, err := s.conn.WriteToUDPAddrPort(b, to)
	return err
}

func newUDPClient(t *testing.T, host *nattest.Host, start *protocol.PunchStart) *udpClient {
	role := udpwire.RoleInitiator
	if start.Role == protocol.RoleResponder {
		role = udpwire.RoleResponder
	}
	codec, err := udpwire.NewCodec(start.Token, start.Wire.RouteID, role,
		udpwire.PadPolicy{Min: start.Wire.PayloadMin, Max: start.Wire.PayloadMax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &udpClient{t: t, host: host, codec: codec}
	t.Cleanup(c.close)
	return c
}

func (c *udpClient) open(id uint8) *udpSock {
	conn, err := c.host.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(c.host.Addrs()[0], 0), "listen")
	if err != nil {
		c.t.Fatal(err)
	}
	c.conns = append(c.conns, conn)
	s := &udpSock{id: id, conn: conn}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		buf, scratch := make([]byte, 2048), make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			h, tl, ok := probetest.Open(c.codec, buf[:n], scratch)
			if !ok {
				continue
			}
			c.mu.Lock()
			fresh := c.win.Accept(h.Seq)
			p := c.p
			c.mu.Unlock()
			if fresh && p != nil {
				p.Deliver(s.id, from, &h, &tl, time.Now())
			}
		}
	}()
	return s
}

func (c *udpClient) close() {
	for _, conn := range c.conns {
		_ = conn.Close()
	}
	c.wg.Wait()
}

// probeReport probes natprobe like the client runtime and returns the
// probe_report.
func (c *udpClient) probeReport(start *protocol.PunchStart) protocol.ProbeReport {
	primary := c.open(nat.SocketID(protocol.FamilyUDP4, nat.IndexPrimary))
	spec := probe.Spec{Codec: c.codec, Family: protocol.FamilyUDP4, Timeout: 2 * time.Second, Probe: start.Probe}
	p := probe.New(spec, primary, nil, func() (probe.SocketHandle, error) {
		return c.open(nat.SocketID(protocol.FamilyUDP4, nat.IndexSecond)), nil
	})
	c.mu.Lock()
	c.p = p
	c.mu.Unlock()
	cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := p.Run(cx)
	if res.Failure != "" {
		c.t.Fatalf("probe: %s %s", res.Failure, res.Detail)
	}
	fr := res.Table.Snapshot()
	fr.Traits = res.Traits
	fr.LocalAddrs = []netip.Addr{c.host.Addrs()[0]}
	return protocol.ProbeReport{
		SessionID: start.SessionID, Role: start.Role,
		Control:  protocol.ControlSpec{Version: 1, Features: protocol.AcceptFeatures(start.Control.Features, protocol.SupportedFeatures())},
		Caps:     protocol.ClientCaps{Impl: "test", MaxSockets: 64, Families: []protocol.FamilyCaps{{Family: protocol.FamilyUDP4, LowTTL: true}}},
		Families: []protocol.FamilyReport{fr}, Clock: res.Clock, Transport: protocol.Transport{Mode: "quic"},
	}
}

// probeFrom sends one probe for observer obs from a fresh socket claiming
// socket id sock, optionally with a SANDWICH TLV.
func (c *udpClient) probeFrom(obs protocol.ObserverSpec, sock uint8, sandwich *[2]uint8) {
	s := c.open(sock)
	pkt, err := probetest.Seal(c.codec, probetest.Probe{Sandwich: sandwich, PlainLen: 120, Sock: sock, Obs: obs.ID})
	if err != nil {
		c.t.Fatal(err)
	}
	if err := s.WriteTo(pkt, obs.Addr); err != nil {
		c.t.Fatal(err)
	}
}

// traitsLog records the traits memory's calls; Apply claims cross-IP
// evidence the session never had.
type traitsLog struct {
	mu      sync.Mutex
	applied int
	finals  []protocol.Traits
}

func (l *traitsLog) Apply(_ natprobe.TraitsKey, cur protocol.Traits) protocol.Traits {
	l.mu.Lock()
	l.applied++
	l.mu.Unlock()
	cur.CrossIP = true
	return cur
}

func (l *traitsLog) Observe(_ natprobe.TraitsKey, final protocol.Traits, _ bool) {
	l.mu.Lock()
	l.finals = append(l.finals, final)
	l.mu.Unlock()
}

// TestNatprobeEndToEnd: with a real natprobe on a simulated Internet, the
// summaries carry the verified (cookie-echoed) endpoints, the default
// planner aims only at them, sandwich probes become a window, a drifted
// mapping is pushed after the next go, the traits memory learns only the
// session's own evidence, and the registry entry goes with the session.
func TestNatprobeEndToEnd(t *testing.T) {
	n := nattest.NewNetwork()
	defer func() { _ = n.Close() }()
	server := n.PublicHost(netip.IPv4Unspecified())
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	srv, err := natprobe.NewServer(natprobe.ServerConfig{Registry: reg, PortCount: 2, Listen: server.Listen,
		Groups: []natprobe.ObserverGroup{{Bind: server.Addrs()[0]}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	tl := &traitsLog{}
	r := newRig(t, withRegistry(reg), func(c *Config) {
		c.TraitsMemory = tl
		c.DefaultProbe = protocol.ProbeSpec{Observers: srv.Observers(protocol.FamilyUDP4), ExtraReply: true}
	})
	p := r.pair(SessionOptions{ClientKeys: [2]string{"vis", "prov"}})
	if !p.starts[0].Control.Has(protocol.FeatureSandwich) {
		t.Fatal("sandwich not offered with a registry")
	}
	var udp [2]*udpClient
	var reps [2]protocol.ProbeReport
	for i := range 2 {
		udp[i] = newUDPClient(t, n.PublicHost(), p.starts[i])
		reps[i] = udp[i].probeReport(p.starts[i])
	}
	for i := range 2 {
		send(t, p.cl[i], &reps[i])
	}
	var sums [2]*protocol.ProbeSummary
	for i := range 2 {
		sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
	}
	peerPrimary := reps[1].Families[0].Sockets[0].Local
	ep := sums[0].Peer.Families[0].Endpoints
	if len(ep) == 0 || !ep[0].Verified || ep[0].Addr != peerPrimary {
		t.Fatalf("peer view %+v", sums[0].Peer)
	}
	for _, s := range sums[0].Plan.Round1.Sides {
		for _, st := range s.Stages {
			for _, tg := range st.Targets {
				if tg.Addr() != peerPrimary.Addr() {
					t.Fatalf("target %v", tg)
				}
			}
		}
	}
	if reg.Len() != 1 {
		t.Fatal("handle closed although sandwich was negotiated")
	}
	for i := range 2 {
		send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 1))
	}
	for i := range 2 {
		expect[protocol.PunchGo](t, p.cl[i])
	}

	// Sandwich: the responder's helper probes reach natprobe, whose reader
	// hands them to the session; the window goes to the initiator.
	p.s.mu.Lock()
	p.s.st.rounds.cur.sandwich[1][0] = true
	p.s.mu.Unlock()
	obs := srv.Observers(protocol.FamilyUDP4)
	helper := nat.SocketID(protocol.FamilyUDP4, nat.IndexSandwich)
	udp[1].probeFrom(obs[0], helper, &[2]uint8{1, nat.SandwichBefore})
	udp[1].probeFrom(obs[1], helper, &[2]uint8{1, nat.SandwichAfter})
	var win *protocol.Assist
	for deadline := time.Now().Add(testkit.WaitBound(t)); win == nil; {
		if time.Now().After(deadline) {
			t.Fatal("no sandwich window")
		}
		r.clk.Advance(0)
		m, _, err := p.cl[0].Next(ctxShort(t))
		if err != nil {
			continue
		}
		if a, ok := m.(*protocol.Assist); ok && a.Source == protocol.TargetsSandwich {
			win = a
		}
	}
	if win.Window == nil || win.Window.IP != peerPrimary.Addr() {
		t.Fatalf("sandwich window %+v", win)
	}

	// Drift: the initiator's primary socket shows up at a new port.
	udp[0].probeFrom(obs[0], nat.SocketID(protocol.FamilyUDP4, nat.IndexPrimary), nil)
	testkit.WaitFor(t, "drift observed", func() bool {
		for _, o := range p.s.handle.Observations(protocol.RoleInitiator) {
			if o.Changes > 0 {
				return true
			}
		}
		return false
	})
	p.endRound(1, [2]simclient.Outcome{fired(5), fired(5)})
	var drift *protocol.Assist
	for drift == nil {
		m, _, err := p.cl[1].Next(ctx(t))
		if err != nil {
			t.Fatal(err)
		}
		if a, ok := m.(*protocol.Assist); ok && a.Source == protocol.TargetsDrift {
			drift = a
		}
	}
	if len(drift.Targets) != 1 || drift.Targets[0].Addr() != udp[0].host.Addrs()[0] {
		t.Fatalf("drift %+v", drift)
	}

	p.confirm(0, 2)
	p.confirm(1, 2)
	testkit.WaitFor(t, "handle closed at the first confirmation", func() bool { return reg.Len() == 0 })
	p.succeed(0, 2)
	p.succeed(1, 2)
	res := r.wait(p.s)
	if res.Outcome != OutcomeSucceeded || res.StrategyKey == "" {
		t.Fatalf("result %+v", res)
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if tl.applied != 2 || len(tl.finals) != 2 {
		t.Fatalf("traits memory: %d applies, %d observes", tl.applied, len(tl.finals))
	}
	for _, f := range tl.finals {
		if f.CrossIP {
			t.Fatal("the memory's own conclusion was fed back")
		}
	}
}

func ctxShort(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	t.Cleanup(cancel)
	return c
}

// TestSandwichRegistrationOutlivesReadyWait: with sandwich probing the
// registration is renewed when the summaries go out, while it is alive —
// Extend cannot revive an expired entry — so a ready that comes after
// the registration's first expiry still finds it.
func TestSandwichRegistrationOutlivesReadyWait(t *testing.T) {
	var reg *natprobe.Registry
	r := newRig(t, func(c *Config) {
		reg = natprobe.NewRegistry(natprobe.RegistryConfig{Clock: c.Clock, MaxEntries: 1})
		c.Registry, c.NoObserver = reg, false
		c.TTL.ReadyTimeout = maxReady
	})
	s := r.session(SessionOptions{})
	// Registered for bind 15 s + probe 2 s + slack 3 s + 5 s = 25 s.
	r.clk.Advance(14900 * time.Millisecond)
	p := &pair{r: r, s: s}
	for i := range 2 {
		p.cl[i] = r.attach(s, roleOf(i))
		p.starts[i] = expect[protocol.PunchStart](t, p.cl[i])
	}
	r.clk.Advance(4900 * time.Millisecond) // just inside the probing deadline
	sums := p.summaries()
	r.clk.Advance(5700 * time.Millisecond) // past the first expiry, inside the ready wait
	// A full Registry drops its expired entries before refusing: a live
	// one keeps the only place.
	other := nat.Registration{SessionID: "other", Route: protocol.RouteID{9}, Token: protocol.Token{9}}
	if _, err := nat.RegisterProbe(reg, other); !errors.Is(err, natprobe.ErrRegistryFull) || reg.Len() != 1 {
		t.Fatalf("registration expired: %v, %d left", err, reg.Len())
	}
	for i := range 2 {
		send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 1))
	}
	for i := range 2 {
		expect[protocol.PunchGo](t, p.cl[i])
	}
	s.Abort(protocol.ReasonCanceled, "")
	r.wait(s)
	if reg.Len() != 0 {
		t.Fatal("registration kept after the end")
	}
}

// classifyLog is the default planner, recording the classification input.
type classifyLog struct {
	engine.DefaultPlanner
	mu  sync.Mutex
	ins []plan.ClassifyInput
}

func (p *classifyLog) Classify(in plan.ClassifyInput) plan.Classification {
	p.mu.Lock()
	p.ins = append(p.ins, in)
	p.mu.Unlock()
	return p.DefaultPlanner.Classify(in)
}

func (p *classifyLog) input(t *testing.T) plan.ClassifyInput {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ins) != 1 {
		t.Fatalf("%d classifications", len(p.ins))
	}
	return p.ins[0]
}

// TestEarlyVerdictOnMeasuredRandom: natprobe itself measured both
// sides — two clients behind symmetric NATs with random ports — as random
// with high confidence, and in the default tier no rung after the two cheap
// ones can run, so the session is rejected at the summary with
// hard_symmetric_random and no go is ever sent. ClassifyInput.Measured is
// natprobe's own merge: the traits memory's advice (here a cross-IP claim)
// reaches the views but not Measured.
func TestEarlyVerdictOnMeasuredRandom(t *testing.T) {
	n := nattest.NewNetwork()
	defer func() { _ = n.Close() }()
	reg, spec := startNatprobe(t, n)
	cl := &classifyLog{}
	r := newRig(t, withRegistry(reg), func(c *Config) {
		c.Planner = cl
		c.TraitsMemory = &traitsLog{}
		c.DefaultProbe = spec
	})
	p := r.pair(SessionOptions{ClientKeys: [2]string{"vis", "prov"}})
	var reps [2]protocol.ProbeReport
	for i := range 2 {
		host := n.NAT(nattest.SymmetricRandom()).Host()
		reps[i] = newUDPClient(t, host, p.starts[i]).probeReport(p.starts[i])
	}
	for i := range 2 {
		send(t, p.cl[i], &reps[i])
	}
	for i := range 2 {
		if a := expectAbort(t, p.cl[i]); a.Reason != protocol.ReasonHardSymmetricRandom {
			t.Fatalf("%s: abort %+v", roleOf(i), a)
		}
	}
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonHardSymmetricRandom || len(res.Rounds) != 0 {
		t.Fatalf("result %+v", res)
	}
	in := cl.input(t)
	views := [2]protocol.PeerView{in.Initiator, in.Responder}
	for i, m := range in.Measured {
		if len(m.Families) != 1 || len(views[i].Families) != 1 {
			t.Fatalf("%s: measured %+v, view %+v", roleOf(i), m, views[i])
		}
		mt, vt := m.Families[0].Traits, views[i].Families[0].Traits
		if mt.PortAlloc != protocol.AllocRandom || mt.PortAllocConf != protocol.ConfHigh || mt.Samples == 0 {
			t.Fatalf("%s: measured traits %+v", roleOf(i), mt)
		}
		if mt.CrossIP || !vt.CrossIP {
			t.Fatalf("%s: the memory's advice in measured %v, in the view %v", roleOf(i), mt.CrossIP, vt.CrossIP)
		}
	}
}

// TestSeqRndVerdict: natprobe measured one side SEQ with APDF
// filtering and the other Random, both at High confidence. Once the two
// cheap rounds found no contact the session ends with hard_symmetric_random
// — whether the planner ends the ladder there (default max_rounds) or
// max_rounds itself is reached at that round (the e2e timeouts' two). A SEQ
// side whose filtering is ADF keeps the plain candidate_timeout at the
// round cap.
func TestSeqRndVerdict(t *testing.T) {
	adf := nattest.SymmetricSeq(1)
	adf.Filtering = nattest.ADF
	for _, c := range []struct {
		name      string
		seq       nattest.NATConfig
		maxRounds uint8
		want      protocol.Reason
	}{
		{"planner ends the ladder", nattest.SymmetricSeq(1), 5, protocol.ReasonHardSymmetricRandom},
		{"round cap at the same round", nattest.SymmetricSeq(1), 2, protocol.ReasonHardSymmetricRandom},
		{"SEQ side ADF", adf, 2, protocol.ReasonCandidateTimeout},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := nattest.NewNetwork()
			defer func() { _ = n.Close() }()
			reg, spec := startNatprobe(t, n)
			cl := &classifyLog{}
			r := newRig(t, withRegistry(reg), func(cfg *Config) {
				cfg.Planner = cl
				cfg.DefaultProbe = spec
			})
			to := protocol.DefaultTimeouts()
			to.MaxRounds = c.maxRounds
			p := r.pair(SessionOptions{Timeouts: &to})
			hosts := [2]*nattest.Host{n.NAT(c.seq).Host(), n.NAT(nattest.SymmetricRandom()).Host()}
			for i := range 2 {
				rep := newUDPClient(t, hosts[i], p.starts[i]).probeReport(p.starts[i])
				send(t, p.cl[i], &rep)
			}
			var sums [2]*protocol.ProbeSummary
			for i := range 2 {
				sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
			}
			if sums[0].Plan.PairClass != engine.PairSeqRnd {
				t.Fatalf("pair class %q; measured %+v", sums[0].Plan.PairClass, cl.input(t).Measured)
			}
			for i := range 2 {
				send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 1))
			}
			for i := range 2 {
				expect[protocol.PunchGo](t, p.cl[i])
			}
			if gos := p.endRound(1, [2]simclient.Outcome{fired(5), fired(19)}); gos[0] == nil || gos[1] == nil {
				t.Fatal("no second round")
			}
			for i := range 2 {
				p.windowEnd(i, 2, fired(30))
			}
			for i := range 2 {
				if a := expectAbort(t, p.cl[i]); a.Reason != c.want {
					t.Fatalf("%s: abort %+v, want %s", roleOf(i), a, c.want)
				}
			}
			if res := r.wait(p.s); res.Reason != c.want || len(res.Rounds) != 2 {
				t.Fatalf("result %s after %d rounds", res.Reason, len(res.Rounds))
			}
		})
	}
}

// randomTraits are the self-reported traits of a symmetric NAT with random
// ports, as confident as a client can claim.
func randomTraits(public netip.AddrPort) protocol.Traits {
	return protocol.Traits{Mapping: protocol.MapAPDM, MappingConf: protocol.ConfHigh, Filtering: protocol.FiltPDF,
		FilteringConf: protocol.ConfHigh, PortAlloc: protocol.AllocRandom, PortAllocConf: protocol.ConfHigh,
		PublicIP: public.Addr(), Observed: public, Samples: 6}
}

// TestNoEarlyVerdictWithoutMeasurement: without natprobe there is no
// measurement, and the clients' own claims of random ports, however
// confident, never reject a session at the summary.
func TestNoEarlyVerdictWithoutMeasurement(t *testing.T) {
	cl := &classifyLog{}
	r := newRig(t, func(c *Config) { c.Planner = cl })
	p := r.pair(SessionOptions{})
	for i := range 2 {
		p.report(i, fam(i, randomTraits))
	}
	for i := range 2 {
		expect[protocol.ProbeSummary](t, p.cl[i])
	}
	in := cl.input(t)
	if len(in.Measured[0].Families)+len(in.Measured[1].Families) != 0 {
		t.Fatalf("measured without natprobe: %+v", in.Measured)
	}
	if in.Initiator.Families[0].Traits.PortAlloc != protocol.AllocRandom {
		t.Fatalf("view %+v", in.Initiator)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

// startNatprobe starts a natprobe server with the default port count on a
// public host of n, and returns its registry and the probe spec of its IPv4
// observers (second socket on, as the e2e world probes).
func startNatprobe(t *testing.T, n *nattest.Network) (*natprobe.Registry, protocol.ProbeSpec) {
	t.Helper()
	server := n.PublicHost(netip.IPv4Unspecified())
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	srv, err := natprobe.NewServer(natprobe.ServerConfig{Registry: reg, Listen: server.Listen,
		Groups: []natprobe.ObserverGroup{{Bind: server.Addrs()[0]}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return reg, protocol.ProbeSpec{V: protocol.ProbeSpecVersion, ExtraReply: true, SecondSocket: true,
		Observers: srv.Observers(protocol.FamilyUDP4)}
}

// TestSTUNConflictsCounted: a STUN value that contradicts natprobe —
// another port where natprobe saw a single mapping — changes nothing in the
// plan and is counted, in the session's Result and in the coordinator's
// Stats.
func TestSTUNConflictsCounted(t *testing.T) {
	n := nattest.NewNetwork()
	defer func() { _ = n.Close() }()
	reg, spec := startNatprobe(t, n)
	r := newRig(t, withRegistry(reg), func(c *Config) { c.DefaultProbe = spec })
	p := r.pair(SessionOptions{})
	var reps [2]protocol.ProbeReport
	for i := range 2 {
		reps[i] = newUDPClient(t, n.PublicHost(), p.starts[i]).probeReport(p.starts[i])
	}
	pub := reps[0].Families[0].Sockets[0].Local // a public host: natprobe sees the socket as it is
	reps[0].Families[0].STUN = []protocol.RowReport{{Observer: 0, Observed: netip.AddrPortFrom(pub.Addr(), pub.Port()+9)}}
	for i := range 2 {
		send(t, p.cl[i], &reps[i])
	}
	sum := expect[protocol.ProbeSummary](t, p.cl[1])
	if tr := sum.Peer.Families[0].Traits; tr.Mapping != protocol.MapEIM || tr.CrossIP {
		t.Fatalf("the initiator's traits %+v", tr)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	if res := r.wait(p.s); res.Counters.STUNConflicts != 1 {
		t.Fatalf("result counters %+v", res.Counters)
	}
	if st := r.c.Stats(); st.STUNConflicts != 1 {
		t.Fatalf("stats: %d STUN conflicts", st.STUNConflicts)
	}
}

// TestTraitsCorrectionSources: the traits memory learns from the
// clients' punch-time corrections, but only a correction from the peer or
// from natprobe's alt observers is cross-IP evidence; one from a STUN server
// is a hint, so the memory never learns a cross-IP mapping from STUN.
func TestTraitsCorrectionSources(t *testing.T) {
	n := nattest.NewNetwork()
	defer func() { _ = n.Close() }()
	reg, spec := startNatprobe(t, n)
	tl := &traitsLog{}
	r := newRig(t, withRegistry(reg), func(c *Config) {
		c.TraitsMemory = tl
		c.DefaultProbe = spec
	})
	p := r.pair(SessionOptions{ClientKeys: [2]string{"vis", "prov"}})
	for i := range 2 {
		rep := newUDPClient(t, n.PublicHost(), p.starts[i]).probeReport(p.starts[i])
		send(t, p.cl[i], &rep)
	}
	var sums [2]*protocol.ProbeSummary
	for i := range 2 {
		sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
	}
	for i := range 2 {
		send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 1))
	}
	for i := range 2 {
		expect[protocol.PunchGo](t, p.cl[i])
	}
	p.confirm(0, 1)
	p.confirm(1, 1)
	eim := protocol.MapEIM
	for i, src := range []protocol.TraitsSource{protocol.TraitsSourceSTUN, protocol.TraitsSourceAlt} {
		res := simclient.Success(p.s.ID(), roleOf(i), p.path(i, 1))
		res.Traits = []protocol.TraitsUpdate{{Family: protocol.FamilyUDP4, Mapping: &eim, Source: src}}
		send(t, p.cl[i], res)
	}
	if res := r.wait(p.s); res.Outcome != OutcomeSucceeded {
		t.Fatalf("result %+v", res)
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if len(tl.finals) != 2 || tl.finals[0].Mapping != eim || tl.finals[0].CrossIP || !tl.finals[1].CrossIP {
		t.Fatalf("observed %+v", tl.finals)
	}
}

// TestRemapPushedAfterEcho: without sandwich probing the natprobe
// registration still outlives the summary, so natprobe keeps watching the
// primary sockets. The responder's primary socket shows up at a new IP, as
// after a rebind: the mapping is not pushed while the responder has not
// echoed its cookie, and once a round_result remap echoes it, the IP joins
// the responder's verified ones, the mapping follows the next go to the
// initiator as peer_targets{source: drift}, and only then becomes the
// planner's first endpoint of the responder, with a punch-time sample.
func TestRemapPushedAfterEcho(t *testing.T) {
	n := nattest.NewNetwork()
	defer func() { _ = n.Close() }()
	server := n.PublicHost(netip.IPv4Unspecified())
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	srv, err := natprobe.NewServer(natprobe.ServerConfig{Registry: reg, PortCount: 2, Listen: server.Listen,
		Groups: []natprobe.ObserverGroup{{Bind: server.Addrs()[0]}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	r := newRig(t, withRegistry(reg), func(c *Config) {
		c.DefaultProbe = protocol.ProbeSpec{Observers: srv.Observers(protocol.FamilyUDP4), ExtraReply: true}
	})
	p := r.pair(SessionOptions{})
	u4 := protocol.FamilyUDP4
	var udp [2]*udpClient
	for i := range 2 {
		udp[i] = newUDPClient(t, n.PublicHost(), p.starts[i])
		rep := udp[i].probeReport(p.starts[i])
		rep.Control.Features = nil // no sandwich
		send(t, p.cl[i], &rep)
	}
	var sums [2]*protocol.ProbeSummary
	for i := range 2 {
		sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
	}
	p.s.mu.Lock()
	sandwich := p.s.st.sand.negotiated
	p.s.mu.Unlock()
	if sandwich || reg.Len() != 1 {
		t.Fatalf("sandwich %v, %d registrations after the summary", sandwich, reg.Len())
	}
	for i := range 2 {
		send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 1))
	}
	for i := range 2 {
		expect[protocol.PunchGo](t, p.cl[i])
	}

	obs := srv.Observers(u4)[0]
	primary := nat.SocketID(u4, nat.IndexPrimary)
	udp[1].host = n.PublicHost() // the same client, now at another address
	udp[1].probeFrom(obs, primary, nil)
	var slot nat.Observation
	testkit.WaitFor(t, "the moved mapping", func() bool {
		for _, o := range p.s.handle.Observations(protocol.RoleResponder) {
			if o.Socket == primary && o.Observer == obs.ID && o.Changes > 0 {
				slot = o
				return true
			}
		}
		return false
	})
	moved := slot.Observed
	// Only the primary socket counts: the sandwich helper's slot moves too
	// (two sockets claim it), and drift does not look at it.
	helper := nat.SocketID(u4, nat.IndexSandwich)
	udp[1].probeFrom(obs, helper, nil)
	udp[1].probeFrom(obs, helper, nil)
	testkit.WaitFor(t, "the helper's moved slot", func() bool {
		for _, o := range p.s.handle.Observations(protocol.RoleResponder) {
			if o.Socket == helper && o.Changes > 0 {
				return true
			}
		}
		return false
	})
	if d := p.s.observeDrift(); len(d[0]) != 0 || len(d[1]) != 1 || d[1][0].Family != u4 || d[1][0].Observed != moved {
		t.Fatalf("drift %+v", d)
	}
	known := func() (verified, first bool, samples int) {
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		fv, _ := familyView(p.s.st.plan.pviews[1], u4)
		return p.s.st.adm.knownIP(1, u4, moved.Addr()), len(fv.Endpoints) > 0 && fv.Endpoints[0].Addr == moved, len(p.s.st.rounds.mappings[1])
	}

	if g := p.endRound(1, [2]simclient.Outcome{fired(5), fired(5)}); g[0] == nil || g[0].Round != 2 {
		t.Fatalf("round 2 go %+v", g[0])
	}
	p.s.mu.Lock()
	pushed := p.s.st.ctr.PeerTargets
	p.s.mu.Unlock()
	if v, _, _ := known(); v || pushed != 0 {
		t.Fatal("a mapping on a new IP was taken without the echo")
	}

	echo := fired(5)
	echo.Remap = &protocol.Remap{Observer: slot.Observer, Observed: moved, Cookie: slot.Cookie}
	if g := p.endRound(2, [2]simclient.Outcome{fired(5), echo}); g[0] == nil || g[0].Round != 3 {
		t.Fatalf("round 3 go %+v", g[0])
	}
	got := expect[protocol.Assist](t, p.cl[0])
	if got.Source != protocol.TargetsDrift || got.Round != 3 || !slices.Equal(got.Targets, []netip.AddrPort{moved}) {
		t.Fatalf("push %+v, want drift to %v", got, moved)
	}
	if v, first, samples := known(); !v || !first || samples == 0 {
		t.Fatalf("after the push: verified %v, first in the planner's view %v, %d samples", v, first, samples)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
	if reg.Len() != 0 {
		t.Fatal("registration kept after the end")
	}
}

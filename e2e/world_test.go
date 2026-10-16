package e2e

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// e2eTimeouts are the shortened protocol timeouts of the e2e suite: probe
// 1.5 s, handshake 6 s, transport 2 s, handover 1 s, max_rounds 2, go_wait at
// its default 5 s.
func e2eTimeouts() protocol.Timeouts {
	return protocol.Timeouts{ProbeTimeoutMs: 1500, GoWaitMs: 5000, HandshakeTimeoutMs: 6000,
		HandoverTimeoutMs: 1000, TransportTimeoutMs: 2000, MaxRounds: 2}
}

// e2eBindTimeout is the coordinator's BindTimeout in the suite (3 s).
// A world with the library's default timeouts leaves it to the
// coordinator's default instead (worldConfig.defaultTimeouts).
const e2eBindTimeout = 3 * time.Second

// NAT profiles.
func profPUB() nattest.NATConfig    { return nattest.PublicOpen() }
func profPUBFW() nattest.NATConfig  { return nattest.PublicFW() }
func profFC() nattest.NATConfig     { return nattest.FullCone() }
func profRC() nattest.NATConfig     { return nattest.RestrictedCone() }
func profPRC() nattest.NATConfig    { return nattest.PortRestricted() }
func profSYMSEQ() nattest.NATConfig { return nattest.SymmetricSeq(1) }
func profSYMRND() nattest.NATConfig { return nattest.SymmetricRandom() }

// profSYMSEQNoise is SYMSEQ with other subscribers taking lambda ports a
// second (SYMSEQ~λ).
func profSYMSEQNoise(lambda float64) nattest.NATConfig {
	c := nattest.SymmetricSeq(1)
	c.PortNoisePPS = lambda
	return c
}

// profSYMSEQDown is SYMSEQ allocating downwards, in steps of −1
// (SYMSEQ-1).
func profSYMSEQDown() nattest.NATConfig { return nattest.SymmetricSeq(-1) }

// profPRESRND is APDM whose fresh socket keeps its local port for its first
// mapping, random ports otherwise (PRESRND).
func profPRESRND() nattest.NATConfig { return nattest.SymmetricPreserveRandom() }

// profADMRND is address-dependent mapping with random ports.
func profADMRND() nattest.NATConfig {
	return nattest.NATConfig{Mapping: nattest.ADM, Filtering: nattest.ADF, PortAlloc: nattest.Random}
}

// withV6 adds IPv6 behind a profile: NoNAT behind a firewall that filters
// like fw.
func withV6(c nattest.NATConfig, fw nattest.Filtering) nattest.NATConfig {
	c.IPv6 = &nattest.IPv6Config{Mode: nattest.NoNAT, Firewall: fw}
	return c
}

// worldConfig configures the server side of a cell.
type worldConfig struct {
	seed     int64
	serverV6 bool // the server also observes IPv6
	// timeouts are the coordinator's protocol timeouts; zero takes the
	// suite's shortened ones (e2eTimeouts).
	timeouts protocol.Timeouts
	// defaultTimeouts replaces the timeouts with the library's defaults,
	// and the suite's BindTimeout with the coordinator's, for the
	// default-timeout comparison: round 3 and beyond, and the
	// full round windows, only exist with them.
	defaultTimeouts bool

	extreme  bool             // coord Budget.AllowExtreme (p2p_allow_extreme)
	policy   *protocol.Policy // coord default policy (the birthday tier)
	coreLink nattest.LinkConfig
	planner  coord.Planner
	memory   coord.StrategyMemory
	traits   natprobe.TraitsMemory
	limits   coord.Limits
	eventLog int // nattest event log; 0 = the default, < 0 = off
	// measure wraps the default planner to record what natprobe measured
	// of both sides (ClassifyInput.Measured). It is only for the cells that
	// assert on that measurement: the wrapper changes nothing in the
	// session, but a planner other than the default one has a fallback after
	// a panic, which the injection-point tests must not see.
	measure bool
	// noSecondSocket probes without the second socket, which leaves
	// natprobe three port samples per side instead of six.
	noSecondSocket bool
	// stun runs a STUN server on a public host of its own and lists it in
	// the probe spec.
	stun     bool
	observer func(coord.Event)
	// onResult also runs in the coordinator's OnResult (user-code faults).
	onResult func(coord.Result)
}

// world is one simulated Internet with the server side of holepunch: a
// natprobe Server and a coordinator on a public host. The host sits behind
// an identity device (PublicOpen) so that a test can blackhole the server's
// UDP while its control links, which are pipes, keep working.
type world struct {
	cfg    worldConfig
	rng    *rand.Rand
	n      *nattest.Network
	srvNAT *nattest.NAT
	server *nattest.Host
	stun   netip.AddrPort // the STUN server of worldConfig.stun
	reg    *natprobe.Registry
	probe  *natprobe.Server
	co     *coord.Coordinator
	// measured records natprobe's measurement (worldConfig.measure).
	measured *measuringPlanner
	// helpers are the goroutines a construct runs next to a session (the
	// neighbours of a burst); close ends them through quit and waits for
	// them.
	helpers sync.WaitGroup
	quit    chan struct{}

	mu      sync.Mutex
	results map[string]int // OnResult calls per session
	gotRes  map[string]chan struct{}
	closed  bool
	nextIP  int // explicit addresses handed out
}

// newWorld builds a world; the caller must close it.
func newWorld(t testing.TB, cfg worldConfig) *world {
	t.Helper()
	bind := e2eBindTimeout
	switch {
	case cfg.defaultTimeouts:
		// Zero leaves BindTimeout to the coordinator's default (15 s).
		cfg.timeouts, bind = protocol.DefaultTimeouts(), 0
	case cfg.timeouts == (protocol.Timeouts{}):
		cfg.timeouts = e2eTimeouts()
	}
	w := &world{cfg: cfg, rng: rand.New(rand.NewPCG(uint64(cfg.seed), 0x6532655f776f726c)),
		results: map[string]int{}, gotRes: map[string]chan struct{}{}, quit: make(chan struct{})}
	opts := []nattest.Option{nattest.WithSeed(cfg.seed), nattest.WithCoreLink(cfg.coreLink)}
	switch {
	case cfg.eventLog > 0:
		opts = append(opts, nattest.WithEventLog(cfg.eventLog))
	case cfg.eventLog < 0:
		opts = append(opts, nattest.WithEventLog(0))
	}
	w.n = nattest.NewNetwork(opts...)
	// A failed construction (t.Fatalf) closes what it built, so that its
	// goroutines do not outlive the test.
	built := false
	defer func() {
		if !built {
			close(w.quit)
			w.helpers.Wait()
			if w.co != nil {
				_ = closeStep(w.co.Close)
			}
			_ = closeStep(w.probe.Close)
			_ = closeStep(w.n.Close)
		}
	}()
	srv := nattest.PublicOpen()
	srv.Name = "server"
	if cfg.serverV6 {
		srv = withV6(srv, nattest.Open)
	}
	w.srvNAT = w.n.NAT(srv)
	w.server = w.srvNAT.Host()
	w.reg = natprobe.NewRegistry(natprobe.RegistryConfig{})
	var groups []natprobe.ObserverGroup
	for _, a := range w.server.Addrs() {
		groups = append(groups, natprobe.ObserverGroup{Bind: a})
	}
	probe, err := natprobe.NewServer(natprobe.ServerConfig{Registry: w.reg, Groups: groups, Listen: w.server.Listen})
	if err != nil {
		t.Fatalf("natprobe: %v", err)
	}
	w.probe = probe
	if err := probe.Start(); err != nil {
		t.Fatalf("natprobe start: %v", err)
	}
	spec := protocol.ProbeSpec{V: protocol.ProbeSpecVersion, ExtraReply: true, SecondSocket: !cfg.noSecondSocket,
		Observers: probe.Observers(protocol.FamilyUDP4)}
	if cfg.serverV6 {
		spec.Observers = append(spec.Observers, probe.Observers(protocol.FamilyUDP6)...)
	}
	if cfg.stun {
		w.stun = w.stunServer(t)
		spec.STUN = []netip.AddrPort{w.stun}
	}
	if cfg.measure {
		w.measured = &measuringPlanner{}
		cfg.planner = w.measured
	}
	ccfg := coord.Config{
		Registry: w.reg, DefaultProbe: spec, Timeouts: cfg.timeouts, Policy: cfg.policy,
		TTL:    coord.TTLConfig{BindTimeout: bind},
		Budget: coord.BudgetConfig{AllowExtreme: cfg.extreme}, Limits: cfg.limits,
		Planner: cfg.planner, Memory: cfg.memory, TraitsMemory: cfg.traits,
		Observer: cfg.observer, OnResult: w.onResult,
	}
	w.co, err = coord.New(ccfg)
	if err != nil {
		t.Fatalf("coord: %v", err)
	}
	built = true
	return w
}

func (w *world) onResult(r coord.Result) {
	if f := w.cfg.onResult; f != nil {
		defer f(r)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results[r.SessionID]++
	if w.results[r.SessionID] == 1 {
		close(w.resultChan(r.SessionID))
	}
}

// resultChan returns the channel closed by a session's first OnResult;
// w.mu is held.
func (w *world) resultChan(id string) chan struct{} {
	ch, ok := w.gotRes[id]
	if !ok {
		ch = make(chan struct{})
		w.gotRes[id] = ch
	}
	return ch
}

// waitResult waits until OnResult has seen the session: the coordinator
// calls it after Done is closed.
func (w *world) waitResult(id string, d time.Duration) bool {
	w.mu.Lock()
	ch := w.resultChan(id)
	w.mu.Unlock()
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

// resultCalls returns how often OnResult saw a session.
func (w *world) resultCalls(id string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.results[id]
}

// close shuts the world down and checks that the server side holds
// nothing: no session, no registry entry, no key in use.
func (w *world) close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.mu.Unlock()
	var errs []error
	if n := w.co.Len(); n != 0 {
		errs = append(errs, fmt.Errorf("coordinator holds %d sessions", n))
	}
	if st := w.co.Stats(); st.ActiveByKey != 0 || st.SessionsActive != 0 {
		errs = append(errs, fmt.Errorf("coordinator stats: %d keys in use, %d sessions active", st.ActiveByKey, st.SessionsActive))
	}
	if n := w.reg.Len(); n != 0 {
		errs = append(errs, fmt.Errorf("registry holds %d entries", n))
	}
	close(w.quit)
	w.helpers.Wait()
	for _, c := range []struct {
		name string
		fn   func() error
	}{{"coordinator", w.co.Close}, {"natprobe", w.probe.Close}, {"network", w.n.Close}} {
		if err := closeStep(c.fn); err != nil {
			errs = append(errs, fmt.Errorf("%s close: %w", c.name, err))
		}
	}
	return errors.Join(errs...)
}

// abandon closes a world whose session could not be created and returns the
// problems: err, and the close's failure if any.
func (w *world) abandon(err error) []string {
	v := []string{err.Error()}
	if cerr := w.close(); cerr != nil {
		v = append(v, fmt.Sprintf("world close: %v", cerr))
	}
	return v
}

// measuringPlanner is the default planner with a record of what natprobe
// itself measured of both sides when the session was classified
// (ClassifyInput.Measured): the evidence the
// summary-time verdict rests on, and the classification the deliberately
// misclassified cells compare with the NAT's real
// behaviour. A world classifies one session at a time; the record is the
// latest one.
type measuringPlanner struct {
	plan.DefaultPlanner

	mu       sync.Mutex
	measured [2]protocol.PeerView
	seen     bool
}

// Classify records the measurement and classifies as the default planner.
func (p *measuringPlanner) Classify(in coord.ClassifyInput) coord.Classification {
	p.mu.Lock()
	p.measured, p.seen = in.Measured, true
	p.mu.Unlock()
	return p.DefaultPlanner.Classify(in)
}

// get returns the latest measurement by role; ok is false before the first
// classification.
func (p *measuringPlanner) get() (v [2]protocol.PeerView, ok bool) {
	if p == nil {
		return v, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.measured, p.seen
}

// randomHigh reports whether natprobe measured every family it observed of
// a side as Random port allocation with High confidence — the side half of
// the summary-time verdict.
func randomHigh(v protocol.PeerView) bool {
	n := 0
	for _, f := range v.Families {
		if f.Traits.Samples == 0 {
			continue
		}
		if f.Traits.PortAlloc != protocol.AllocRandom || f.Traits.PortAllocConf != protocol.ConfHigh {
			return false
		}
		n++
	}
	return n > 0
}

// describeView renders what natprobe measured of a side: per family the
// mapping, the port allocation (with step and velocity when sequential) and
// their confidences.
func describeView(v protocol.PeerView) string {
	var parts []string
	for _, f := range v.Families {
		t := f.Traits
		s := fmt.Sprintf("%s %s/%s %s/%s", f.Family, t.Mapping, t.MappingConf, t.PortAlloc, t.PortAllocConf)
		if t.PortAlloc == protocol.AllocSequential {
			s += fmt.Sprintf(" step %d v %.0f/s", t.PortStep, t.PortVelocity)
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "unmeasured"
	}
	return strings.Join(parts, "; ")
}

// closeStep runs one Close and turns a panic that escapes it into an error,
// so that the other parts of the world are still closed.
func closeStep(fn func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic escaped Close: %v", p)
		}
	}()
	return fn()
}

// delay draws a link delay in [lo, hi] from the world's seed.
func (w *world) delay(lo, hi time.Duration) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return lo + time.Duration(w.rng.Int64N(int64(hi-lo)+1))
}

// side is one client: its host, the NAT devices in front of it (nearest
// first), its Network wrapper and an optional port mapper.
type side struct {
	host   *nattest.Host
	nats   []*nattest.NAT
	net    *clientNet
	mapper *fakeMapper
	// pm replaces mapper as the client's PortMapper (user-code faults).
	pm holepunch.PortMapper
}

// Uplink delays of the client NATs (10–40 ms on the control
// links, a few to 20 ms on the NAT uplinks).
const (
	uplinkMin = 5 * time.Millisecond
	uplinkMax = 20 * time.Millisecond
)

// behind builds a client behind nested NAT devices, outermost first (at
// least one), with host addresses lan (none: automatic).
func (w *world) behind(cfgs []nattest.NATConfig, lan ...netip.Addr) *side {
	outer := cfgs[0]
	if outer.Uplink == (nattest.LinkConfig{}) {
		outer.Uplink = nattest.LinkConfig{Delay: w.delay(uplinkMin, uplinkMax)}
	}
	nat := w.n.NAT(outer)
	chain := []*nattest.NAT{nat}
	for _, c := range cfgs[1:] {
		nat = nat.NAT(c)
		chain = append([]*nattest.NAT{nat}, chain...)
	}
	h := nat.Host(lan...)
	return &side{host: h, nats: chain, net: newClientNet(h)}
}

// on builds a second client on an existing NAT (same LAN as an earlier side).
func (w *world) on(nats []*nattest.NAT, lan ...netip.Addr) *side {
	h := nats[0].Host(lan...)
	return &side{host: h, nats: nats, net: newClientNet(h)}
}

// sameHost returns a second client on the host of s (two processes on one
// machine).
func sameHost(s *side) *side {
	return &side{host: s.host, nats: s.nats, net: newClientNet(s.host)}
}

// natStats sums the counters of a side's NAT devices.
func (s *side) natStats() (filtered, scanBans uint64) {
	for _, n := range s.nats {
		st := n.Stats()
		filtered += st.FilteredInbound
		scanBans += st.ScanBans
	}
	return filtered, scanBans
}

// publicIPs returns the addresses a peer sees the side at: the outermost
// device's external addresses, or the host's own for a device that
// translates nothing.
func (s *side) publicIPs() []netip.Addr {
	outer := s.nats[len(s.nats)-1]
	if ips := outer.ExternalIPs(); len(ips) > 0 {
		out := ips
		for _, a := range s.host.Addrs() {
			if a.Is6() {
				out = append(out, a)
			}
		}
		return out
	}
	return s.host.Addrs()
}

// fakeMapper is the port mapper of a home router behind an upstream NAT: it
// reports the router's own mapping of the socket, whose external endpoint lies
// in the upstream network. nattest does not speak UPnP/PCP/NAT-PMP. It counts
// the mappings it handed out and their releases, so that a test can check
// that every mapping was released; a Map that fails hands out none.
type fakeMapper struct {
	home     *nattest.NAT
	maps     atomic.Int32
	releases atomic.Int32
}

// mapperPoll is how often the fake mapper looks for the router's mapping,
// which appears with the socket's first packet.
const mapperPoll = 5 * time.Millisecond

// Map waits for the home router's mapping of conn's port and reports it.
func (m *fakeMapper) Map(ctx context.Context, conn net.PacketConn, _ protocol.PortMappingPolicy) (protocol.PortMappingInfo, func() error, error) {
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return protocol.PortMappingInfo{}, nil, fmt.Errorf("e2e: local address %v is not UDP", conn.LocalAddr())
	}
	port := la.AddrPort().Port()
	tm := time.NewTimer(0)
	defer tm.Stop()
	for {
		for _, mp := range m.home.Mappings() {
			if mp.Internal.Port() == port {
				m.maps.Add(1)
				var once sync.Once
				return protocol.PortMappingInfo{Method: protocol.PortMapUPnP, External: mp.External, Internal: mp.Internal, Lease: time.Hour},
					func() error { once.Do(func() { m.releases.Add(1) }); return nil }, nil
			}
		}
		tm.Reset(mapperPoll)
		select {
		case <-ctx.Done():
			return protocol.PortMappingInfo{}, nil, ctx.Err()
		case <-tm.C:
		}
	}
}

var _ holepunch.PortMapper = (*fakeMapper)(nil)

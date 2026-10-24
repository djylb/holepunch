package coord_test

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// These tests run the coordinator with the default planner and a real
// natprobe against two real clients (the root package) on a simulated
// Internet: every target the planner chooses must pass the clients'
// admission, so the clients refuse none, and a shared upstream NAT or an
// unverified IPv6 family connects over the path meant for it.

// e2eTimeouts keep a session within a few seconds.
func e2eTimeouts() protocol.Timeouts {
	return protocol.Timeouts{ProbeTimeoutMs: 600, SummaryWaitMs: 3000, GoWaitMs: 1500, HandshakeTimeoutMs: 4000,
		HandoverTimeoutMs: 1500, TransportTimeoutMs: 5000, MaxRounds: 3}
}

// e2eWorld is a simulated Internet with natprobe and the coordinator on an
// IPv4-only public host.
type e2eWorld struct {
	t      *testing.T
	n      *nattest.Network
	server *nattest.Host
	c      *coord.Coordinator
}

func newE2E(t *testing.T, opts ...func(*coord.Config)) *e2eWorld {
	t.Helper()
	return newE2EWorld(t, false, opts...)
}

// newE2EWorld is newE2E, with natprobe's change-IP replies from a second
// server address when alt is set: the cross-address evidence that teaches
// the traits memory an endpoint-independent mapping.
func newE2EWorld(t *testing.T, alt bool, opts ...func(*coord.Config)) *e2eWorld {
	t.Helper()
	n := nattest.NewNetwork()
	addrs := []netip.Addr{netip.IPv4Unspecified()}
	if alt {
		addrs = append(addrs, netip.IPv4Unspecified())
	}
	server := n.PublicHost(addrs...)
	groups := []natprobe.ObserverGroup{{Bind: server.Addrs()[0]}}
	if alt {
		groups = append(groups, natprobe.ObserverGroup{Bind: server.Addrs()[1], Alt: true})
	}
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	srv, err := natprobe.NewServer(natprobe.ServerConfig{Registry: reg, Groups: groups,
		Listen: server.Listen, SourceRate: natprobe.Rate{PerSec: -1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	cfg := coord.Config{Registry: reg, Timeouts: e2eTimeouts(),
		DefaultProbe: protocol.ProbeSpec{Observers: srv.Observers(protocol.FamilyUDP4), ExtraReply: true}}
	for _, o := range opts {
		o(&cfg)
	}
	c, err := coord.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		_ = srv.Close()
		_ = n.Close()
	})
	return &e2eWorld{t: t, n: n, server: server, c: c}
}

// punch runs one session between hosts[0] (initiator) and hosts[1] and
// returns the coordinator's result and both clients' sessions.
func (w *e2eWorld) punch(hosts [2]*nattest.Host, mappers [2]holepunch.PortMapper) (coord.Result, [2]*holepunch.Session) {
	w.t.Helper()
	return w.punchWith(coord.SessionOptions{}, hosts, mappers)
}

// punchWith is punch with the session's options.
func (w *e2eWorld) punchWith(opts coord.SessionOptions, hosts [2]*nattest.Host, mappers [2]holepunch.PortMapper) (coord.Result, [2]*holepunch.Session) {
	t := w.t
	t.Helper()
	s, err := w.c.NewSession(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var (
		wg    sync.WaitGroup
		sess  [2]*holepunch.Session
		errs  [2]error
		pipes []net.Conn
	)
	for i, role := range []protocol.Role{protocol.RoleInitiator, protocol.RoleResponder} {
		cli, srv := w.n.Pipe(nattest.PipeConfig{A: hosts[i], B: w.server, DelayAB: 5 * time.Millisecond, DelayBA: 5 * time.Millisecond})
		pipes = append(pipes, cli, srv)
		if err := s.Attach(role, srv, coord.AttachOptions{Security: protocol.ControlSecurityInsecureForTesting}); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess[i], errs[i] = holepunch.Punch(ctx, cli, holepunch.Options{ControlSecurity: protocol.ControlSecurityInsecureForTesting,
				Network: hosts[i], TransportMode: "quic", PortMapper: mappers[i]})
		}()
	}
	wg.Wait()
	select {
	case <-s.Done():
	case <-ctx.Done():
		t.Fatalf("session not done: %+v", s.Snapshot())
	}
	for _, p := range pipes {
		_ = p.Close()
	}
	t.Cleanup(func() {
		for _, x := range sess {
			if x != nil {
				_ = x.Close()
			}
		}
	})
	res, _ := s.Result()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("client %d: %v (coordinator: %s %s)", i, err, res.Reason, res.Detail)
		}
		if d := sess[i].Diagnostics(); d.Counters.TargetRejected != 0 {
			t.Errorf("client %d refused %d targets of the plans (warn %v)", i, d.Counters.TargetRejected, d.Warn)
		}
	}
	if res.Outcome != coord.OutcomeSucceeded {
		t.Fatalf("coordinator result %+v", res)
	}
	return res, sess
}

// TestE2EUnverifiedFamily: the server observes IPv4 only; both
// hosts sit behind symmetric IPv4 NATs and have global IPv6 addresses
// behind stateful firewalls. IPv6 runs unverified, Direct to the addresses
// the clients reported, and connects.
func TestE2EUnverifiedFamily(t *testing.T) {
	t.Parallel()
	w := newE2E(t)
	cfg := nattest.SymmetricRandom()
	cfg.IPv6 = &nattest.IPv6Config{Mode: nattest.NoNAT, Firewall: nattest.APDF}
	hosts := [2]*nattest.Host{w.n.NAT(cfg).Host(), w.n.NAT(cfg).Host()}
	res, sess := w.punch(hosts, [2]holepunch.PortMapper{})
	for i, s := range sess {
		if got := s.Result(); got.Path.Family != protocol.FamilyUDP6 || !slices.Contains(hosts[1-i].Addrs(), got.Path.RemoteAddr.Addr()) {
			t.Fatalf("client %d connected %s to %v", i, got.Path.Family, got.Path.RemoteAddr)
		}
	}
	if !slices.Contains(res.Warn, protocol.WarnUnverifiedTargets) {
		t.Fatalf("warn %v", res.Warn)
	}
}

// TestE2ESameLAN: two hosts on one LAN behind a NAT without
// hairpin. Only the LAN stage can connect them.
func TestE2ESameLAN(t *testing.T) {
	t.Parallel()
	w := newE2E(t)
	lan := w.n.NAT(nattest.PortRestricted())
	hosts := [2]*nattest.Host{lan.Host(), lan.Host()}
	_, sess := w.punch(hosts, [2]holepunch.PortMapper{})
	for i, s := range sess {
		if got := s.Result().Path.RemoteAddr.Addr(); !slices.Contains(hosts[1-i].Addrs(), got) {
			t.Fatalf("client %d connected to %v, want the peer's LAN address %v", i, got, hosts[1-i].Addrs())
		}
	}
}

// upstreamMapper is the port mapper of a home router behind a carrier NAT:
// it reports the router's mapping of the socket, an address in the carrier's
// shared address space.
type upstreamMapper struct{ home *nattest.NAT }

func (m upstreamMapper) Map(ctx context.Context, conn net.PacketConn, _ protocol.PortMappingPolicy) (protocol.PortMappingInfo, func() error, error) {
	port := conn.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	for {
		for _, mp := range m.home.Mappings() {
			if mp.Internal.Port() == port {
				return protocol.PortMappingInfo{Method: protocol.PortMapUPnP, External: mp.External, Internal: mp.Internal, Lease: time.Hour},
					func() error { return nil }, nil
			}
		}
		select {
		case <-ctx.Done():
			return protocol.PortMappingInfo{}, nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestE2EUpstreamLAN: two homes on different LANs behind one
// carrier NAT without hairpin. The coordinator pushes each home router's
// mapping in the carrier network as peer_targets{source: portmap}, with
// room in the round's grant; the clients send to them and connect there.
func TestE2EUpstreamLAN(t *testing.T) {
	t.Parallel()
	w := newE2E(t)
	cg := nattest.CGNAT(nattest.PortRestricted(), nattest.FullCone())
	carrier := w.n.NAT(cg[0])
	homes := [2]*nattest.NAT{carrier.NAT(cg[1]), carrier.NAT(cg[1])}
	hosts := [2]*nattest.Host{homes[0].Host(), homes[1].Host()}
	res, sess := w.punch(hosts, [2]holepunch.PortMapper{upstreamMapper{homes[0]}, upstreamMapper{homes[1]}})
	for i, s := range sess {
		got := s.Result().Path.RemoteAddr
		if !slices.ContainsFunc(homes[1-i].Mappings(), func(m nattest.MappingInfo) bool { return m.External == got }) {
			t.Fatalf("client %d connected to %v, not to the peer's upstream-LAN candidate", i, got)
		}
	}
	if res.Counters.PeerTargets < 2 {
		t.Fatalf("counters %+v", res.Counters)
	}
}

// rebindPair runs a session between a host behind a port-restricted NAT
// (initiator) and one behind a full-cone NAT (responder) whose NAT changes
// its external IP when on sees the event it waits for. It checks that the
// port-restricted side connected to the new IP,
// after the coordinator pushed the new mapping as peer_targets{source:
// drift}, and returns the round that confirmed.
func rebindPair(t *testing.T, maxRounds uint8, on func(ev coord.Event, fc *nattest.NAT)) int {
	t.Helper()
	var (
		fc     atomic.Pointer[nattest.NAT]
		mu     sync.Mutex
		pushed []coord.PeerTargetsData
	)
	w := newE2E(t, func(c *coord.Config) {
		c.Timeouts.MaxRounds = maxRounds
		c.Observer = func(ev coord.Event) {
			if n := fc.Load(); n != nil {
				on(ev, n)
			}
			if d, ok := ev.Data.(coord.PeerTargetsData); ok && ev.Kind == coord.EvPeerTargets {
				mu.Lock()
				pushed = append(pushed, d)
				mu.Unlock()
			}
		}
	})
	n := w.n.NAT(nattest.FullCone())
	before := n.ExternalIPs()
	fc.Store(n)
	hosts := [2]*nattest.Host{w.n.NAT(nattest.PortRestricted()).Host(), n.Host()}
	res, sess := w.punch(hosts, [2]holepunch.PortMapper{})
	after := n.ExternalIPs()
	if slices.Equal(before, after) {
		t.Fatalf("the NAT kept its external IPs %v", after)
	}
	if got := sess[0].Result().Path.RemoteAddr.Addr(); !slices.Contains(after, got) {
		t.Fatalf("initiator connected to %v, want the full-cone NAT's new IP %v", got, after)
	}
	mu.Lock()
	defer mu.Unlock()
	drift := slices.ContainsFunc(pushed, func(d coord.PeerTargetsData) bool {
		return d.Source == protocol.TargetsDrift && len(d.Targets) == 1 && slices.Contains(after, d.Targets[0].Addr())
	})
	if !drift {
		t.Fatalf("no peer_targets{drift} to the new IP: %+v", pushed)
	}
	return res.Winner.Round
}

// TestE2ERebindBeforeGo (the e2e cell rebind/PRC-FC): the full-cone
// side's NAT changes its external IP once the summaries are out, before the
// first go, with two rounds as in the e2e suite. In round 1 each side aims
// at a dead or filtered address; halfway through it the full-cone side
// re-observes its primary mapping and reports the new one with the ack's
// cookie, the coordinator verifies it and pushes it with round 2's go, and
// round 2 connects on the new IP.
func TestE2ERebindBeforeGo(t *testing.T) {
	t.Parallel()
	var once sync.Once
	round := rebindPair(t, 2, func(ev coord.Event, fc *nattest.NAT) {
		if ev.Kind == coord.EvPlanned {
			once.Do(func() { fc.Rebind(nil) })
		}
	})
	if round != 2 {
		t.Fatalf("confirmed in round %d, want 2", round)
	}
}

// TestE2ERebindWhilePunching: the full-cone side's uplink fails as
// round 1 starts and comes back with a new external IP once round 1 ended,
// as after a WAN reconnect. Round 2 runs on the new mapping, which the
// port-restricted side filters; its re-observation reveals the mapping and
// round 3 connects.
func TestE2ERebindWhilePunching(t *testing.T) {
	t.Parallel()
	var down, up sync.Once
	round := rebindPair(t, 3, func(ev coord.Event, fc *nattest.NAT) {
		switch {
		case ev.Kind == coord.EvGo && ev.Round == 1:
			down.Do(func() { fc.Blackhole(time.Hour) })
		case ev.Kind == coord.EvRoundEnded && ev.Round == 1:
			up.Do(func() {
				fc.Blackhole(0)
				fc.Rebind(nil)
			})
		}
	})
	if round != 3 {
		t.Fatalf("confirmed in round %d, want 3", round)
	}
}

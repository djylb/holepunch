package coord

import (
	"net/netip"
	"testing"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// early is rep as a warm client sends it before probing ends: the rows,
// no traits and no port mapping.
func early(rep protocol.ProbeReport) *protocol.ProbeReport {
	e := rep
	e.Early = true
	e.Families = nil
	for _, fr := range rep.Families {
		fr.Traits, fr.PortMap = protocol.Traits{Family: fr.Family}, nil
		e.Families = append(e.Families, fr)
	}
	return &e
}

// TestWarmStates: the side the traits memory knows is planned on its early
// report, the other one waits for its final report (cold), and planning
// starts when that comes; the warm side's final report, arriving after the
// summary, still brings its port mapping. A client not offered a warm start
// that sends an early report violates the protocol.
func TestWarmStates(t *testing.T) {
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
	hosts := [2]*nattest.Host{n.PublicHost(), n.PublicHost()}
	mem := natprobe.NewTraitsMemory(natprobe.TraitsMemoryConfig{})
	mem.Observe(natprobe.TraitsKey{ClientKey: "vis", Family: protocol.FamilyUDP4, PublicIP: hosts[0].Addrs()[0], LocalIP: hosts[0].Addrs()[0]},
		protocol.Traits{Family: protocol.FamilyUDP4, Mapping: protocol.MapEIM, MappingConf: protocol.ConfHigh, CrossIP: true,
			PortAlloc: protocol.AllocPreserving, PortAllocConf: protocol.ConfHigh}, true)
	r := newRig(t, withRegistry(reg), func(c *Config) {
		c.TraitsMemory = mem
		c.DefaultProbe = protocol.ProbeSpec{Observers: srv.Observers(protocol.FamilyUDP4)}
	})
	p := r.pair(SessionOptions{ClientKeys: [2]string{"vis", "prov"}})
	var reps [2]protocol.ProbeReport
	for i := range 2 {
		if !p.starts[i].Probe.Warm {
			t.Fatalf("side %d not offered a warm start", i)
		}
		reps[i] = newUDPClient(t, hosts[i], p.starts[i]).probeReport(p.starts[i])
		send(t, p.cl[i], early(reps[i]))
	}
	testkit.WaitFor(t, "the responder found cold", func() bool {
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		return p.s.st.plan.warm[1] == WarmCold && !p.s.st.plan.planning
	})
	p.s.mu.Lock()
	planned := p.s.st.plan.planned
	p.s.mu.Unlock()
	if planned {
		t.Fatal("planned before the cold side's final report")
	}
	send(t, p.cl[1], &reps[1])
	for i := range 2 {
		expect[protocol.ProbeSummary](t, p.cl[i])
	}
	final := reps[0]
	final.Families[0].PortMap = &protocol.PortMapReport{Method: protocol.PortMapUPnP,
		External: netip.AddrPortFrom(hosts[0].Addrs()[0], 41000), Internal: final.Families[0].Sockets[0].Local, LeaseSeconds: 60}
	send(t, p.cl[0], &final)
	testkit.WaitFor(t, "the late mapping queued", func() bool {
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		return len(p.s.st.rounds.portmap[1]) == 1
	})
	p.s.Abort(protocol.ReasonCanceled, "")
	if res := r.wait(p.s); res.Warm != [2]WarmStart{WarmHit, WarmCold} {
		t.Fatalf("warm %v", res.Warm)
	}

	cold := newRig(t)
	q := cold.pair(SessionOptions{})
	rep := simclient.Report(*q.starts[0], 5, "quic", fam(0, simclient.OpenTraits))
	rep.Early = true
	send(t, q.cl[0], rep)
	if res := cold.wait(q.s); res.Reason != protocol.ReasonProtocolViolation || res.Warm != [2]WarmStart{WarmOff, WarmOff} {
		t.Fatalf("an early report not asked for: %+v", res)
	}
}

package probe

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/stun"
)

const ms = time.Millisecond

// checkReport asserts that the result makes a valid probe_report.
func checkReport(t *testing.T, r Result) {
	t.Helper()
	fr := r.Table.Snapshot()
	fr.Traits = r.Traits
	fr.Failure = r.Failure
	rep := protocol.ProbeReport{SessionID: "s1", Role: protocol.RoleInitiator, Control: protocol.DefaultControlSpec(),
		Families: []protocol.FamilyReport{fr}, Clock: r.Clock, Transport: protocol.Transport{Mode: "quic"}}
	if err := rep.Validate(); err != nil {
		t.Fatalf("report invalid: %v", err)
	}
}

func serverSends(c Counters) int {
	return int(c.Primary) + int(c.TopUp) + int(c.Second) + int(c.Sibling) + int(c.Alt)
}

// EIM, not PDF, no loss: DONE within 1 RTT + 10 ms, one probe per observer.
func TestEIMNotPDF(t *testing.T) {
	o := defaultOpts()
	o.nat.filtering = protocol.FiltADF
	s := newSim(t, o)
	r := s.stepRun()
	if r.Failure != "" || s.now > o.rtt+10*ms {
		t.Fatalf("failure %q at %v", r.Failure, s.now)
	}
	tr := r.Traits
	if tr.Mapping != protocol.MapEIM || tr.MappingConf != protocol.ConfMedium || tr.Filtering != protocol.FiltNotPDF ||
		tr.FilteringConf != protocol.ConfHigh || tr.Samples != 3 || !tr.Provisional || tr.Observed != netip.MustParseAddrPort("203.0.113.5:40000") ||
		tr.PortAlloc != protocol.AllocPreserving {
		t.Fatalf("traits %+v", tr)
	}
	if r.Sent.Primary != 3 || serverSends(r.Sent) != 3 || r.Sent.Rejected != 0 || r.Sent.SendErrors != 0 {
		t.Fatalf("sent %+v", r.Sent)
	}
	if r.Clock.RTTMs != 40 {
		t.Fatalf("clock %+v", r.Clock)
	}
	checkReport(t, r)
	for _, row := range r.Table.Snapshot().Sockets[0].Rows {
		if row.Cookie == 0 || row.RTTMs != 40 || !row.Observed.IsValid() {
			t.Fatalf("row %+v", row)
		}
	}
}

// An answer read at the instant of its probe (an RTT below the clock's
// resolution, as on Windows over loopback) is the smallest sample, not a
// missing one: RTTMs is 1, never 0.
func TestRTTBelowClockResolution(t *testing.T) {
	o := defaultOpts()
	o.rtt = 0
	s := newSim(t, o)
	r := s.stepRun()
	if r.Failure != "" || r.Clock.RTTMs != 1 {
		t.Fatalf("failure %q clock %+v", r.Failure, r.Clock)
	}
	checkReport(t, r)
}

// The responder role works the same; its probes carry its role.
func TestResponderRole(t *testing.T) {
	o := defaultOpts()
	o.role = udpwire.RoleResponder
	s := newSim(t, o)
	if s.p.role != udpwire.RoleResponder {
		t.Fatalf("role %v", s.p.role)
	}
	if r := s.stepRun(); r.Failure != "" || r.Traits.Samples != 3 {
		t.Fatalf("result %+v", r)
	}
}

// PDF: DONE ≤ RTT + extraWait + 10 ms, ≤ 4 probes, PDF/High.
func TestPDF(t *testing.T) {
	o := defaultOpts()
	o.nat.filtering = protocol.FiltPDF
	s := newSim(t, o)
	r := s.stepRun()
	if r.Failure != "" || s.now > o.rtt+80*ms+10*ms {
		t.Fatalf("failure %q at %v", r.Failure, s.now)
	}
	if r.Traits.Filtering != protocol.FiltPDF || r.Traits.FilteringConf != protocol.ConfHigh || r.Traits.Mapping != protocol.MapEIM {
		t.Fatalf("traits %+v", r.Traits)
	}
	if serverSends(r.Sent) > 4 {
		t.Fatalf("sent %+v", r.Sent)
	}
	checkReport(t, r)
}

// APDM sequential with background allocations: the second socket,
// Sequential/High, ≤ 7 probes, done within 3.5 RTT. The velocity spans the
// round trip between the two sockets' probes: within 30% over a 120 ms
// RTT, none over a 40 ms one, which a single foreign mapping would read as
// tens of ports a second.
func TestAPDMSequentialVelocity(t *testing.T) {
	for _, c := range []struct {
		rtt      time.Duration
		velocity float64
	}{{120 * ms, 50}, {40 * ms, 0}} {
		o := defaultOpts()
		o.rtt = c.rtt
		o.nat = natCfg{mapping: protocol.MapAPDM, alloc: "seq", step: 1, velocity: 50, filtering: protocol.FiltPDF}
		s := newSim(t, o)
		r := s.stepRun()
		tr := r.Traits
		if r.Failure != "" || tr.Mapping != protocol.MapAPDM || tr.MappingConf != protocol.ConfHigh ||
			tr.PortAlloc != protocol.AllocSequential || tr.PortAllocConf != protocol.ConfHigh || tr.PortStep != 1 {
			t.Fatalf("rtt %v: traits %+v", c.rtt, tr)
		}
		if math.Abs(float64(tr.PortVelocity)-c.velocity) > c.velocity*0.3 {
			t.Fatalf("rtt %v: velocity %v, want %v±30%%", c.rtt, tr.PortVelocity, c.velocity)
		}
		if r.Sent.Second != 3 || serverSends(r.Sent) > 7 {
			t.Fatalf("rtt %v: sent %+v", c.rtt, r.Sent)
		}
		if s.now > o.rtt*7/2 {
			t.Fatalf("rtt %v: done at %v", c.rtt, s.now)
		}
		if !tr.Predictable() {
			t.Fatal("not predictable")
		}
		socks := r.Table.Sockets()
		if len(socks) != 2 || socks[1].Kind != protocol.SocketSecond {
			t.Fatalf("sockets %+v", socks)
		}
		checkReport(t, r)
	}

	// a negative step
	o := defaultOpts()
	o.nat = natCfg{mapping: protocol.MapAPDM, alloc: "seq", step: -2, filtering: protocol.FiltPDF, base: 60000}
	r := newSim(t, o).stepRun()
	if r.Traits.PortAlloc != protocol.AllocSequential || r.Traits.PortStep != -2 || r.Traits.PortAnchor != 60000-2*6 {
		t.Fatalf("traits %+v", r.Traits)
	}
	// random allocation
	o.nat = natCfg{mapping: protocol.MapAPDM, alloc: "random", filtering: protocol.FiltPDF}
	r = newSim(t, o).stepRun()
	if r.Traits.Mapping != protocol.MapAPDM || r.Traits.PortAlloc != protocol.AllocRandom || r.Traits.PortAllocConf != protocol.ConfHigh {
		t.Fatalf("traits %+v", r.Traits)
	}
	// the second socket disabled
	o.second = false
	r = newSim(t, o).stepRun()
	if r.Sent.Second != 0 || r.Traits.PortAlloc != protocol.AllocRandom || r.Traits.PortAllocConf != protocol.ConfLow {
		t.Fatalf("traits %+v sent %+v", r.Traits, r.Sent)
	}
}

// A second socket the runtime cannot open, or opens wrongly, is skipped.
func TestSecondSocketFailures(t *testing.T) {
	o := defaultOpts()
	o.nat = natCfg{mapping: protocol.MapAPDM, alloc: "seq", step: 1, filtering: protocol.FiltPDF}
	for name, open := range map[string]func(*sim) (SocketHandle, error){
		"error": func(*sim) (SocketHandle, error) { return nil, errors.New("bind failed") },
		"panic": func(*sim) (SocketHandle, error) { panic("open") },
		"wrong id": func(s *sim) (SocketHandle, error) {
			return s.sock(nat.SocketID(protocol.FamilyUDP4, 7), "192.168.1.10:40007"), nil
		},
		"typed nil": func(*sim) (SocketHandle, error) { return (*simSock)(nil), nil },
	} {
		s := newSim(t, o)
		s.p = New(s.spec, s.socks[0], nil, func() (SocketHandle, error) { return open(s) })
		r := s.stepRun()
		if r.Failure != "" || r.Sent.Second != 0 || r.Traits.Mapping != protocol.MapAPDM || len(r.Table.Sockets()) != 1 {
			t.Fatalf("%s: %+v", name, r)
		}
	}
}

// 20% random loss, 100 runs.
func TestLossy(t *testing.T) {
	unknown := 0
	for seed := range uint64(100) {
		o := defaultOpts()
		o.loss = 0.2
		o.seed = seed + 1
		o.nat.filtering = protocol.FiltPDF
		s := newSim(t, o)
		r := s.stepRun()
		if s.now > defaultTimeout {
			t.Fatalf("seed %d: ended at %v", seed, s.now)
		}
		if r.Traits.Mapping == protocol.MapUnknown {
			unknown++
		}
		if r.Sent.Primary > 12 || r.Sent.TopUp > 1 || serverSends(r.Sent) > serverBudget {
			t.Fatalf("seed %d: sent %+v", seed, r.Sent)
		}
		checkReport(t, r)
	}
	if unknown > 1 {
		t.Fatalf("%d/100 runs without a mapping conclusion", unknown)
	}
}

// An unreachable server: probe_timeout at the deadline, 4 probes per observer.
func TestUnreachable(t *testing.T) {
	s := newSim(t, defaultOpts())
	s.unreachable = true
	r := s.stepRun()
	if r.Failure != protocol.ReasonProbeTimeout || s.now != defaultTimeout {
		t.Fatalf("failure %q at %v", r.Failure, s.now)
	}
	if r.Sent.Primary != 12 || r.Traits.Samples != 0 {
		t.Fatalf("sent %+v traits %+v", r.Sent, r.Traits)
	}
	checkReport(t, r)
	// with rtt_hint_ms the schedule is shorter, the hard limit the same
	o := defaultOpts()
	o.rttHint = 30
	o.timeout = 700 * ms
	s = newSim(t, o)
	s.unreachable = true
	if r := s.stepRun(); r.Failure != protocol.ReasonProbeTimeout || s.now != 700*ms {
		t.Fatalf("failure %q at %v", r.Failure, s.now)
	}
	// limits: a timeout below 500 ms is raised, an absurd hint is capped
	o.timeout, o.rttHint = 100*ms, 60000
	s = newSim(t, o)
	s.unreachable = true
	if r := s.stepRun(); r.Failure != protocol.ReasonProbeTimeout || s.now != minTimeout || r.Sent.Primary != 6 {
		t.Fatalf("failure %q at %v, sent %+v", r.Failure, s.now, r.Sent)
	}
}

// Every send fails → udp_blocked within 3·T1.
func TestSendFailures(t *testing.T) {
	s := newSim(t, defaultOpts())
	s.writeErr = func(uint8, netip.AddrPort) error { return syscall.EPERM }
	r := s.stepRun()
	t1 := 170 * ms
	if r.Failure != protocol.ReasonUDPBlocked || r.Detail != "send_failed" || s.now > 3*t1 {
		t.Fatalf("failure %q/%q at %v", r.Failure, r.Detail, s.now)
	}
	// only observer 1 fails: the others still answer
	s = newSim(t, defaultOpts())
	bad := netip.AddrPortFrom(srvIP, 3479)
	s.writeErr = func(_ uint8, to netip.AddrPort) error {
		if to == bad {
			return syscall.EPERM
		}
		return nil
	}
	r = s.stepRun()
	if r.Failure != "" || r.Traits.Samples != 2 || r.Traits.Mapping != protocol.MapEIM || r.Sent.SendErrors == 0 {
		t.Fatalf("result %+v", r)
	}
	// failures that stop before the second round: udp_blocked at the deadline
	o := defaultOpts()
	o.ports = 1
	s = newSim(t, o)
	fails := 0
	s.writeErr = func(uint8, netip.AddrPort) error {
		if fails++; fails == 1 {
			return syscall.ENETUNREACH
		}
		return nil
	}
	s.unreachable = true
	if r := s.stepRun(); r.Failure != protocol.ReasonUDPBlocked || r.Detail != "send_failed" || s.now != defaultTimeout {
		t.Fatalf("result %+v at %v", r, s.now)
	}
}

func TestICMPUnreachable(t *testing.T) {
	s := newSim(t, defaultOpts())
	s.unreachable, s.icmp = true, true
	r := s.stepRun()
	if r.Failure != protocol.ReasonUDPBlocked || r.Detail != "icmp_unreachable" || s.now > 300*ms {
		t.Fatalf("failure %q/%q at %v", r.Failure, r.Detail, s.now)
	}
	if r.Sent.ICMP == 0 {
		t.Fatalf("sent %+v", r.Sent)
	}
}

// With an alt group the unsolicited change-IP test comes first.
func TestAltGroupEIFAndADF(t *testing.T) {
	o := defaultOpts()
	o.alt = true
	s := newSim(t, o)
	r := s.stepRun()
	if r.Traits.Filtering != protocol.FiltEIF || r.Traits.FilteringConf != protocol.ConfHigh ||
		r.Traits.Mapping != protocol.MapEIM || r.Traits.MappingConf != protocol.ConfHigh || !r.Traits.CrossIP {
		t.Fatalf("EIF traits %+v", r.Traits)
	}
	firstAlt := s.sentTo(altIP)
	if len(firstAlt) == 0 || firstAlt[0].at < o.rtt || r.Sent.Alt != 1 {
		t.Fatalf("solicited alt probe %v, sent %+v", firstAlt, r.Sent)
	}
	checkReport(t, r)

	o.nat.filtering = protocol.FiltADF
	s = newSim(t, o)
	r = s.stepRun()
	if r.Traits.Filtering != protocol.FiltADF || r.Traits.FilteringConf != protocol.ConfMedium {
		t.Fatalf("ADF traits %+v", r.Traits)
	}
	firstAlt = s.sentTo(altIP)
	if len(firstAlt) == 0 || firstAlt[0].at < o.rtt+80*ms {
		t.Fatalf("the alt IP was contacted before the unsolicited test settled: %v", firstAlt)
	}
	checkReport(t, r)

	// the server's alt quota is spent: no declaration, the solicited probe still goes
	s = newSim(t, o)
	s.altLeft = 0
	r = s.stepRun()
	if r.Sent.Alt != 1 || r.Traits.Filtering != protocol.FiltNotPDF {
		t.Fatalf("no alt quota: traits %+v sent %+v", r.Traits, r.Sent)
	}
	// the solicited alt probes fail: done 2·T1 after the first, without cross-IP evidence
	o.nat.filtering = protocol.FiltEIF
	s = newSim(t, o)
	s.writeErr = func(_ uint8, to netip.AddrPort) error {
		if to.Addr() == altIP {
			return syscall.EPERM
		}
		return nil
	}
	r = s.stepRun()
	if r.Failure != "" || r.Sent.SendErrors != 2 || r.Traits.Filtering != protocol.FiltEIF || r.Traits.MappingConf != protocol.ConfMedium {
		t.Fatalf("failed alt probes: %+v", r)
	}
}

// Exactly one extra declaration: the prober tops up observer 0 once.
func TestTopUp(t *testing.T) {
	o := defaultOpts()
	o.ports, o.alt = 2, true
	o.nat.filtering = protocol.FiltPDF
	s := newSim(t, o)
	r := s.stepRun()
	if r.Sent.TopUp != 1 || r.Traits.Filtering != protocol.FiltPDF || r.Traits.FilteringConf != protocol.ConfHigh {
		t.Fatalf("traits %+v sent %+v", r.Traits, r.Sent)
	}
	// the server is out of extra quota: no top-up, filtering from one declaration
	s = newSim(t, o)
	s.extraLeft = 1
	r = s.stepRun()
	if r.Sent.TopUp != 0 || r.Traits.Filtering != protocol.FiltPDF || r.Traits.FilteringConf != protocol.ConfMedium {
		t.Fatalf("quota: traits %+v sent %+v", r.Traits, r.Sent)
	}
}

// QUOTA_EXHAUSTED on the ack of a WANT_ALT probe is the alt
// quota. With the default alt quota (2), losing observer 0's first ack makes
// its retransmission take the last alt, and that ack carries FC while every
// extra is still available: the top-up must still go out, so a single extra
// declaration never decides PDF on its own.
func TestAltQuotaDoesNotStopTopUp(t *testing.T) {
	o := defaultOpts()
	o.ports, o.alt = 2, true
	o.nat.filtering = protocol.FiltPDF
	s := newSim(t, o)
	dropped := false
	r := s.stepRunHook(func(now time.Duration) {
		// at owd the server has answered both probes; the first reply it
		// scheduled is observer 0's ack
		if !dropped && now == o.rtt/2 {
			dropped = s.dropFirstEventAt(o.rtt)
		}
	})
	if !dropped || s.altLeft != 0 {
		t.Fatalf("setup: ack dropped %v, alt quota left %d", dropped, s.altLeft)
	}
	if r.Sent.TopUp != 1 {
		t.Fatalf("no top-up with %d extras left: sent %+v", s.extraLeft, r.Sent)
	}
	if r.Traits.Filtering != protocol.FiltPDF || r.Traits.FilteringConf != protocol.ConfHigh {
		t.Fatalf("filtering %v/%v, want pdf/high from two declarations", r.Traits.Filtering, r.Traits.FilteringConf)
	}
}

// EIF needs an alt reply received before anything was sent
// to the alt IP. The late copy of the unsolicited alt reply, arriving after
// the solicited probe opened an ADF filter, is no evidence.
func TestLateAltAfterSolicitedIsNotEIF(t *testing.T) {
	o := defaultOpts()
	o.alt = true
	s := newSim(t, o)
	rs := newRunState(s.p)
	rs.step(0) // SEND0
	at := func(d time.Duration) time.Time { return s.start.Add(d) }
	pub := netip.MustParseAddrPort("203.0.113.5:40000")
	var rec0 *probeRec
	for _, r := range rs.recs {
		rs.handle(inbound{sock: r.tg.sockID, from: r.tg.obs.Addr, h: udpwire.Header{Type: udpwire.TProbeAck, Role: udpwire.RoleServer,
			Sock: r.tg.sockID, Aux: uint16(r.tg.obs.ID), Seq: 100 + r.seq, EchoSeq: r.seq, EchoTS: r.ts,
			FB: r.want == wantAlt}, t: udpwire.TLVs{Observed: pub, Cookie: 7}, at: at(40 * ms)})
		if r.want == wantAlt {
			rec0 = r
		}
	}
	if rec0 == nil || !rec0.altDeclared {
		t.Fatal("setup: no alt declaration")
	}
	// the declared alt reply is waited out (ADF drops it), then the solicited
	// probe goes to the alt IP
	now := 40*ms + rs.extraWait()
	rs.step(now)
	if len(rs.altTgts) == 0 || rs.altTgts[0].sends == 0 {
		t.Fatal("setup: no solicited alt probe")
	}
	late := inbound{sock: rec0.tg.sockID, from: netip.AddrPortFrom(altIP, 41999), h: udpwire.Header{Type: udpwire.TProbeAlt,
		Role: udpwire.RoleServer, Sock: rec0.tg.sockID, Aux: uint16(rec0.tg.obs.ID), Seq: 999, EchoSeq: rec0.seq, EchoTS: rec0.ts},
		t: udpwire.TLVs{Observed: pub}, at: at(now + 5*ms)}
	rs.handle(late)
	if tr := rs.table.Classify(); tr.Filtering == protocol.FiltEIF {
		t.Fatalf("a late alt reply made the filtering %v/%v", tr.Filtering, tr.FilteringConf)
	}

	// The same reply before the alt IP was contacted is EIF evidence.
	s = newSim(t, o)
	rs = newRunState(s.p)
	rs.step(0)
	for _, r := range rs.recs {
		if r.want == wantAlt {
			rs.handle(inbound{sock: r.tg.sockID, from: netip.AddrPortFrom(altIP, 41999), h: udpwire.Header{Type: udpwire.TProbeAlt,
				Role: udpwire.RoleServer, Sock: r.tg.sockID, Aux: uint16(r.tg.obs.ID), Seq: 999, EchoSeq: r.seq, EchoTS: r.ts},
				t: udpwire.TLVs{Observed: pub}, at: at(30 * ms)})
		}
		rs.handle(inbound{sock: r.tg.sockID, from: r.tg.obs.Addr, h: udpwire.Header{Type: udpwire.TProbeAck, Role: udpwire.RoleServer,
			Sock: r.tg.sockID, Aux: uint16(r.tg.obs.ID), Seq: 100 + r.seq, EchoSeq: r.seq, EchoTS: r.ts,
			FB: r.want == wantAlt}, t: udpwire.TLVs{Observed: pub, Cookie: 7}, at: at(40 * ms)})
	}
	if tr := rs.table.Classify(); tr.Filtering != protocol.FiltEIF {
		t.Fatalf("an unsolicited alt reply: filtering %v/%v, want eif", tr.Filtering, tr.FilteringConf)
	}
}

// ICMP unreachable caused by a dead STUN server on the primary socket
// is no evidence against the natprobe observers. A reachable server whose RTT
// exceeds T1 (no rtt_hint) must not fail as udp_blocked before its first ack
// (udp_blocked needs every observer silent and ICMP).
func TestSTUNICMPDoesNotFailReachableServer(t *testing.T) {
	o := defaultOpts()
	o.rtt = 400 * ms
	o.stun = true
	s := newSim(t, o)
	s.stunOn = false // the STUN host answers with ICMP port unreachable
	s.writeErr = func(sock uint8, to netip.AddrPort) error {
		if to == stunAddr {
			s.schedule(20*ms, func() { s.noteICMP(sock) }) // write holds mu
		}
		return nil
	}
	r := s.stepRun()
	if r.Failure != "" || r.Traits.Samples != 3 {
		t.Fatalf("reachable server (RTT %v) failed as %v/%v at %v (samples %d)", o.rtt, r.Failure, r.Detail, s.now, r.Traits.Samples)
	}
	if r.Sent.ICMP == 0 {
		t.Fatal("setup: no ICMP note")
	}

	// A LAN observer probed from the primary socket is no main observer either.
	o = defaultOpts()
	o.rtt = 400 * ms
	s = newSim(t, o)
	lan := netip.MustParseAddrPort("10.0.0.1:3478")
	s.observers = append(s.observers, protocol.ObserverSpec{ID: 16, Addr: lan, Group: 2})
	s.spec.Probe.Observers = s.observers
	s.p = New(s.spec, s.socks[0], nil, nil)
	s.writeErr = func(sock uint8, to netip.AddrPort) error {
		if to == lan {
			s.schedule(20*ms, func() { s.noteICMP(sock) })
			s.schedule(200*ms, func() { s.noteICMP(sock) })
		}
		return nil
	}
	if r := s.stepRun(); r.Failure != "" {
		t.Fatalf("LAN-observer ICMP failed a reachable server: %v/%v at %v", r.Failure, r.Detail, s.now)
	}
}

// A server without extra replies: filtering unknown, no waiting.
func TestNoExtraReply(t *testing.T) {
	o := defaultOpts()
	s := newSim(t, o)
	s.extraReply = false
	r := s.stepRun()
	if r.Traits.Filtering != protocol.FiltUnknown || s.now > o.rtt+10*ms {
		t.Fatalf("traits %+v at %v", r.Traits, s.now)
	}
	o.extraReply = false // the hint: no WANT_EXTRA at all
	s = newSim(t, o)
	r = s.stepRun()
	if r.Traits.Filtering != protocol.FiltUnknown || s.now > o.rtt+10*ms {
		t.Fatalf("traits %+v at %v", r.Traits, s.now)
	}
}

func TestExtraBeforeAck(t *testing.T) {
	s := newSim(t, defaultOpts())
	s.extraFirst = true
	r := s.stepRun()
	if r.Traits.Filtering != protocol.FiltNotPDF {
		t.Fatalf("traits %+v", r.Traits)
	}
}

func TestSTUNSubProbe(t *testing.T) {
	o := defaultOpts()
	o.stun = true
	s := newSim(t, o)
	r := s.stepRun()
	// an agreeing STUN answer is a hint: natprobe's single IP stays Medium
	if r.Sent.STUN != 1 || r.Traits.MappingConf != protocol.ConfMedium || r.Traits.CrossIP {
		t.Fatalf("traits %+v sent %+v", r.Traits, r.Sent)
	}
	fr := r.Table.Snapshot()
	if len(fr.STUN) != 1 || fr.STUN[0].Observed != netip.MustParseAddrPort("203.0.113.5:40000") {
		t.Fatalf("stun rows %+v", fr.STUN)
	}
	// an unreachable STUN server holds probing back at most until mappingDone + 150 ms
	s = newSim(t, o)
	s.stunOn = false
	r = s.stepRun()
	if s.now > o.rtt+stunGrace+ms || r.Sent.STUN != 2 {
		t.Fatalf("done at %v, sent %+v", s.now, r.Sent)
	}
	// an answer of the wrong family is ignored and the report stays valid
	s = newSim(t, o)
	s.stunWrongV6 = true
	r = s.stepRun()
	if len(r.Table.Snapshot().STUN) != 0 || r.Traits.MappingConf != protocol.ConfMedium {
		t.Fatalf("v6 STUN answer used: %+v", r.Traits)
	}
	checkReport(t, r)
	// STUN servers of the other family, without port or beyond eight are skipped
	o.stun = false
	s = newSim(t, o)
	s.spec.Probe.STUN = []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:3478"), netip.MustParseAddrPort("192.0.2.9:0"), stunAddr}
	for i := range protocol.MaxReportSTUNRows {
		s.spec.Probe.STUN = append(s.spec.Probe.STUN, netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(51 + i)}), 3478))
	}
	s.p = New(s.spec, s.socks[0], nil, nil)
	rs := newRunState(s.p)
	if len(rs.stun) != protocol.MaxReportSTUNRows || rs.stun[0].addr != stunAddr || rs.stun[0].idx != 2 || rs.stun[protocol.MaxReportSTUNRows-1].idx != protocol.MaxReportSTUNRows+1 {
		t.Fatalf("stun targets %+v", rs.stun)
	}
}

// Every STUN server of the family is asked at once, and silent ones hold
// probing back no longer than one silent server does; only a LAN-observed
// family, for which a STUN answer is the only public address, waits up to
// stunLANGrace for its first one.
func TestSTUNWaits(t *testing.T) {
	silent := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(60 + i)}), 3478)
	}
	many := []netip.AddrPort{stunAddr}
	for i := range protocol.MaxReportSTUNRows - 1 {
		many = append(many, silent(i))
	}
	lan := defaultOpts()
	lan.nat = natCfg{noNAT: true} // seen at 192.168.1.10 by public observers
	for _, c := range []struct {
		name     string
		o        simOpts
		servers  []netip.AddrPort
		delay    time.Duration // the answering server's delay; < 0 silent
		maxDone  time.Duration
		minDone  time.Duration
		rows     int
		lanTrait bool
	}{
		{"eight servers, seven silent", defaultOpts(), many, 0, 40*ms + stunGrace + ms, 0, 1, false},
		{"slow STUN, public client", defaultOpts(), many[:1], 600 * ms, 40*ms + stunGrace + ms, 0, 0, false},
		{"slow STUN, LAN-observed client", lan, many, 600 * ms, 600*ms + 5*ms, 600 * ms, 1, true},
		{"silent STUN, LAN-observed client", lan, many[1:], -1, 40*ms + stunLANGrace + ms, stunLANGrace, 0, true},
	} {
		s := newSim(t, c.o)
		s.stunOn, s.stunDelay = c.delay >= 0, max(c.delay, 0)
		s.spec.Probe.STUN = c.servers
		s.p = New(s.spec, s.socks[0], nil, nil)
		r := s.stepRun()
		if s.now > c.maxDone || s.now < c.minDone {
			t.Fatalf("%s: done at %v, want within [%v, %v]", c.name, s.now, c.minDone, c.maxDone)
		}
		if len(r.Table.Snapshot().STUN) != c.rows || r.Traits.LANObserved != c.lanTrait || int(r.Sent.STUN) < len(c.servers) {
			t.Fatalf("%s: stun rows %+v, traits %+v, sent %+v", c.name, r.Table.Snapshot().STUN, r.Traits, r.Sent)
		}
		checkReport(t, r)
	}
}

func TestSiblingsAndLANObserver(t *testing.T) {
	o := defaultOpts()
	o.siblings = 2
	s := newSim(t, o)
	s.observers = append(s.observers, protocol.ObserverSpec{ID: 16, Addr: netip.MustParseAddrPort("10.0.0.1:3478"), Group: 2})
	s.spec.Probe.Observers = s.observers
	s.p = New(s.spec, s.socks[0], []SocketHandle{s.socks[2], s.socks[3], s.socks[0]}, nil)
	r := s.stepRun()
	if r.Sent.Sibling != 2 || r.Sent.Primary != 4 || r.Traits.Samples != 3 || r.Traits.MultiHomed {
		t.Fatalf("traits %+v sent %+v", r.Traits, r.Sent)
	}
	if len(r.Table.Sockets()) != 3 {
		t.Fatalf("sockets %+v", r.Table.Sockets())
	}
	checkReport(t, r)
}

// An unavailable STUN server — writes failing, silent, answering
// with ICMP — changes neither the flow nor any conclusion: the traits are
// those of a run without STUN, and a family whose server is silent fails as
// probe_timeout, not as udp_blocked on the STUN server's account.
func TestSTUNUnavailable(t *testing.T) {
	plain := newSim(t, defaultOpts()).stepRun()
	o := defaultOpts()
	o.stun = true
	failing := func(s *sim) {
		s.writeErr = func(_ uint8, to netip.AddrPort) error {
			if to == stunAddr {
				return syscall.EHOSTUNREACH
			}
			return nil
		}
	}
	icmp := func(s *sim) {
		s.stunOn = false
		s.writeErr = func(sock uint8, to netip.AddrPort) error {
			if to == stunAddr {
				s.schedule(20*ms, func() { s.noteICMP(sock) }) // write holds mu
			}
			return nil
		}
	}
	silent := func(s *sim) { s.stunOn = false }
	for name, mut := range map[string]func(*sim){"failing": failing, "icmp": icmp, "silent": silent} {
		s := newSim(t, o)
		mut(s)
		r := s.stepRun()
		if r.Failure != "" || r.Traits != plain.Traits || r.Sent.SendErrors != 0 {
			t.Errorf("%s: %+v, without STUN %+v", name, r, plain.Traits)
		}
		if name == "failing" && r.Sent.STUNErrors != 2 {
			t.Errorf("failing: %+v", r.Sent)
		}

		s = newSim(t, o)
		mut(s)
		s.unreachable = true // the server is silent
		if r := s.stepRun(); r.Failure != protocol.ReasonProbeTimeout || r.Detail != "" || s.now != defaultTimeout {
			t.Errorf("%s, silent server: %v/%v at %v", name, r.Failure, r.Detail, s.now)
		}
	}
	// ICMP from the server itself still fails the family as udp_blocked,
	// with a STUN server answering ICMP as well.
	s := newSim(t, o)
	icmp(s)
	s.unreachable, s.icmp = true, true
	if r := s.stepRun(); r.Failure != protocol.ReasonUDPBlocked || r.Detail != "icmp_unreachable" {
		t.Fatalf("server ICMP: %v/%v", r.Failure, r.Detail)
	}
	// A single ICMP after a round that probed the server only is too little
	// to stop early, but at the hard limit it is the server's: udp_blocked.
	s = newSim(t, defaultOpts())
	s.unreachable = true
	once := false
	s.writeErr = func(sock uint8, to netip.AddrPort) error {
		if to.Addr() == srvIP && !once {
			once = true
			s.schedule(20*ms, func() { s.noteICMP(sock) })
		}
		return nil
	}
	if r := s.stepRun(); r.Failure != protocol.ReasonUDPBlocked || r.Detail != "icmp_unreachable" || s.now != defaultTimeout {
		t.Fatalf("one server ICMP: %v/%v at %v", r.Failure, r.Detail, s.now)
	}
}

// Whatever the configuration, at most 25 server-bound probes and 4 STUN.
func TestPerFamilyBudget(t *testing.T) {
	o := defaultOpts()
	o.ports, o.alt, o.stun, o.siblings = 8, true, true, 2
	s := newSim(t, o)
	s.unreachable = true
	s.stunOn = false
	r := s.stepRun()
	if serverSends(r.Sent) != serverBudget || r.Sent.STUN != 2 {
		t.Fatalf("sent %+v", r.Sent)
	}
	o.stun = false
	s = newSim(t, o)
	s.spec.Probe.STUN = []netip.AddrPort{stunAddr, netip.MustParseAddrPort("192.0.2.51:3478")}
	s.p = New(s.spec, s.socks[0], nil, nil)
	s.unreachable = true
	if r := s.stepRun(); int(r.Sent.STUN) > stunBudget || r.Sent.STUN != 4 {
		t.Fatalf("sent %+v", r.Sent)
	}
}

func TestNoNATHost(t *testing.T) {
	o := defaultOpts()
	o.nat = natCfg{noNAT: true, filtering: protocol.FiltPDF}
	s := newSim(t, o)
	s.socks[0].local = netip.MustParseAddrPort("203.0.113.9:40000") // a public local address
	s.p = New(s.spec, s.socks[0], nil, nil)
	r := s.stepRun()
	if r.Traits.NoNAT != protocol.TriTrue || r.Traits.Mapping != protocol.MapEIM || r.Traits.MappingConf != protocol.ConfHigh ||
		r.Traits.Filtering != protocol.FiltPDF {
		t.Fatalf("traits %+v", r.Traits)
	}
}

func TestNoObserverForFamily(t *testing.T) {
	s := newSim(t, defaultOpts())
	s.spec.Family = protocol.FamilyUDP6
	p6 := &simSock{sim: s, id: nat.SocketID(protocol.FamilyUDP6, 0), local: netip.MustParseAddrPort("[2001:db8::5]:40000")}
	s.p = New(s.spec, p6, nil, nil)
	r := s.p.Run(context.Background())
	if r.Failure != protocol.ReasonNoProbeEndpoint || r.Table == nil || r.Sent.Primary != 0 || r.Traits.Family != protocol.FamilyUDP6 {
		t.Fatalf("result %+v", r)
	}
	checkReportFamily(t, r, protocol.FamilyUDP6)
}

func checkReportFamily(t *testing.T, r Result, f protocol.Family) {
	t.Helper()
	fr := r.Table.Snapshot()
	fr.Traits, fr.Failure = r.Traits, r.Failure
	if fr.Family != f {
		t.Fatalf("family %v", fr.Family)
	}
	rep := protocol.ProbeReport{SessionID: "s1", Role: protocol.RoleInitiator, Control: protocol.DefaultControlSpec(),
		Families: []protocol.FamilyReport{fr}, Transport: protocol.Transport{Mode: "quic"}}
	if err := rep.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBadArguments(t *testing.T) {
	s := newSim(t, defaultOpts())
	token, route := testKeys()
	srvCodec, err := udpwire.NewCodec(token, route, udpwire.RoleServer, udpwire.PadPolicy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		spec   Spec
		prim   SocketHandle
		detail string
	}{
		{"nil codec", Spec{Family: protocol.FamilyUDP4}, s.socks[0], "nil_codec"},
		{"server codec", Spec{Codec: srvCodec, Family: protocol.FamilyUDP4}, s.socks[0], "bad_codec"},
		{"bad family", Spec{Codec: s.cli, Family: "udp9"}, s.socks[0], "bad_family"},
		{"nil primary", Spec{Codec: s.cli, Family: protocol.FamilyUDP4}, nil, "bad_primary"},
		{"typed nil primary", Spec{Codec: s.cli, Family: protocol.FamilyUDP4}, (*simSock)(nil), "bad_primary"},
		{"v6 primary for v4", Spec{Codec: s.cli, Family: protocol.FamilyUDP4}, &simSock{id: 0x80}, "bad_primary"},
		{"second socket as primary", Spec{Codec: s.cli, Family: protocol.FamilyUDP4}, &simSock{id: 1}, "bad_primary"},
		{"panicking primary", Spec{Codec: s.cli, Family: protocol.FamilyUDP4}, panicSock{}, "bad_primary"},
	}
	for _, c := range cases {
		p := New(c.spec, c.prim, []SocketHandle{nil, panicSock{}}, nil)
		r := p.Run(context.Background())
		if r.Failure != protocol.ReasonInternal || r.Detail != c.detail || r.Table == nil {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
	var nilP *Prober
	if r := nilP.Run(context.Background()); r.Failure != protocol.ReasonInternal || r.Detail != "nil_prober" {
		t.Fatal("nil prober")
	}
	if nilP.Deliver(0, netip.AddrPort{}, &udpwire.Header{}, nil, time.Time{}) || nilP.DeliverSTUN(0, netip.AddrPort{}, nil, time.Time{}) ||
		nilP.Hairpin(context.Background()) != protocol.TriUnknown {
		t.Fatal("nil prober methods")
	}
	nilP.NoteUnreachable(0)
}

type panicSock struct{}

func (panicSock) ID() uint8                            { panic("id") }
func (panicSock) Local() netip.AddrPort                { panic("local") }
func (panicSock) WriteTo([]byte, netip.AddrPort) error { panic("write") }

// A panicking WriteTo is a failed send, never a crash.
func TestPanickingWriteTo(t *testing.T) {
	s := newSim(t, defaultOpts())
	s.writeErr = func(uint8, netip.AddrPort) error { panic("boom") }
	r := s.stepRun()
	if r.Failure != protocol.ReasonUDPBlocked || r.Detail != "send_failed" {
		t.Fatalf("result %+v", r)
	}
}

func TestDeliverFiltering(t *testing.T) {
	s := newSim(t, defaultOpts())
	p := s.p
	h := &udpwire.Header{Type: udpwire.TProbeAck}
	if p.Deliver(0, netip.AddrPort{}, h, nil, time.Time{}) {
		t.Fatal("accepted before Run")
	}
	p.active.Store(true)
	if p.Deliver(0, netip.AddrPort{}, &udpwire.Header{Type: udpwire.TPunch}, nil, time.Time{}) || p.Deliver(0, netip.AddrPort{}, nil, nil, time.Time{}) {
		t.Fatal("a non-probe type accepted")
	}
	for range inboxCap {
		if !p.Deliver(0, netip.AddrPort{}, h, nil, time.Time{}) {
			t.Fatal("the inbox refused early")
		}
	}
	if p.Deliver(0, netip.AddrPort{}, h, nil, time.Time{}) || p.dropped.Load() != 1 {
		t.Fatal("a full inbox must drop")
	}
	if p.DeliverSTUN(1, netip.AddrPort{}, nil, time.Time{}) || p.DeliverSTUN(0, netip.AddrPort{}, []byte("garbage"), time.Time{}) {
		t.Fatal("bad STUN accepted")
	}
	p.NoteUnreachable(5) // not the primary: ignored
	if p.icmp.Load() != 0 {
		t.Fatal("ICMP on another socket counted")
	}
}

// Replies that do not match their probe are rejected and change nothing.
func TestRejectMismatchedReplies(t *testing.T) {
	s := newSim(t, defaultOpts())
	p := s.p
	rs := newRunState(p)
	rs.step(0) // SEND0
	rec := rs.recs[0]
	base := inbound{sock: rec.tg.sockID, from: rec.tg.obs.Addr, h: udpwire.Header{Type: udpwire.TProbeAck, Role: udpwire.RoleServer,
		Sock: rec.tg.sockID, Aux: uint16(rec.tg.obs.ID), Seq: 9, EchoSeq: rec.seq, EchoTS: rec.ts},
		t: udpwire.TLVs{Observed: netip.MustParseAddrPort("203.0.113.5:40000"), Cookie: 3}, at: s.fake.Now()}
	bad := []func(*inbound){
		func(in *inbound) { in.h.EchoSeq = 999 },
		func(in *inbound) { in.h.EchoTS++ },
		func(in *inbound) { in.sock = 7 },
		func(in *inbound) { in.h.Sock = 7 },
		func(in *inbound) { in.h.Aux = 5 },
		func(in *inbound) { in.h.Aux |= 0x100 },
		func(in *inbound) { in.h.Role = udpwire.RoleResponder },
		func(in *inbound) { in.from = netip.MustParseAddrPort("198.51.100.1:9999") },
		func(in *inbound) { in.t.Observed = netip.AddrPort{} },
		func(in *inbound) { in.h.Type = udpwire.TProbeAlt },                                    // no WANT_ALT on that probe
		func(in *inbound) { in.h.Type = udpwire.TProbeExtra },                                  // from the observer's own port
		func(in *inbound) { in.h.Type = udpwire.THairpin },                                     // outside the self-test
		func(in *inbound) { in.stun = true; in.txid = [12]byte{1}; in.mapped = in.t.Observed }, // unknown STUN txid
	}
	for i, mut := range bad {
		in := base
		mut(&in)
		rs.handle(in)
		if rs.counters.Rejected != uint32(i+1) || rec.acked {
			t.Fatalf("case %d accepted: %+v", i, rs.counters)
		}
	}
	rs.handle(base)
	if !rec.acked || rs.counters.Rejected != uint32(len(bad)) {
		t.Fatal("a valid ack refused")
	}
	rs.handle(base) // a duplicate: ignored, not rejected
	if rs.counters.Rejected != uint32(len(bad)) {
		t.Fatal("duplicate counted")
	}
	// an extra from the right IP but not from the declared port
	in := base
	in.h.Type, in.from = udpwire.TProbeExtra, netip.MustParseAddrPort("198.51.100.1:1")
	rs.handle(in)
	if rs.counters.Rejected != uint32(len(bad))+1 {
		t.Fatal("an undeclared extra accepted")
	}
	// a delivery without a timestamp takes the clock's time
	in = base
	in.at = time.Time{}
	in.h.EchoSeq = rs.recs[1].seq
	in.h.EchoTS = rs.recs[1].ts
	in.h.Aux = uint16(rs.recs[1].tg.obs.ID)
	in.from = rs.recs[1].tg.obs.Addr
	rs.handle(in)
	if !rs.recs[1].acked {
		t.Fatal("ack without timestamp refused")
	}
}

func TestCtxReason(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errors.New("x"))
	if r, _ := ctxReason(ctx); r != protocol.ReasonCanceled {
		t.Fatal(r)
	}
	ctx, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if r, _ := ctxReason(ctx); r != protocol.ReasonCanceled {
		t.Fatal(r)
	}
	// a panic elsewhere in the session group
	g := life.New(context.Background())
	g.Go("x", func(context.Context) { panic("boom") })
	<-g.Context().Done()
	if r, d := ctxReason(g.Context()); r != protocol.ReasonInternal || d != "panic:x" {
		t.Fatalf("%v %q", r, d)
	}
	_ = g.Close(0)
}

func TestCodecRole(t *testing.T) {
	token, route := testKeys()
	for _, role := range []udpwire.Role{udpwire.RoleInitiator, udpwire.RoleResponder} {
		c, err := udpwire.NewCodec(token, route, role, udpwire.PadPolicy{Min: 64, Max: 128}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := codecRole(c); !ok || got != role {
			t.Fatalf("codecRole = %v, %v; want %v", got, ok, role)
		}
	}
	if _, ok := codecRole(nil); ok {
		t.Fatal("nil codec")
	}
}

// A STUN answer that names no address of the family (a NAT64 path answers
// in the other family) ends that server's wait but is no public address: a
// LAN-observed family keeps waiting for another server as if none had
// answered.
func TestSTUNWrongFamilyKeepsLANWait(t *testing.T) {
	o := defaultOpts()
	o.nat = natCfg{noNAT: true}
	s := newSim(t, o)
	s.stunOn, s.stunWrongV6 = true, true
	s.spec.Probe.STUN = []netip.AddrPort{stunAddr, netip.MustParseAddrPort("192.0.2.60:3478")} // the second stays silent
	s.p = New(s.spec, s.socks[0], nil, nil)
	r := s.stepRun()
	if s.now < stunLANGrace || s.now > o.rtt+stunLANGrace+ms {
		t.Fatalf("done at %v, want the LAN wait of %v", s.now, stunLANGrace)
	}
	if len(r.Table.Snapshot().STUN) != 0 || !r.Traits.LANObserved || r.Sent.Rejected != 0 {
		t.Fatalf("stun rows %+v, traits %+v, sent %+v", r.Table.Snapshot().STUN, r.Traits, r.Sent)
	}
	checkReport(t, r)
}

// Only the family's STUN servers may queue a STUN message: anyone else's
// would take the inbox from the observers' replies.
func TestDeliverSTUNFromServersOnly(t *testing.T) {
	o := defaultOpts()
	o.stun = true
	s := newSim(t, o)
	s.p.active.Store(true)
	msg := stun.AppendBindingResponse(nil, stun.TransactionID{7}, netip.MustParseAddrPort("203.0.113.5:40000"))
	if s.p.DeliverSTUN(0, netip.MustParseAddrPort("192.0.2.51:3478"), msg, time.Time{}) {
		t.Fatal("a STUN message from another host was queued")
	}
	if !s.p.DeliverSTUN(0, netip.AddrPortFrom(netip.AddrFrom16(stunAddr.Addr().As16()), stunAddr.Port()), msg, time.Time{}) {
		t.Fatal("the STUN server's answer (IPv4-mapped source) was refused")
	}
	if len(s.p.inbox) != 1 {
		t.Fatalf("inbox holds %d", len(s.p.inbox))
	}
}

// TestFirstAckAndStop: OnFirstAck is called once, when the first main
// observer answers; a Prober stopped before Run returns at once with
// nothing sent.
func TestFirstAckAndStop(t *testing.T) {
	s := newSim(t, defaultOpts())
	calls := 0
	s.p.spec.OnFirstAck = func() {
		calls++
		answered := false
		for _, row := range s.p.table.Snapshot().Sockets[0].Rows {
			answered = answered || row.Cookie != 0
		}
		if !answered {
			t.Error("no answered row when OnFirstAck runs")
		}
	}
	if r := s.stepRun(); r.Failure != "" || calls != 1 {
		t.Fatalf("failure %q, OnFirstAck called %d times", r.Failure, calls)
	}

	stopped := newSim(t, defaultOpts())
	stopped.p.Stop()
	stopped.p.Stop()
	r := stopped.p.Run(context.Background())
	if r.Sent.Primary != 0 || r.Failure != protocol.ReasonProbeTimeout {
		t.Fatalf("a stopped prober: failure %q, sent %+v", r.Failure, r.Sent)
	}
}

package coord

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

func TestApplyTraitsUpdate(t *testing.T) {
	m, c, f, step, vel, hp := protocol.MapADM, protocol.ConfHigh, protocol.FiltEIF, int16(2), float32(3), protocol.TriTrue
	got := applyTraitsUpdate(protocol.Traits{}, protocol.TraitsUpdate{Mapping: &m, MappingConf: &c, Filtering: &f,
		FilteringConf: &c, PortStep: &step, PortVelocity: &vel, Hairpin: &hp, Source: protocol.TraitsSourcePeer})
	if got.Mapping != m || got.MappingConf != c || got.Filtering != f || got.FilteringConf != c || got.PortStep != step ||
		got.PortVelocity != vel || got.Hairpin != hp || !got.CrossIP {
		t.Fatalf("traits %+v", got)
	}
	high := protocol.ConfHigh
	got = applyTraitsUpdate(protocol.Traits{Mapping: m}, protocol.TraitsUpdate{MappingConf: &high, Source: protocol.TraitsSourcePeer})
	if got.MappingConf != high || got.CrossIP {
		t.Fatalf("a confidence change is no cross-IP evidence: %+v", got)
	}
	obs := mustAP("203.0.113.5:40000")
	eim := protocol.Traits{Mapping: protocol.MapEIM, MappingConf: protocol.ConfMedium, Observed: obs}
	public := func(a netip.AddrPort) protocol.PathInfo {
		return protocol.PathInfo{Remote: a, Kind: protocol.PathPublic}
	}
	if got := peerConfirmed(eim, public(obs)); got.MappingConf != protocol.ConfHigh || !got.CrossIP {
		t.Fatalf("seen at the observed mapping: %+v", got)
	}
	if got := peerConfirmed(eim, public(mustAP("203.0.113.5:40001"))); got != eim {
		t.Fatalf("seen at another port: %+v", got)
	}
	if got := peerConfirmed(eim, protocol.PathInfo{Remote: obs, Kind: protocol.PathOverlay}); got != eim {
		t.Fatalf("an overlay path: %+v", got)
	}
	adm := eim
	adm.Mapping = protocol.MapADM
	if got := peerConfirmed(adm, public(obs)); got != adm {
		t.Fatalf("an ADM: %+v", got)
	}
	if !overturns(eim, adm) || overturns(eim, eim) || overturns(adm, adm) {
		t.Fatal("overturns")
	}
	multi := eim
	multi.MultiExit = true
	if !overturns(eim, multi) {
		t.Fatal("several exits")
	}
	got = applyTraitsUpdate(protocol.Traits{}, protocol.TraitsUpdate{Hairpin: &hp, Source: protocol.TraitsSourceHairpin})
	if got.CrossIP {
		t.Fatal("hairpin is no cross-IP evidence")
	}
	// A STUN server is only a hint; the alt observers are natprobe's.
	for src, cross := range map[protocol.TraitsSource]bool{protocol.TraitsSourceSTUN: false, protocol.TraitsSourceAlt: true} {
		got = applyTraitsUpdate(protocol.Traits{}, protocol.TraitsUpdate{Mapping: &m, Filtering: &f, Source: src})
		if got.Mapping != m || got.Filtering != f || got.CrossIP != cross {
			t.Fatalf("%s: traits %+v", src, got)
		}
	}
}

func TestSameLAN(t *testing.T) {
	lan := func(addrs ...string) protocol.FamilyView {
		var fv protocol.FamilyView
		for _, a := range addrs {
			fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Addr: mustAP(a), Source: protocol.EndpointLAN})
		}
		fv.Endpoints = append(fv.Endpoints, protocol.Endpoint{Addr: pubI, Source: protocol.EndpointServer})
		return fv
	}
	if !sameLAN(lan("192.168.1.2:1"), lan("192.168.1.9:2")) || sameLAN(lan("192.168.1.2:1"), lan("192.168.2.9:2")) {
		t.Fatal("v4")
	}
	if !sameLAN(lan("[fd00::1]:1"), lan("[fd00::2]:2")) {
		t.Fatal("v6")
	}
}

func TestClassifyLoss(t *testing.T) {
	pe := life.Safe("x", func() { panic("boom") })
	cases := []struct {
		err    error
		code   protocol.Reason
		detail string
		kind   lossKind
	}{
		{pe, protocol.ReasonInternal, "panic:x: boom", lossInternal},
		{controlwire.ErrFlood, protocol.ReasonProtocolViolation, "control_flood", lossProtocol},
		{os.ErrDeadlineExceeded, protocol.ReasonPeerOffline, detailWriteTimeout, lossLink},
		{io.EOF, protocol.ReasonPeerOffline, "", lossLink},
	}
	for _, c := range cases {
		if got := classifyLoss(c.err); got != (linkLoss{code: c.code, detail: c.detail, kind: c.kind}) {
			t.Errorf("%v: %+v", c.err, got)
		}
	}
	if term := internalTerm(errors.New(strings.Repeat("x", 400))); len(term.detail) != protocol.MaxDetail || term.panic != nil {
		t.Fatalf("internal term %+v", term)
	}
}

// TestEncodeFailureIsInternal: a frame the coordinator cannot encode is a
// defect of its own and ends the session with internal.
func TestEncodeFailureIsInternal(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.s.mu.Lock()
	fx := p.s.sendMarkedLocked(0, protocol.Ping{Seq: 0}, &p.s.st.links[0].markPing[0])
	p.s.mu.Unlock()
	if fx.term == nil || fx.term.code != protocol.ReasonInternal {
		t.Fatalf("effects %+v", fx)
	}
	p.s.apply(fx)
	r.wait(p.s)
}

// TestSessionGoroutinePanic: a panic in a goroutine of the session group ends
// the session with internal and an event carrying the stack.
func TestSessionGoroutinePanic(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	if _, ok := s.Result(); ok {
		t.Fatal("result before the end")
	}
	s.group.Go("coord.test", func(context.Context) { panic("boom") })
	res := r.wait(s)
	if res.Reason != protocol.ReasonInternal || !strings.HasPrefix(res.Detail, "panic:coord.test") {
		t.Fatalf("result %+v", res)
	}
	evs := r.waitEvents(EvInternalError, 1)
	if info, ok := evs[0].Data.(PanicInfo); !ok || len(info.Stack) == 0 {
		t.Fatalf("event %+v", evs[0])
	}
}

func TestEventKindNames(t *testing.T) {
	for k := EvCreated; k <= EvClosed; k++ {
		if k.String() == "unknown" {
			t.Fatalf("%d unnamed", k)
		}
	}
	if EventKind(0).String() != "unknown" || EventKind(99).String() != "unknown" {
		t.Fatal("unknown kinds")
	}
}

// TestSelfView: a relay-only view takes the client's addresses, deduplicated
// and bounded, none of them verified; the planner gets it as sent.
func TestSelfView(t *testing.T) {
	rep := protocol.ProbeReport{Families: []protocol.FamilyReport{{
		Family: protocol.FamilyUDP4,
		Traits: protocol.Traits{PortAnchor: 40000, PortAnchorMs: 777},
		Sockets: []protocol.SocketReport{
			{Kind: protocol.SocketPrimary, Rows: []protocol.RowReport{{Observed: pubI}, {Observed: pubI}}},
			{ID: 1, Kind: protocol.SocketSecond, Rows: []protocol.RowReport{{Observed: mustAP("203.0.113.10:40001")}}},
			{ID: 2, Kind: protocol.SocketSibling, Rows: []protocol.RowReport{{Observed: mustAP("10.1.1.1:1")}}},
		},
		STUN:    []protocol.RowReport{{Observed: mustAP("203.0.113.10:40002")}},
		PortMap: &protocol.PortMapReport{External: mustAP("203.0.113.10:40003")},
	}}}
	v := selfView(rep)
	eps := v.Families[0].Endpoints
	if len(eps) != 5 || v.Families[0].Traits.Samples != 1 || eps[1].Source != protocol.EndpointSecond ||
		v.Families[0].Traits.PortAnchorMs != 0 {
		t.Fatalf("view %+v", v)
	}
	for _, e := range eps {
		if e.Verified {
			t.Fatalf("self-reported endpoint %+v marked verified", e)
		}
	}
}

func TestPickTransport(t *testing.T) {
	cases := []struct {
		a, b, fb, want string
		ok             bool
	}{
		{"quic", "quic", "", "quic", true},
		{"", "kcp", "", "kcp", true},
		{"quic", "", "", "quic", true},
		{"quic", "kcp", "", "", false},
		{"quic", "kcp", "tcp", "tcp", true},
		{"", "", "kcp", "kcp", true},
	}
	for _, c := range cases {
		if got, ok := pickTransport(c.a, c.b, c.fb); got != c.want || ok != c.ok {
			t.Errorf("%q %q %q: %q %v", c.a, c.b, c.fb, got, ok)
		}
	}
}

func TestStatsHistograms(t *testing.T) {
	var c counters
	created := time.Unix(100, 0)
	c.record(&Result{Outcome: OutcomeSucceeded, RTT: [2]time.Duration{30 * time.Millisecond, 2 * time.Second},
		Winner: &WinnerInfo{Round: 2}, MemoryHit: true, Confirmed: [2]bool{true, false},
		Timing: Timing{Created: created, FirstConfirm: created.Add(1500 * time.Millisecond)},
		Rounds: []RoundRecord{{Class: plan.RoundNoContact}, {Class: plan.RoundConfirmed}}})
	c.record(&Result{Outcome: OutcomeFailed, Reason: protocol.ReasonCandidateTimeout})
	s := c.snapshot()
	if s.SessionsTotal != 2 || s.ByOutcome != [3]int64{1, 1, 0} || s.ByReason[protocol.ReasonCandidateTimeout] != 1 ||
		s.HalfConfirmed != 1 || s.ConfirmAtRound[2] != 1 || s.ConfirmAtRound[0] != 1 || s.RTTHistogramMs[1] != 1 ||
		s.RTTHistogramMs[7] != 1 || s.TimeToConfirm[2] != 1 || s.MemoryHits != 1 || s.RoundsByClass[plan.RoundNoContact] != 1 {
		t.Fatalf("stats %+v", s)
	}
}

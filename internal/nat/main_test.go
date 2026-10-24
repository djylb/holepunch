package nat

import (
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/protocol"
)

func TestMain(m *testing.M) { goroutines.VerifyTestMain(m) }

// Socket ids of the udp4 tests.
var (
	v4P = SocketID(protocol.FamilyUDP4, IndexPrimary)
	v4S = SocketID(protocol.FamilyUDP4, IndexSecond)
	v4B = SocketID(protocol.FamilyUDP4, IndexSibling)
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// mainObservers are three ports of one server IP (group 0) and one alt
// observer on a second IP.
func mainObservers() []Observer {
	return []Observer{
		{ID: 0, Addr: ap("198.51.100.1:3478"), Group: 0},
		{ID: 1, Addr: ap("198.51.100.1:3479"), Group: 0},
		{ID: 2, Addr: ap("198.51.100.1:3480"), Group: 0},
		{ID: 8, Addr: ap("198.51.100.2:3478"), Group: 1, Alt: true},
	}
}

// fixture drives a client-side table: probes go out in order (seq grows) and
// are answered with the given observed values.
type fixture struct {
	t   *ObsTable
	seq uint32
	at  time.Duration
}

func newFixture(local string, extra ...SocketMeta) *fixture {
	socks := append([]SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap(local)}}, extra...)
	return &fixture{t: NewTable(protocol.FamilyUDP4, socks, mainObservers())}
}

func secondSocket() SocketMeta {
	return SocketMeta{ID: v4S, Kind: protocol.SocketSecond, Local: ap("192.168.1.10:40001")}
}

func (f *fixture) send(sock uint8, src Source, obs uint8) PointKey {
	f.seq++
	f.at += time.Millisecond
	k := PointKey{Socket: sock, Source: src, Observer: obs}
	f.t.NoteSent(k, f.seq, f.at)
	return k
}

// probe sends to observer obs from sock and answers with observed ("" = lost).
func (f *fixture) probe(sock, obs uint8, observed string) {
	k := f.send(sock, SourceServer, obs)
	if observed != "" {
		f.t.Record(k, ap(observed), f.at+20*time.Millisecond, 20*time.Millisecond, 7)
	}
}

// primary probes observers 0, 1, 2 … from the primary socket.
func (f *fixture) primary(observed ...string) {
	for i, o := range observed {
		f.probe(v4P, uint8(i), o)
	}
}

func (f *fixture) filter(obs uint8, extraDeclared, extraSeen, altDeclared, altSeen uint8) {
	f.t.AddFilter(FilterEvidence{Socket: v4P, Observer: obs, ExtraDeclared: extraDeclared, ExtraSeen: extraSeen,
		AltDeclared: altDeclared, AltSeen: altSeen})
}

func (f *fixture) peer(dest, observed string) {
	f.t.Record(PointKey{Socket: v4P, Source: SourcePeer, Peer: ap(dest)}, ap(observed), f.at, 0, 0)
}

func wantMapping(t *testing.T, tr protocol.Traits, m protocol.Mapping, c protocol.Conf) {
	t.Helper()
	if tr.Mapping != m || tr.MappingConf != c {
		t.Fatalf("mapping = %v/%v, want %v/%v (traits %+v)", tr.Mapping, tr.MappingConf, m, c, tr)
	}
}

func wantFiltering(t *testing.T, tr protocol.Traits, f protocol.Filtering, c protocol.Conf) {
	t.Helper()
	if tr.Filtering != f || tr.FilteringConf != c {
		t.Fatalf("filtering = %v/%v, want %v/%v", tr.Filtering, tr.FilteringConf, f, c)
	}
}

func wantAlloc(t *testing.T, tr protocol.Traits, a protocol.PortAlloc, c protocol.Conf) {
	t.Helper()
	if tr.PortAlloc != a || tr.PortAllocConf != c {
		t.Fatalf("alloc = %v/%v, want %v/%v (traits %+v)", tr.PortAlloc, tr.PortAllocConf, a, c, tr)
	}
}

// validReport checks fr as the only family of a probe_report.
func validReport(fr protocol.FamilyReport) error {
	r := protocol.ProbeReport{
		SessionID: "s1", Role: protocol.RoleInitiator,
		Control:   protocol.DefaultControlSpec(),
		Families:  []protocol.FamilyReport{fr},
		Transport: protocol.Transport{Mode: "quic"},
	}
	return r.Validate()
}

// validView checks v as both views of a probe_summary with a minimal plan.
func validView(f protocol.Family, v protocol.PeerView) error {
	sum := protocol.ProbeSummary{SessionID: "s1", Self: v, Peer: v, Transport: protocol.TransportPick{Mode: "quic"},
		Timeouts: protocol.DefaultTimeouts(), Plan: protocol.PlanSpec{ID: "p", RoundsMax: 1, Budget: protocol.DefaultBudget(),
			Round1: protocol.RoundPlan{Round: 1, Variant: "direct", Budget: protocol.BudgetLight, WindowMs: 1000,
				Sides: []protocol.FamilySide{{Family: f, Role: protocol.SideBoth, Sockets: 1,
					Stages: []protocol.Stage{{Kind: protocol.StageReplyOnly}}}}}}}
	return sum.Validate()
}

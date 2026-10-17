package natprobe

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

func reportFor(id string, role protocol.Role, f protocol.Family, local string, rows []protocol.RowReport) protocol.ProbeReport {
	return protocol.ProbeReport{SessionID: id, Role: role, Control: protocol.DefaultControlSpec(),
		Families: []protocol.FamilyReport{{Family: f, Sockets: []protocol.SocketReport{
			{ID: nat.SocketID(f, 0), Kind: protocol.SocketPrimary, Local: netip.MustParseAddrPort(local), Rows: rows}}}},
		Transport: protocol.Transport{Mode: "quic"}}
}

// session drives probes through the rig and builds the client's rows the
// way the prober does (observed value, first seq, cookie of the latest ack).
type session struct {
	t    *testing.T
	r    *rig
	h    *handle
	c    *client
	role protocol.Role
	rows map[[2]uint8]*protocol.RowReport
	ord  [][2]uint8
	seen map[[2]uint8]protocol.FilterReport
}

func newSession(t *testing.T, r *rig, id string, role protocol.Role, b byte) *session {
	urole := udpwire.RoleInitiator
	if role == protocol.RoleResponder {
		urole = udpwire.RoleResponder
	}
	return &session{t: t, r: r, h: register(t, r.reg, id, tok(b), rt(b)), c: newClient(t, tok(b), rt(b), urole), role: role,
		rows: map[[2]uint8]*protocol.RowReport{}, seen: map[[2]uint8]protocol.FilterReport{}}
}

// probe sends from sock to listener i (observer id = the listener's) and
// records what the client saw; lose drops the replies.
func (s *session) probe(sock uint8, i int, src netip.AddrPort, extra, lose bool) {
	obs := s.r.ls[i].id
	seq := s.c.codec.NextSeq()
	k := [2]uint8{sock, obs}
	if s.rows[k] == nil {
		s.rows[k] = &protocol.RowReport{Observer: obs, FirstSeq: seq, SentMs: uint32(len(s.ord))}
		s.ord = append(s.ord, k)
	}
	out := s.r.deliver(i, s.c.probe(probeOpts{sock: sock, obs: obs, extra: extra, seq: seq}), src)
	if lose {
		return
	}
	for _, o := range out {
		h, tl, ok := s.c.open(o.b)
		if !ok {
			s.t.Fatal("a reply does not open")
		}
		switch h.Type {
		case udpwire.TProbeAck:
			row := s.rows[k]
			if !row.Observed.IsValid() {
				row.Observed = tl.Observed
			}
			row.RTTMs, row.Cookie = 12, tl.Cookie
		case udpwire.TProbeExtra:
			f := s.seen[k]
			f.Socket, f.Observer, f.ExtraSeen = sock, obs, f.ExtraSeen+1
			s.seen[k] = f
		default:
			s.t.Fatalf("reply type %d", h.Type)
		}
	}
}

func (s *session) report(f protocol.Family, locals map[uint8]string, kinds map[uint8]protocol.SocketKind) protocol.ProbeReport {
	rep := protocol.ProbeReport{SessionID: s.h.e.id, Role: s.role, Control: protocol.DefaultControlSpec(),
		Families: []protocol.FamilyReport{{Family: f}}, Transport: protocol.Transport{Mode: "quic"}}
	bySock := map[uint8]*protocol.SocketReport{}
	var order []uint8
	for _, k := range s.ord {
		sr := bySock[k[0]]
		if sr == nil {
			kind := kinds[k[0]]
			if kind == "" {
				kind = protocol.SocketPrimary
			}
			sr = &protocol.SocketReport{ID: k[0], Kind: kind, Local: netip.MustParseAddrPort(locals[k[0]])}
			bySock[k[0]] = sr
			order = append(order, k[0])
		}
		sr.Rows = append(sr.Rows, *s.rows[k])
	}
	for _, id := range order {
		rep.Families[0].Sockets = append(rep.Families[0].Sockets, *bySock[id])
	}
	for _, f := range s.seen {
		rep.Families[0].Filters = append(rep.Families[0].Filters, f)
	}
	return rep
}

func mustMerge(t *testing.T, h *handle, role protocol.Role, rep protocol.ProbeReport, mem TraitsMemory) (protocol.FamilyView, nat.MergeDiag) {
	t.Helper()
	if err := rep.Validate(); err != nil {
		t.Fatalf("report invalid: %v", err)
	}
	view, diag, err := h.mergeTest(role, rep, mem, TraitsKey{ClientKey: "client-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Families) != 1 {
		t.Fatalf("view %+v", view)
	}
	sum := protocol.ProbeSummary{SessionID: "s", Self: view, Peer: view, Transport: protocol.TransportPick{Mode: "quic"},
		Timeouts: protocol.DefaultTimeouts(), Plan: minimalPlan(view.Families[0].Family)}
	if err := sum.Validate(); err != nil {
		t.Fatalf("summary invalid: %v", err)
	}
	return view.Families[0], diag
}

func minimalPlan(f protocol.Family) protocol.PlanSpec {
	return protocol.PlanSpec{ID: "p", RoundsMax: 1, Budget: protocol.DefaultBudget(),
		Round1: protocol.RoundPlan{Round: 1, Variant: "direct", Budget: protocol.BudgetLight, WindowMs: 1000,
			Sides: []protocol.FamilySide{{Family: f, Role: protocol.SideBoth, Sockets: 1, Stages: []protocol.Stage{{Kind: protocol.StageReplyOnly}}}}}}
}

var local4 = map[uint8]string{0: "192.168.1.10:40000", 1: "192.168.1.10:40001", 2: "10.8.0.2:40000"}

// Verified endpoints only; the traits are authoritative.
func TestMergeVerified(t *testing.T) {
	r := newRig(t, rigOpts{})
	s := newSession(t, r, "s1", protocol.RoleInitiator, 1)
	for i := range 3 {
		s.probe(0, i, srcA, true, false)
	}
	fv, diag := mustMerge(t, s.h, protocol.RoleInitiator, s.report(protocol.FamilyUDP4, local4, nil), nil)
	tr := fv.Traits
	if tr.Provisional || tr.Mapping != protocol.MapEIM || tr.MappingConf != protocol.ConfMedium || tr.Filtering != protocol.FiltNotPDF ||
		tr.Samples != 3 || tr.Observed != srcA || tr.NoNAT != protocol.TriFalse {
		t.Fatalf("traits %+v", tr)
	}
	if diag != (nat.MergeDiag{}) {
		t.Fatalf("diag %+v", diag)
	}
	want := []protocol.Endpoint{{Addr: srcA, Source: protocol.EndpointServer, Socket: 0, Verified: true},
		{Addr: netip.MustParseAddrPort("192.168.1.10:40000"), Source: protocol.EndpointLAN, Socket: 0}}
	if len(fv.Endpoints) != 2 || fv.Endpoints[0] != want[0] || fv.Endpoints[1] != want[1] {
		t.Fatalf("endpoints %+v", fv.Endpoints)
	}
}

// A forged row the server never saw is dropped; a wrong cookie is
// not verified; a row whose ack was lost is still classified.
func TestMergeServerAuthority(t *testing.T) {
	r := newRig(t, rigOpts{})
	s := newSession(t, r, "s1", protocol.RoleInitiator, 1)
	s.probe(0, 0, srcA, false, false)
	s.probe(0, 1, srcA, false, true) // the ack is lost: a row without answer
	s.probe(0, 2, srcA, false, false)
	rep := s.report(protocol.FamilyUDP4, local4, nil)
	rows := rep.Families[0].Sockets[0].Rows
	rows[2].Cookie++ // a wrong cookie
	forged := netip.MustParseAddrPort("1.2.3.4:5")
	rows = append(rows, protocol.RowReport{Observer: 9, Observed: forged, RTTMs: 3}, protocol.RowReport{Observer: 10}) // never seen by the server
	rows = append(rows, rows[0])                                                                                       // a repeated row
	rep.Families[0].Sockets[0].Rows = rows
	fv, diag := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil)
	if diag.Unverified != 1 || diag.CookieMissing != 2 || fv.Traits.Samples != 3 {
		t.Fatalf("diag %+v traits %+v", diag, fv.Traits)
	}
	for _, e := range fv.Endpoints {
		if e.Addr == forged {
			t.Fatal("the forged address was handed out")
		}
	}
	if fv.Endpoints[0].Addr != srcA || !fv.Endpoints[0].Verified {
		t.Fatalf("endpoints %+v", fv.Endpoints)
	}
	// a client row missing entirely (the probe arrived, nothing reported) is added
	rep.Families[0].Sockets[0].Rows = rep.Families[0].Sockets[0].Rows[:1]
	if fv, _ := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil); fv.Traits.Samples != 3 {
		t.Fatalf("the server-only slots were not merged: %+v", fv.Traits)
	}
	// nothing verified → no server endpoint at all
	for i := range rep.Families[0].Sockets[0].Rows {
		rep.Families[0].Sockets[0].Rows[i].Cookie = 0
	}
	fv, _ = mustMerge(t, s.h, protocol.RoleInitiator, rep, nil)
	for _, e := range fv.Endpoints {
		if e.Verified || e.Source == protocol.EndpointServer {
			t.Fatalf("unverified endpoint %+v", e)
		}
	}
}

func TestMergeConflictAndDrift(t *testing.T) {
	r := newRig(t, rigOpts{})
	s := newSession(t, r, "s1", protocol.RoleInitiator, 1)
	for i := range 3 {
		s.probe(0, i, srcA, false, false)
	}
	rep := s.report(protocol.FamilyUDP4, local4, nil)
	rep.Families[0].Sockets[0].Rows[1].Observed = netip.MustParseAddrPort("203.0.113.99:1") // an SNAT proxy style conflict
	fv, diag := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil)
	if diag.Conflicts != 1 || fv.Traits.MappingConf != protocol.ConfLow {
		t.Fatalf("diag %+v traits %+v", diag, fv.Traits)
	}
	// the server saw the mapping change: drift, and only the latest value is verified
	moved := netip.MustParseAddrPort("203.0.113.5:40100")
	s.probe(0, 0, moved, false, false)
	fv, _ = mustMerge(t, s.h, protocol.RoleInitiator, s.report(protocol.FamilyUDP4, local4, nil), nil)
	if !fv.Traits.Drifted || fv.Traits.MappingConf != protocol.ConfLow {
		t.Fatalf("traits %+v", fv.Traits)
	}
	found := false
	for _, e := range fv.Endpoints {
		found = found || (e.Addr == moved && e.Verified)
	}
	if !found {
		t.Fatalf("the latest value is not verified: %+v", fv.Endpoints)
	}
}

func TestMergeFiltering(t *testing.T) {
	r := newRig(t, rigOpts{})
	s := newSession(t, r, "s1", protocol.RoleInitiator, 1)
	for i := range 3 {
		s.probe(0, i, srcA, true, false)
	}
	rep := s.report(protocol.FamilyUDP4, local4, nil)
	rep.Families[0].Filters = nil // the client saw no extra: PDF by the server's counts
	fv, _ := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil)
	if fv.Traits.Filtering != protocol.FiltPDF || fv.Traits.FilteringConf != protocol.ConfHigh {
		t.Fatalf("traits %+v", fv.Traits)
	}
	// a client cannot claim more extras than were sent; a repeated entry counts once
	rep.Families[0].Filters = []protocol.FilterReport{{Socket: 0, Observer: 1, ExtraSeen: 200}, {Socket: 0, Observer: 1, ExtraSeen: 9}}
	if fv, _ := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil); fv.Traits.Filtering != protocol.FiltNotPDF {
		t.Fatalf("traits %+v", fv.Traits)
	}
	// declarations in acks the client never got are not negative evidence
	r2 := newRig(t, rigOpts{})
	s2 := newSession(t, r2, "s2", protocol.RoleInitiator, 2)
	for i := range 3 {
		s2.probe(0, i, srcA, true, i > 0)
	}
	if fv, _ := mustMerge(t, s2.h, protocol.RoleInitiator, s2.report(protocol.FamilyUDP4, local4, nil), nil); fv.Traits.FilteringConf != protocol.ConfHigh {
		t.Fatalf("traits %+v", fv.Traits)
	}
}

func TestMergeSelfReported(t *testing.T) {
	r := newRig(t, rigOpts{})
	s := newSession(t, r, "s1", protocol.RoleInitiator, 1)
	for i := range 2 {
		s.probe(0, i, srcA, false, false)
	}
	rep := s.report(protocol.FamilyUDP4, local4, nil)
	rep.Families[0].STUN = []protocol.RowReport{{Observer: 0, Observed: srcA, RTTMs: 30}, {Observer: 1, Observed: netip.MustParseAddrPort("198.18.0.1:4000")}, {Observer: 2}}
	rep.Families[0].PortMap = &protocol.PortMapReport{Method: protocol.PortMapPCP, External: netip.MustParseAddrPort("10.64.0.9:40000"), LeaseSeconds: 60}
	fv, diag := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil)
	// the agreeing STUN row is a hint: natprobe's single IP stays Medium
	if diag.RejectedEndpoints != 1 || diag.STUNConflicts != 0 || fv.Traits.CrossIP || fv.Traits.MappingConf != protocol.ConfMedium ||
		fv.Traits.CGNAT != protocol.TriTrue {
		t.Fatalf("diag %+v traits %+v", diag, fv.Traits)
	}
	var srcs []string
	for _, e := range fv.Endpoints {
		srcs = append(srcs, string(e.Source)+"="+e.Addr.String())
	}
	if fmt.Sprint(srcs) != "[server=203.0.113.5:40000 portmap=10.64.0.9:40000 lan=192.168.1.10:40000]" {
		t.Fatalf("endpoints %v", srcs)
	}
	rep.Families[0].PortMap.External = netip.MustParseAddrPort("192.0.2.200:1")
	if _, diag := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil); diag.RejectedEndpoints != 2 {
		t.Fatalf("a foreign port mapping was accepted: %+v", diag)
	}
}

// A STUN value that contradicts natprobe's records — another
// port where natprobe saw one mapping — is counted and marks the mapping
// path dependent, changing no conclusion; a second value at one STUN point
// is no contradiction, and a STUN server that never answered (an empty row)
// changes nothing either. The STUN value on the verified IP is handed to
// the peer as an endpoint.
func TestMergeSTUNHint(t *testing.T) {
	r := newRig(t, rigOpts{})
	s := newSession(t, r, "s1", protocol.RoleInitiator, 1)
	for i := range 3 {
		s.probe(0, i, srcA, false, false)
	}
	rep := s.report(protocol.FamilyUDP4, local4, nil)
	plain, diag := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil)
	if diag.STUNConflicts != 0 || plain.Traits.Mapping != protocol.MapEIM || plain.Traits.MappingConf != protocol.ConfMedium {
		t.Fatalf("diag %+v traits %+v", diag, plain.Traits)
	}
	other := netip.AddrPortFrom(srcA.Addr(), srcA.Port()+9)
	for _, c := range []struct {
		name      string
		rows      []protocol.RowReport
		conflicts int
	}{
		{"silent server", []protocol.RowReport{{Observer: 0}}, 0},
		{"another port", []protocol.RowReport{{Observer: 0, Observed: other}}, 1},
		{"two values", []protocol.RowReport{{Observer: 0, Observed: srcA}, {Observer: 0, Observed: other}}, 0},
	} {
		rep.Families[0].STUN = c.rows
		fv, diag := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil)
		want := plain.Traits
		want.PathDependent = c.conflicts > 0
		if diag.STUNConflicts != c.conflicts || fv.Traits != want {
			t.Errorf("%s: diag %+v traits %+v, want %+v", c.name, diag, fv.Traits, want)
		}
		if c.name == "another port" && !slices.ContainsFunc(fv.Endpoints, func(e protocol.Endpoint) bool {
			return e.Source == protocol.EndpointSTUN && e.Addr == other && !e.Verified
		}) {
			t.Errorf("%s: no STUN endpoint in %+v", c.name, fv.Endpoints)
		}
	}
}

func TestMergeErrors(t *testing.T) {
	r := newRig(t, rigOpts{})
	s := newSession(t, r, "s1", protocol.RoleInitiator, 1)
	s.probe(0, 0, srcA, false, false)
	rep := s.report(protocol.FamilyUDP4, local4, nil)
	var verr *protocol.ValidationError
	if _, _, err := s.h.mergeTest(protocol.RoleResponder, rep, nil, TraitsKey{}); !errors.As(err, &verr) || verr.Detail != "role_mismatch" {
		t.Fatalf("role mismatch: %v", err)
	}
	other := rep
	other.SessionID = "other"
	if _, _, err := s.h.mergeTest(protocol.RoleInitiator, other, nil, TraitsKey{}); !errors.As(err, &verr) || verr.Detail != "session_mismatch" {
		t.Fatalf("session mismatch: %v", err)
	}
	if _, _, err := s.h.mergeTest(protocol.RoleServer, rep, nil, TraitsKey{}); err == nil {
		t.Fatal("server role accepted")
	}
	var nilH *handle
	if _, _, err := nilH.mergeTest(protocol.RoleInitiator, rep, nil, TraitsKey{}); err == nil {
		t.Fatal("nil handle")
	}
	// junk inside an otherwise matching report never panics
	junk := rep
	junk.Families = []protocol.FamilyReport{
		{Family: "udp9"},
		{Family: protocol.FamilyUDP4, Sockets: []protocol.SocketReport{{ID: 0x80, Kind: protocol.SocketPrimary}, {ID: 0, Kind: "weird"}},
			STUN: []protocol.RowReport{{Observed: netip.MustParseAddrPort("[2001:db8::1]:5")}}, PortMap: &protocol.PortMapReport{}},
		{Family: protocol.FamilyUDP4},
	}
	view, _, err := s.h.mergeTest(protocol.RoleInitiator, junk, nil, TraitsKey{})
	if err != nil || len(view.Families) != 1 {
		t.Fatalf("junk: %v %+v", err, view)
	}
	// a panicking memory is contained
	fv, diag := mustMerge(t, s.h, protocol.RoleInitiator, rep, panicMemory{})
	if diag.MemoryPanics != 1 || fv.Traits.Provisional {
		t.Fatalf("diag %+v", diag)
	}
}

type panicMemory struct{}

func (panicMemory) Apply(TraitsKey, protocol.Traits) protocol.Traits { panic("apply") }
func (panicMemory) Observe(TraitsKey, protocol.Traits, bool)         {}

// PortAnchorMs: server monotonic ms from Register to the anchor's first probe.
func TestMergeAnchorMs(t *testing.T) {
	r := newRig(t, rigOpts{})
	s := newSession(t, r, "s1", protocol.RoleInitiator, 1)
	r.clk.Advance(700 * time.Millisecond)
	for i := range 3 {
		s.probe(0, i, netip.AddrPortFrom(srcA.Addr(), uint16(50001+i)), false, false)
		r.clk.Advance(time.Millisecond)
	}
	fv, _ := mustMerge(t, s.h, protocol.RoleInitiator, s.report(protocol.FamilyUDP4, local4, nil), nil)
	tr := fv.Traits
	if tr.Mapping != protocol.MapAPDM || tr.PortAlloc != protocol.AllocSequential || tr.PortAnchor != 50003 || tr.PortAnchorMs != 702 {
		t.Fatalf("traits %+v", tr)
	}
}

// A probe that never reached natprobe still took its port on the way
// out. The client reports the row unanswered, and the merge keeps it as a
// point of the send order: 50001 → 50003 is two sends of a sequential
// allocator, not a gap that pulls the APDM side to a pool. A row claiming
// an answer the server never saw is still dropped.
func TestMergeLostProbeKeepsOrder(t *testing.T) {
	r := newRig(t, rigOpts{})
	s := newSession(t, r, "s1", protocol.RoleInitiator, 1)
	at := func(port uint16) netip.AddrPort { return netip.AddrPortFrom(srcA.Addr(), port) }
	s.probe(0, 0, at(50001), false, false)
	lost := protocol.RowReport{Observer: r.ls[1].id, FirstSeq: s.c.codec.NextSeq(), SentMs: 1}
	s.probe(0, 2, at(50003), false, false)
	for i := range 3 {
		s.probe(1, i, at(uint16(50004+i)), false, false)
	}
	rep := s.report(protocol.FamilyUDP4, local4, map[uint8]protocol.SocketKind{1: protocol.SocketSecond})
	rows := &rep.Families[0].Sockets[0].Rows
	*rows = append([]protocol.RowReport{(*rows)[0], lost}, (*rows)[1:]...)
	fv, diag := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil)
	tr := fv.Traits
	if tr.Mapping != protocol.MapAPDM || tr.PortAlloc != protocol.AllocSequential || tr.PortStep != 1 || tr.PortAnchor != 50006 {
		t.Fatalf("traits %+v", tr)
	}
	if diag.Unverified != 0 {
		t.Fatalf("diag %+v: an unanswered row is no claim", diag)
	}
	for _, e := range fv.Endpoints {
		if e.Addr.Port() == 50002 || !e.Addr.IsValid() {
			t.Fatalf("endpoint %+v from a lost probe", e)
		}
	}
	// The same row claiming an answer is a forgery and dropped.
	(*rows)[1].Observed, (*rows)[1].RTTMs = at(50002), 9
	if _, diag := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil); diag.Unverified != 1 {
		t.Fatalf("diag %+v", diag)
	}
}

// At component level: the ADM learned in session 1 (a punch-time
// correction) makes session 2's single-IP EIM an ADM/Medium.
func TestMergeWithMemory(t *testing.T) {
	r := newRig(t, rigOpts{})
	mem := NewTraitsMemory(TraitsMemoryConfig{Clock: r.clk})
	run := func(id string, b byte) protocol.Traits {
		s := newSession(t, r, id, protocol.RoleInitiator, b)
		for i := range 3 {
			s.probe(0, i, srcA, false, false)
		}
		fv, _ := mustMerge(t, s.h, protocol.RoleInitiator, s.report(protocol.FamilyUDP4, local4, nil), mem)
		return fv.Traits
	}
	first := run("s1", 1)
	if first.Mapping != protocol.MapEIM || first.MappingConf != protocol.ConfMedium {
		t.Fatalf("first %+v", first)
	}
	final := first
	final.Mapping, final.MappingConf, final.CrossIP = protocol.MapADM, protocol.ConfHigh, true // the punch_result.traits correction
	mem.Observe(TraitsKey{ClientKey: "client-1", Family: protocol.FamilyUDP4, PublicIP: srcA.Addr()}, final, true)
	second := run("s2", 2)
	if second.Mapping != protocol.MapADM || second.MappingConf != protocol.ConfMedium || second.Provisional {
		t.Fatalf("second %+v", second)
	}
}

// A typical dual-stack probe_summary is ≤ 6 KiB; the worst
// case (12 endpoints per family and view, every field at its widest) still
// fits the message's frame cap.
func TestSummarySize(t *testing.T) {
	view := func(f protocol.Family, ip string, n int, src protocol.EndpointSource) protocol.FamilyView {
		var eps []protocol.Endpoint
		for i := range n {
			eps = append(eps, protocol.Endpoint{Addr: netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(60000+i)), Source: src, Socket: 0x83, Verified: true})
		}
		tr := protocol.Traits{Family: f, NoNAT: protocol.TriFalse, Mapping: protocol.MapAPDM, MappingConf: protocol.ConfHigh,
			Filtering: protocol.FiltNotPDF, FilteringConf: protocol.ConfHigh, PortAlloc: protocol.AllocPool, PortAllocConf: protocol.ConfMedium,
			PortStep: -64, PortVelocity: 123.25, PortAnchor: 65535, PortAnchorMs: 1 << 40, PortRangeLo: 31744, PortRangeHi: 32767,
			FirstPreserved: true, MultiExit: true, MultiHomed: true, Drifted: true, Hairpin: protocol.TriTrue, CGNAT: protocol.TriTrue,
			CrossIP: true, PublicIP: netip.MustParseAddr(ip), Observed: netip.AddrPortFrom(netip.MustParseAddr(ip), 65535), Samples: 16}
		return protocol.FamilyView{Family: f, Traits: tr, Endpoints: eps}
	}
	size := func(n6, n4 int) int {
		pv := protocol.PeerView{Families: []protocol.FamilyView{
			view(protocol.FamilyUDP6, "2001:db8:ffff:ffff:ffff:ffff:ffff:fffe", n6, protocol.EndpointSibling),
			view(protocol.FamilyUDP4, "203.0.113.254", n4, protocol.EndpointSecond)}}
		plan := minimalPlan(protocol.FamilyUDP4)
		sum := protocol.ProbeSummary{SessionID: "AAAAAAAAAAAAAAAAAAAAAAAA", Self: pv, Peer: pv,
			Pair: protocol.PairFacts{SharedFamilies: []protocol.Family{protocol.FamilyUDP6, protocol.FamilyUDP4},
				SamePublicIP:  map[protocol.Family]bool{protocol.FamilyUDP4: true, protocol.FamilyUDP6: false},
				ProbeRTTMs:    map[protocol.Role]uint32{protocol.RoleInitiator: 123, protocol.RoleResponder: 456},
				ClockOffsetMs: map[protocol.Role]int64{protocol.RoleInitiator: -1234, protocol.RoleResponder: 5678}},
			Transport: protocol.TransportPick{Mode: "quic"}, Timeouts: protocol.DefaultTimeouts(), Plan: plan}
		f, err := msgframe.Encode(sum)
		if err != nil {
			t.Fatal(err)
		}
		return len(f.Payload)
	}
	typical, worst := size(3, 6), size(12, 12)
	t.Logf("summary: typical %d B, worst case %d B, cap %d B", typical, worst, protocol.MsgProbeSummary.MaxPayload())
	if typical > 6<<10 {
		t.Fatalf("a typical dual-stack summary of %d B > 6 KiB", typical)
	}
	if worst > protocol.MsgProbeSummary.MaxPayload() {
		t.Fatalf("the worst-case summary of %d B exceeds the frame cap", worst)
	}
}

// The overlay addresses a client reports become unverified overlay
// endpoints at its primary socket's port; they are no LAN endpoints.
func TestMergeOverlay(t *testing.T) {
	r := newRig(t, rigOpts{})
	s := newSession(t, r, "s1", protocol.RoleInitiator, 1)
	s.probe(0, 0, srcA, false, false)
	rep := s.report(protocol.FamilyUDP4, local4, nil)
	rep.Families[0].Overlay = []netip.Addr{netip.MustParseAddr("100.101.102.103")}
	fv, _ := mustMerge(t, s.h, protocol.RoleInitiator, rep, nil)
	want := netip.MustParseAddrPort("100.101.102.103:40000") // the primary socket's port (local4[0])
	n := 0
	for _, e := range fv.Endpoints {
		switch {
		case e.Source == protocol.EndpointOverlay && e.Addr == want && !e.Verified:
			n++
		case e.Addr.Addr() == want.Addr():
			t.Fatalf("overlay address as %s endpoint", e.Source)
		}
	}
	if n != 1 {
		t.Fatalf("endpoints %+v", fv.Endpoints)
	}
}

// mergeTest is Merge with a typed memory and key and the default options.
func (h *handle) mergeTest(role protocol.Role, rep protocol.ProbeReport, mem TraitsMemory, key TraitsKey) (protocol.PeerView, nat.MergeDiag, error) {
	return h.mergeWith(role, rep, mem, key, mergeOptions{})
}

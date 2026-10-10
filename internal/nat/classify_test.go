package nat

import (
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Single IP, consistent observers → EIM/Medium and usable; two
// answers are still Medium.
func TestSingleIPEIMIsMedium(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:40000", "203.0.113.5:40000", "203.0.113.5:40000")
	tr := f.t.Classify()
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfMedium)
	if !tr.ObservedUsable() || tr.Samples != 3 || tr.Observed != ap("203.0.113.5:40000") || tr.PublicIP != ip("203.0.113.5") {
		t.Fatalf("traits %+v", tr)
	}
	if tr.NoNAT != protocol.TriFalse || tr.CrossIP || tr.MultiExit || tr.Drifted || !tr.Provisional {
		t.Fatalf("flags %+v", tr)
	}
	wantAlloc(t, tr, protocol.AllocPreserving, protocol.ConfHigh)

	f = newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:41000", "", "203.0.113.5:41000")
	tr = f.t.Classify()
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfMedium)
	if tr.Samples != 2 || tr.PortAlloc != protocol.AllocUnknown {
		t.Fatalf("traits %+v", tr)
	}

	// one sample is not enough: Unknown/Low ("m ≤ 1")
	f = newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:41000", "", "")
	wantMapping(t, f.t.Classify(), protocol.MapUnknown, protocol.ConfLow)
	// none: Unknown/None, Samples 0
	f = newFixture("192.168.1.10:40000")
	f.primary("", "", "")
	tr = f.t.Classify()
	wantMapping(t, tr, protocol.MapUnknown, protocol.ConfNone)
	if tr.Samples != 0 || tr.Observed.IsValid() || tr.NoNAT != protocol.TriUnknown {
		t.Fatalf("traits %+v", tr)
	}
}

// Cross-IP sources refine a single-IP EIM.
func TestCrossIPEvidence(t *testing.T) {
	base := func() *fixture {
		f := newFixture("192.168.1.10:40000")
		f.primary("203.0.113.5:41000", "203.0.113.5:41000", "203.0.113.5:41000")
		return f
	}
	f := base()
	f.peer("192.0.2.9:7000", "203.0.113.5:41000")
	tr := f.t.Classify()
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfHigh)
	if !tr.CrossIP {
		t.Fatal("CrossIP not set")
	}

	f = base()
	f.peer("192.0.2.9:7000", "203.0.113.5:41007")
	tr = f.t.Classify()
	wantMapping(t, tr, protocol.MapADM, protocol.ConfHigh)
	if !tr.EndpointDependent() || tr.MultiExit {
		t.Fatalf("traits %+v", tr)
	}

	f = base()
	f.peer("192.0.2.9:7000", "203.0.113.77:41000")
	tr = f.t.Classify()
	if !tr.MultiExit {
		t.Fatalf("MultiExit not set: %+v", tr)
	}
	wantMapping(t, tr, protocol.MapUnknown, protocol.ConfLow)

	// natprobe's alt group (solicited) is a cross-IP source too; STUN is
	// only a hint (TestSTUNIsAHint)
	f = base()
	k := f.send(v4P, SourceServerAlt, 8)
	f.t.Record(k, ap("203.0.113.5:41000"), f.at, time.Millisecond, 3)
	wantMapping(t, f.t.Classify(), protocol.MapEIM, protocol.ConfHigh)
	f = base()
	k = f.send(v4P, SourceServerAlt, 8)
	f.t.Record(k, ap("203.0.113.5:41009"), f.at, time.Millisecond, 3)
	wantMapping(t, f.t.Classify(), protocol.MapADM, protocol.ConfHigh)

	// a private peer view (same LAN, hairpin) does not count
	f = base()
	f.peer("192.168.1.20:7000", "192.168.1.10:40000")
	tr = f.t.Classify()
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfMedium)
	if tr.CrossIP || tr.MultiExit {
		t.Fatalf("private peer view counted: %+v", tr)
	}
}

// STUN is a hint. Agreeing with natprobe it raises nothing
// above the Medium of natprobe's single-IP samples and sets no CrossIP;
// contradicting natprobe — another port, another IP, a second value — it
// changes no conclusion and is counted (STUNConflicts), and another port of
// the IP natprobe saw marks the mapping path dependent; a STUN server that
// never answers leaves the classification as it was.
func TestSTUNIsAHint(t *testing.T) {
	stun := func(f *fixture, obs uint8, vals ...string) {
		for _, v := range vals {
			f.t.Record(PointKey{Socket: v4P, Source: SourceSTUN, Observer: obs}, ap(v), f.at, 0, 0)
		}
	}
	eim := func() *fixture {
		f := newFixture("192.168.1.10:40000")
		f.primary("203.0.113.5:41000", "203.0.113.5:41000", "203.0.113.5:41000")
		return f
	}
	plain := eim().t.Classify()
	for _, c := range []struct {
		name          string
		vals          []string
		conflicts     int
		pathDependent bool
	}{
		{"agrees", []string{"203.0.113.5:41000"}, 0, false},
		{"another port", []string{"203.0.113.5:41009"}, 1, true},
		{"another ip", []string{"203.0.113.77:41000"}, 1, false},
		{"two values", []string{"203.0.113.5:41000", "203.0.113.5:41500"}, 0, false},
	} {
		f := eim()
		stun(f, 0, c.vals...)
		tr := f.t.Classify()
		want := plain
		want.PathDependent = c.pathDependent
		if tr != want {
			t.Errorf("%s: traits %+v, want %+v", c.name, tr, want)
		}
		if n := f.t.STUNConflicts(); n != c.conflicts {
			t.Errorf("%s: %d conflicts, want %d", c.name, n, c.conflicts)
		}
	}
	wantMapping(t, plain, protocol.MapEIM, protocol.ConfMedium)
	if plain.CrossIP || plain.MultiExit || plain.Drifted {
		t.Fatalf("traits %+v", plain)
	}

	// Two STUN servers, one agreeing and one at another IP: one conflict.
	f := eim()
	stun(f, 0, "203.0.113.5:41000")
	stun(f, 1, "198.18.0.9:41000")
	if n := f.t.STUNConflicts(); n != 1 {
		t.Fatalf("%d conflicts", n)
	}
	// natprobe's own evidence still decides: the peer raises to High.
	f.peer("192.0.2.9:7000", "203.0.113.5:41000")
	if tr := f.t.Classify(); tr.MappingConf != protocol.ConfHigh || !tr.CrossIP || tr.MultiExit {
		t.Fatalf("with the peer: %+v", tr)
	}

	// On a mapping natprobe found endpoint dependent another port is
	// expected: no conflict. Neither is a port the alt group saw vary.
	f = newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:50001", "203.0.113.5:50002", "203.0.113.5:50003")
	stun(f, 0, "203.0.113.5:50010")
	if tr := f.t.Classify(); tr.Mapping != protocol.MapAPDM || f.t.STUNConflicts() != 0 {
		t.Fatalf("apdm: %+v, %d conflicts", tr, f.t.STUNConflicts())
	}
	f = eim()
	k := f.send(v4P, SourceServerAlt, 8)
	f.t.Record(k, ap("203.0.113.5:41100"), f.at, time.Millisecond, 3)
	stun(f, 0, "203.0.113.5:41200")
	if tr := f.t.Classify(); tr.Mapping != protocol.MapADM || tr.MappingConf != protocol.ConfHigh || f.t.STUNConflicts() != 0 {
		t.Fatalf("adm: %+v, %d conflicts", tr, f.t.STUNConflicts())
	}

	// Nothing to compare with: no server sample, no primary socket.
	f = newFixture("192.168.1.10:40000")
	f.primary("", "", "")
	stun(f, 0, "203.0.113.5:41000")
	if n := f.t.STUNConflicts(); n != 0 {
		t.Fatalf("no samples: %d conflicts", n)
	}
	if n := NewTable(protocol.FamilyUDP4, nil, mainObservers()).STUNConflicts(); n != 0 {
		t.Fatalf("no primary: %d conflicts", n)
	}
}

// Several server IPs in the main set compare across addresses directly.
func TestMultiGroupMainObservers(t *testing.T) {
	obs := []Observer{
		{ID: 0, Addr: ap("198.51.100.1:3478"), Group: 0},
		{ID: 1, Addr: ap("198.51.100.1:3479"), Group: 0},
		{ID: 8, Addr: ap("198.51.100.9:3478"), Group: 1},
		{ID: 9, Addr: ap("198.51.100.9:3479"), Group: 1},
	}
	run := func(vals ...string) protocol.Traits {
		tb := NewTable(protocol.FamilyUDP4, []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("10.0.0.2:5000")}}, obs)
		for i, o := range []uint8{0, 1, 8, 9} {
			k := PointKey{Socket: v4P, Source: SourceServer, Observer: o}
			tb.NoteSent(k, uint32(i+1), time.Duration(i))
			if vals[i] != "" {
				tb.Record(k, ap(vals[i]), time.Duration(i), 0, 1)
			}
		}
		return tb.Classify()
	}
	tr := run("203.0.113.5:6000", "203.0.113.5:6000", "203.0.113.5:6000", "203.0.113.5:6000")
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfHigh)
	if !tr.CrossIP {
		t.Fatal("CrossIP")
	}
	wantMapping(t, run("203.0.113.5:6000", "203.0.113.5:6000", "203.0.113.5:6100", "203.0.113.5:6100"), protocol.MapADM, protocol.ConfHigh)
	wantMapping(t, run("203.0.113.5:6000", "", "203.0.113.5:6100", ""), protocol.MapAPDM, protocol.ConfLow)
	wantMapping(t, run("203.0.113.5:6000", "203.0.113.5:6001", "203.0.113.5:6002", "203.0.113.5:6003"), protocol.MapAPDM, protocol.ConfHigh)
}

func TestAPDMConfidence(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:50001", "203.0.113.5:50002")
	tr := f.t.Classify()
	wantMapping(t, tr, protocol.MapAPDM, protocol.ConfMedium)
	if tr.Drifted || tr.PortAlloc != protocol.AllocUnknown { // one difference only
		t.Fatalf("traits %+v", tr)
	}
	f = newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:50001", "203.0.113.5:50002", "203.0.113.5:50003")
	wantMapping(t, f.t.Classify(), protocol.MapAPDM, protocol.ConfHigh)

	// m = 2 but the second socket varies too → High
	f = newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:50001", "203.0.113.5:50002", "")
	f.probe(v4S, 0, "203.0.113.5:50010")
	f.probe(v4S, 1, "203.0.113.5:50011")
	wantMapping(t, f.t.Classify(), protocol.MapAPDM, protocol.ConfHigh)
}

// Drift versus mapping behaviour.
func TestDriftVersusAPDM(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:41000", "203.0.113.5:41000", "203.0.113.5:41000")
	k := PointKey{Socket: v4P, Source: SourceServer, Observer: 0}
	if drift := f.t.Record(k, ap("203.0.113.5:41000"), time.Second, 0, 9); drift {
		t.Fatal("the same value is not drift")
	}
	if drift := f.t.Record(k, ap("203.0.113.5:42000"), 2*time.Second, 0, 9); !drift {
		t.Fatal("a second value at one point is drift")
	}
	tr := f.t.Classify()
	if !tr.Drifted || tr.MappingConf > protocol.ConfLow {
		t.Fatalf("traits %+v", tr)
	}
	// the first value is still the sample
	if tr.Observed != ap("203.0.113.5:41000") || tr.Mapping != protocol.MapEIM {
		t.Fatalf("traits %+v", tr)
	}
	f = newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:41000", "203.0.113.5:41001", "203.0.113.5:41002")
	if tr := f.t.Classify(); tr.Drifted || tr.Mapping != protocol.MapAPDM {
		t.Fatalf("traits %+v", tr)
	}
	// a server row with a recorded change is drift too
	tb := NewTable(protocol.FamilyUDP4, []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("10.0.0.2:1")}}, mainObservers())
	tb.RecordServer(Row{Key: k, Observed: ap("203.0.113.5:41000"), Changes: 2, FirstSeq: 1})
	tb.RecordServer(Row{Key: PointKey{Socket: v4P, Source: SourceServer, Observer: 1}, Observed: ap("203.0.113.5:41000"), FirstSeq: 2})
	if tr := tb.Classify(); !tr.Drifted || tr.MappingConf != protocol.ConfLow {
		t.Fatalf("traits %+v", tr)
	}
}

// A peer point whose value changed is drift, not cross-address evidence.
// Only the point's first value is compared with the main observers, so a
// consistent EIM stays EIM (capped to Low by the drift) instead of becoming
// ADM.
func TestPeerDriftIsNotADM(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:40000", "203.0.113.5:40000", "203.0.113.5:40000")
	f.peer("198.18.0.9:50000", "203.0.113.5:40000") // the peer saw our mapping
	f.peer("198.18.0.9:50000", "203.0.113.5:40100") // same point, rebuilt mapping
	tr := f.t.Classify()
	if !tr.Drifted {
		t.Fatal("drift not detected")
	}
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfLow)
	if tr.MultiExit {
		t.Fatalf("traits %+v", tr)
	}
}

// A drifted peer point whose new value is on another public IP
// is not MultiExit either.
func TestPeerDriftIsNotMultiExit(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:40000", "203.0.113.5:40000", "203.0.113.5:40000")
	f.peer("198.18.0.9:50000", "203.0.113.5:40000")
	f.peer("198.18.0.9:50000", "203.0.113.77:40000")
	tr := f.t.Classify()
	if tr.MultiExit || !tr.Drifted {
		t.Fatalf("drifted peer point taken as MultiExit: %+v", tr)
	}
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfLow)

	// Two different peer points (different destinations) that disagree are
	// still mapping evidence: the first values differ across points.
	f = newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:40000", "203.0.113.5:40000", "203.0.113.5:40000")
	f.peer("198.18.0.9:50000", "203.0.113.5:40000")
	f.peer("198.18.0.9:50001", "203.0.113.77:40000")
	if tr := f.t.Classify(); !tr.MultiExit || tr.Drifted {
		t.Fatalf("two disagreeing peer points: %+v", tr)
	}
}

// Filtering.
func TestFiltering(t *testing.T) {
	eim := func() *fixture {
		f := newFixture("192.168.1.10:40000")
		f.primary("203.0.113.5:41000", "203.0.113.5:41000", "203.0.113.5:41000")
		return f
	}
	f := eim()
	f.filter(1, 1, 0, 0, 0)
	f.filter(2, 1, 0, 0, 0)
	tr := f.t.Classify()
	wantFiltering(t, tr, protocol.FiltPDF, protocol.ConfHigh)
	if !tr.NeedsSimultaneous() {
		t.Fatal("PDF needs simultaneous sends")
	}
	f = eim()
	f.filter(1, 1, 0, 0, 0)
	wantFiltering(t, f.t.Classify(), protocol.FiltPDF, protocol.ConfMedium)
	f = eim()
	f.filter(1, 1, 1, 0, 0)
	f.filter(2, 1, 0, 0, 0)
	wantFiltering(t, f.t.Classify(), protocol.FiltNotPDF, protocol.ConfHigh)
	f = eim()
	wantFiltering(t, f.t.Classify(), protocol.FiltUnknown, protocol.ConfNone)
	f = eim()
	f.filter(0, 0, 0, 1, 1)
	wantFiltering(t, f.t.Classify(), protocol.FiltEIF, protocol.ConfHigh)
	f = eim()
	f.filter(0, 0, 0, 1, 0)
	f.filter(1, 1, 1, 0, 0)
	wantFiltering(t, f.t.Classify(), protocol.FiltADF, protocol.ConfMedium)
	f = eim()
	f.filter(0, 0, 0, 2, 0)
	f.filter(1, 1, 1, 0, 0)
	wantFiltering(t, f.t.Classify(), protocol.FiltADF, protocol.ConfHigh)
	// an unsolicited inbound packet while punching → EIF
	f = eim()
	f.t.NoteUnsolicitedInbound(v4P, ip("192.0.2.9"))
	wantFiltering(t, f.t.Classify(), protocol.FiltEIF, protocol.ConfHigh)
	// an alt declared and not seen, no extra seen: undecided
	f = eim()
	f.filter(0, 0, 0, 1, 0)
	wantFiltering(t, f.t.Classify(), protocol.FiltUnknown, protocol.ConfNone)
	// evidence of another socket or of an unknown observer does not count
	f = eim()
	f.t.AddFilter(FilterEvidence{Socket: v4S, Observer: 1, ExtraDeclared: 1, ExtraSeen: 1})
	f.t.AddFilter(FilterEvidence{Socket: v4P, Observer: 30, ExtraDeclared: 1, ExtraSeen: 1})
	wantFiltering(t, f.t.Classify(), protocol.FiltUnknown, protocol.ConfNone)
}

// IPv6, with and without NAT.
func TestIPv6(t *testing.T) {
	p6 := SocketID(protocol.FamilyUDP6, IndexPrimary)
	obs := []Observer{
		{ID: 0, Addr: ap("[2001:db8::1]:3478")},
		{ID: 1, Addr: ap("[2001:db8::1]:3479")},
	}
	table := func(local string, vals ...string) *ObsTable {
		tb := NewTable(protocol.FamilyUDP6, []SocketMeta{{ID: p6, Kind: protocol.SocketPrimary, Local: ap(local)}}, obs)
		for i, v := range vals {
			k := PointKey{Socket: p6, Source: SourceServer, Observer: uint8(i)}
			tb.NoteSent(k, uint32(i+1), 0)
			tb.Record(k, ap(v), 1, 0, 1)
		}
		return tb
	}
	tr := table("[2001:db8:1::5]:6000", "[2001:db8:1::5]:6000", "[2001:db8:1::5]:6000").Classify()
	if tr.NoNAT != protocol.TriTrue || !tr.ObservedUsable() {
		t.Fatalf("traits %+v", tr)
	}
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfHigh)
	wantAlloc(t, tr, protocol.AllocPreserving, protocol.ConfHigh)
	// NPTv6: the IP changes, the port is kept → v4 rules: EIM/Medium, preserving
	tr = table("[fd00::5]:6000", "[2001:db8:1::5]:6000", "[2001:db8:1::5]:6000").Classify()
	if tr.NoNAT != protocol.TriFalse {
		t.Fatalf("traits %+v", tr)
	}
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfMedium)
	wantAlloc(t, tr, protocol.AllocPreserving, protocol.ConfHigh)
	// contradiction: one observer sees the local address, another does not
	tr = table("[2001:db8:1::5]:6000", "[2001:db8:1::5]:6000", "[2001:db8:1::5]:6001").Classify()
	if tr.NoNAT != protocol.TriUnknown || tr.Mapping != protocol.MapAPDM {
		t.Fatalf("traits %+v", tr)
	}
	// NoNAT + NotPDF = open (EIF)
	tb := table("[2001:db8:1::5]:6000", "[2001:db8:1::5]:6000", "[2001:db8:1::5]:6000")
	tb.AddFilter(FilterEvidence{Socket: p6, Observer: 1, ExtraDeclared: 1, ExtraSeen: 1})
	tr = tb.Classify()
	wantFiltering(t, tr, protocol.FiltEIF, protocol.ConfHigh)
	if DisplayName(tr) != "v6:Public" || Fingerprint(tr) != "v6|NONAT|EIF" {
		t.Fatalf("name %q fingerprint %q", DisplayName(tr), Fingerprint(tr))
	}
}

// Private observers take no part in the mapping or MultiExit.
func TestPrivateObserversIgnored(t *testing.T) {
	obs := append(mainObservers(), Observer{ID: 16, Addr: ap("10.1.0.1:3478"), Group: 2})
	tb := NewTable(protocol.FamilyUDP4, []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("10.1.0.20:40000")}}, obs)
	for i, o := range []uint8{0, 1, 2, 16} {
		k := PointKey{Socket: v4P, Source: SourceServer, Observer: o}
		tb.NoteSent(k, uint32(i+1), 0)
		v := "203.0.113.5:41000"
		if o == 16 {
			v = "10.1.0.20:40000" // the LAN observer sees the private address
		}
		tb.Record(k, ap(v), 1, 0, 1)
	}
	tr := tb.Classify()
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfMedium)
	if tr.MultiExit || tr.Samples != 3 || tr.NoNAT != protocol.TriFalse {
		t.Fatalf("traits %+v", tr)
	}
	// a LAN-only deployment (every observer private) classifies in private scope
	lan := []Observer{{ID: 0, Addr: ap("127.0.0.1:3478")}, {ID: 1, Addr: ap("127.0.0.1:3479")}}
	tb = NewTable(protocol.FamilyUDP4, []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("127.0.0.1:5000")}}, lan)
	for i := range 2 {
		k := PointKey{Socket: v4P, Source: SourceServer, Observer: uint8(i)}
		tb.NoteSent(k, uint32(i+1), 0)
		tb.Record(k, ap("127.0.0.1:5000"), 1, 0, 1)
	}
	tr = tb.Classify()
	if tr.NoNAT != protocol.TriTrue || tr.Samples != 2 {
		t.Fatalf("loopback traits %+v", tr)
	}
	wantMapping(t, tr, protocol.MapEIM, protocol.ConfHigh)
	// only alt or scope-less observers: global scope, nothing to classify
	tb = NewTable(protocol.FamilyUDP4, []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("10.0.0.2:1")}},
		[]Observer{{ID: 8, Addr: ap("198.51.100.2:3478"), Alt: true}})
	if tb.classScopeLocked() != ScopeGlobal || tb.Classify().Samples != 0 {
		t.Fatal("alt-only table")
	}
}

func TestMultiHomedAndCGNAT(t *testing.T) {
	sibling := SocketMeta{ID: v4B, Kind: protocol.SocketSibling, Local: ap("10.8.0.2:40000")}
	f := newFixture("192.168.1.10:40000", sibling)
	f.primary("203.0.113.5:41000", "203.0.113.5:41000", "203.0.113.5:41000")
	f.probe(v4B, 0, "198.18.0.7:41000")
	tr := f.t.Classify()
	if !tr.MultiHomed || tr.MultiExit {
		t.Fatalf("traits %+v", tr)
	}
	// a sibling through the same exit
	f = newFixture("192.168.1.10:40000", sibling)
	f.primary("203.0.113.5:41000", "203.0.113.5:41000")
	f.probe(v4B, 0, "203.0.113.5:41100")
	if tr := f.t.Classify(); tr.MultiHomed {
		t.Fatalf("traits %+v", tr)
	}
	// a mapped external address in shared space while the server sees a public IP
	f = newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:41000", "203.0.113.5:41000")
	f.t.Record(PointKey{Socket: v4P, Source: SourcePortMap}, ap("100.70.1.2:40000"), 1, 0, 0)
	if tr := f.t.Classify(); tr.CGNAT != protocol.TriTrue {
		t.Fatalf("traits %+v", tr)
	}
	// a local address in shared space
	f = newFixture("100.64.3.4:40000")
	f.primary("203.0.113.5:41000", "203.0.113.5:41000")
	if tr := f.t.Classify(); tr.CGNAT != protocol.TriTrue {
		t.Fatalf("traits %+v", tr)
	}
	// mapped external = public IP → no CGNAT
	f = newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:41000", "203.0.113.5:41000")
	f.t.Record(PointKey{Socket: v4P, Source: SourcePortMap}, ap("203.0.113.5:40000"), 1, 0, 0)
	if tr := f.t.Classify(); tr.CGNAT != protocol.TriFalse {
		t.Fatalf("traits %+v", tr)
	}
	f = newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:41000", "203.0.113.5:41000")
	if tr := f.t.Classify(); tr.CGNAT != protocol.TriUnknown {
		t.Fatalf("traits %+v", tr)
	}
	// no sample: a shared-space local address still says CGNAT
	f = newFixture("100.64.3.4:40000")
	if tr := f.t.Classify(); tr.CGNAT != protocol.TriTrue || tr.Samples != 0 {
		t.Fatalf("traits %+v", tr)
	}
}

func TestHairpinCarried(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:41000", "203.0.113.5:41000")
	f.t.SetHairpin(protocol.TriFalse)
	f.t.SetHairpin(protocol.Tri(9)) // invalid: ignored
	if tr := f.t.Classify(); tr.Hairpin != protocol.TriFalse {
		t.Fatalf("hairpin %v", tr.Hairpin)
	}
}

func TestNoPrimarySocket(t *testing.T) {
	tb := NewTable(protocol.FamilyUDP4, nil, mainObservers())
	tr := tb.Classify()
	if tr.Family != protocol.FamilyUDP4 || tr.Samples != 0 || tr.Mapping != protocol.MapUnknown || !tr.Provisional {
		t.Fatalf("traits %+v", tr)
	}
}

// Values of another family never enter a table: they would make the report
// fail validation (a STUN server answering a v4 request with a v6 address).
func TestForeignFamilyValuesIgnored(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:41000", "203.0.113.5:41000")
	for _, bad := range []netip.AddrPort{ap("[2001:db8::7]:5000"), ap("203.0.113.5:0"), ap("0.0.0.0:5"), ap("224.0.0.1:5"), {}} {
		if f.t.Record(PointKey{Socket: v4P, Source: SourceSTUN}, bad, 1, 0, 0) {
			t.Fatalf("%v reported drift", bad)
		}
		f.t.RecordServer(Row{Key: PointKey{Socket: v4P, Source: SourceServer, Observer: 2}, Observed: bad})
	}
	if n := len(f.t.rows); n != 2 {
		t.Fatalf("%d rows", n)
	}
	fr := f.t.Snapshot()
	if err := validReport(fr); err != nil || len(fr.STUN) != 0 {
		t.Fatalf("snapshot %+v: %v", fr, err)
	}
}

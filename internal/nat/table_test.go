package nat

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

func TestSocketIDs(t *testing.T) {
	if SocketID(protocol.FamilyUDP4, 0) != 0 || SocketID(protocol.FamilyUDP6, 1) != 0x81 || SocketID(protocol.FamilyUDP4, 200) != 200&0x7F {
		t.Fatal("SocketID")
	}
	if SocketFamily(0x81) != protocol.FamilyUDP6 || SocketFamily(3) != protocol.FamilyUDP4 {
		t.Fatal("SocketFamily")
	}
	if SocketID(protocol.FamilyUDP6, IndexSandwich) != 0x84 {
		t.Fatal("sandwich helper id")
	}
}

func TestScope(t *testing.T) {
	cases := map[string]Scope{
		"203.0.113.5": ScopeGlobal, "2001:db8::1": ScopeGlobal, "10.1.2.3": ScopePrivate, "192.168.0.1": ScopePrivate,
		"172.16.0.1": ScopePrivate, "100.64.0.1": ScopePrivate, "100.127.255.255": ScopePrivate, "100.128.0.1": ScopeGlobal,
		"127.0.0.1": ScopePrivate, "169.254.1.1": ScopePrivate, "fe80::1": ScopePrivate, "fd00::1": ScopePrivate,
		"::1": ScopePrivate, "0.0.0.0": ScopeNone, "::": ScopeNone, "224.0.0.1": ScopeNone, "ff02::1": ScopeNone,
		"255.255.255.255": ScopeNone, "::ffff:10.0.0.1": ScopePrivate, "::ffff:203.0.113.1": ScopeGlobal,
	}
	for s, want := range cases {
		if got := ScopeOf(ip(s)); got != want {
			t.Errorf("ScopeOf(%s) = %d, want %d", s, got, want)
		}
	}
	if ScopeOf(netip.Addr{}) != ScopeNone || IsCGN(ip("2001:db8::1")) {
		t.Error("zero address / v6 CGN")
	}
}

func TestObserversParse(t *testing.T) {
	specs := []protocol.ObserverSpec{
		{ID: 0, Addr: ap("198.51.100.1:3478")},
		{ID: 1, Addr: ap("198.51.100.1:3479")},
		{ID: 1, Addr: ap("198.51.100.1:3480")},          // repeated id
		{ID: 2, Addr: ap("198.51.100.1:3479")},          // repeated address
		{ID: 3, Addr: ap("[2001:db8::1]:3478")},         // other family
		{ID: 5, Addr: ap("198.51.100.1:0")},             // port 0
		{ID: 6, Addr: ap("[::ffff:198.51.100.2]:3478")}, // v4-mapped
		{ID: 7, Addr: ap("0.0.0.0:3478")},               // unspecified
		{ID: 9, Addr: ap("255.255.255.255:3478")},       // broadcast
		{ID: 8, Addr: ap("10.0.0.1:3478"), Group: 1, Alt: true},
	}
	got := Observers(protocol.FamilyUDP4, specs)
	if len(got) != 4 || got[0].ID != 0 || got[1].ID != 1 || got[2].ID != 6 || got[2].Addr != ap("198.51.100.2:3478") ||
		got[3].Scope != ScopePrivate || !got[3].Alt || got[3].Group != 1 || got[0].Scope != ScopeGlobal {
		t.Fatalf("observers %+v", got)
	}
	if v6 := Observers(protocol.FamilyUDP6, specs); len(v6) != 1 || v6[0].ID != 3 {
		t.Fatalf("v6 observers %+v", v6)
	}
	if Observers("udp9", specs) != nil {
		t.Fatal("bad family")
	}
	var many []protocol.ObserverSpec
	for i := range 40 {
		many = append(many, protocol.ObserverSpec{ID: uint8(i), Addr: netip.AddrPortFrom(ip("198.51.100.1"), uint16(1000+i))})
	}
	if n := len(Observers(protocol.FamilyUDP4, many)); n != maxObservers {
		t.Fatalf("%d observers", n)
	}
}

func TestNewTableFilters(t *testing.T) {
	socks := []SocketMeta{
		{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("10.0.0.2:1")},
		{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("10.0.0.2:1")},   // repeated
		{ID: 0x80, Kind: protocol.SocketPrimary, Local: ap("[fd00::2]:1")}, // other family
		{ID: v4S, Kind: "warmup", Local: ap("10.0.0.2:2")},                 // unknown kind
		{ID: v4B, Kind: protocol.SocketSibling, Local: ap("[::ffff:10.0.0.3]:1")},
	}
	obs := append(mainObservers(), Observer{ID: 0, Addr: ap("198.51.100.3:1")}, Observer{ID: 30, Addr: ap("[2001:db8::1]:1")},
		Observer{ID: 31}, Observer{ID: 40, Scope: ScopePrivate, Alt: true})
	tb := NewTable(protocol.FamilyUDP4, socks, obs)
	if s := tb.Sockets(); len(s) != 2 || s[1].ID != v4B || s[1].Local != ap("10.0.0.3:1") {
		t.Fatalf("sockets %+v", s)
	}
	if len(tb.observers) != 5 || tb.observers[4].ID != 40 {
		t.Fatalf("observers %+v", tb.observers)
	}
	if !tb.AddSocket(SocketMeta{ID: v4S, Kind: protocol.SocketSecond, Local: ap("10.0.0.2:2")}) || !tb.AddSocket(SocketMeta{ID: v4S, Kind: protocol.SocketSecond}) {
		t.Fatal("AddSocket")
	}
	for i := uint8(5); i < 12; i++ {
		tb.AddSocket(SocketMeta{ID: i, Kind: protocol.SocketSibling, Local: ap("10.0.0.9:1")})
	}
	if len(tb.Sockets()) != maxSockets || tb.AddSocket(SocketMeta{ID: 20, Kind: protocol.SocketSibling}) {
		t.Fatalf("%d sockets", len(tb.Sockets()))
	}
	if tb.family != protocol.FamilyUDP4 {
		t.Fatal("family")
	}
}

func TestRecordSemantics(t *testing.T) {
	tb := NewTable(protocol.FamilyUDP4, []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("10.0.0.2:1")}}, mainObservers())
	k := PointKey{Socket: v4P, Source: SourceServer, Observer: 0}
	tb.NoteSent(k, 5, 2*time.Millisecond)
	tb.NoteSent(k, 9, 9*time.Millisecond) // a retransmission keeps the first send
	if tb.Record(k, netip.AddrPort{}, 1, 0, 0) {
		t.Fatal("invalid value recorded")
	}
	tb.Record(k, ap("[::ffff:203.0.113.5]:41000"), 30*time.Millisecond, 25*time.Millisecond, 11)
	tb.Record(k, ap("203.0.113.5:41000"), 40*time.Millisecond, 18*time.Millisecond, 12)
	tb.Record(k, ap("203.0.113.5:41000"), 41*time.Millisecond, 0, 12) // unknown RTT keeps the minimum
	rows := tb.rows
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	r := rows[0]
	if r.Observed != ap("203.0.113.5:41000") || r.FirstSeq != 5 || r.FirstSent != 2*time.Millisecond ||
		r.RTT != 18*time.Millisecond || r.Cookie != 12 || r.FirstSeen != 30*time.Millisecond || r.LastSeen != 41*time.Millisecond {
		t.Fatalf("row %+v", r)
	}
	// a new value keeps the point's first seq and send time
	tb.Record(k, ap("203.0.113.5:42000"), 50*time.Millisecond, 0, 13)
	rows = tb.rows
	if len(rows) != 2 || rows[1].FirstSeq != 5 || rows[1].FirstSent != 2*time.Millisecond {
		t.Fatalf("rows %+v", rows)
	}
	// the first value again: still drift (two values at the point)
	if !tb.Record(k, ap("203.0.113.5:41000"), 60*time.Millisecond, 0, 14) {
		t.Fatal("A→B→A is drift")
	}
	// a point that was never sent to: unknown send time
	pk := PointKey{Socket: v4P, Source: SourcePeer, Peer: ap("192.0.2.1:9")}
	tb.Record(pk, ap("203.0.113.5:41000"), 1, 0, 0)
	if rows = tb.rows; rows[2].FirstSent != -1 || rows[2].FirstSeq != 0 {
		t.Fatalf("peer row %+v", rows[2])
	}
	for range 300 {
		tb.Record(pk, ap("203.0.113.5:41000"), 1, 0, 0)
	}
	if len(tb.rows) != 3 {
		t.Fatalf("a repeated value added rows: %+v", tb.rows)
	}
}

// At most 64 rows; the oldest rows of other sockets go first.
func TestRowBound(t *testing.T) {
	socks := []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("10.0.0.2:1")}, {ID: v4B, Kind: protocol.SocketSibling, Local: ap("10.0.0.3:1")}}
	tb := NewTable(protocol.FamilyUDP4, socks, mainObservers())
	tb.Record(PointKey{Socket: v4B, Source: SourceServer, Observer: 0}, ap("203.0.113.5:1"), 1, 0, 0)
	for i := range 100 {
		tb.Record(PointKey{Socket: v4P, Source: SourcePeer, Peer: netip.AddrPortFrom(ip("192.0.2.1"), uint16(i+1))}, ap("203.0.113.5:2"), 1, 0, 0)
	}
	rows := tb.rows
	if len(rows) != maxRows {
		t.Fatalf("%d rows", len(rows))
	}
	for _, r := range rows {
		if r.Key.Socket == v4B {
			t.Fatal("the sibling row should have been evicted first")
		}
	}
	// only primary rows left: new rows are dropped
	if rows[maxRows-1].Key.Peer.Port() != maxRows {
		t.Fatalf("last row %+v", rows[maxRows-1])
	}
	for range 30 {
		tb.AddFilter(FilterEvidence{Socket: v4P, Observer: uint8(len(tb.filters))})
		tb.NoteUnsolicitedInbound(v4P, netip.AddrFrom4([4]byte{192, 0, 2, byte(len(tb.inbound) + 1)}))
	}
	if len(tb.filters) != maxFilters || len(tb.inbound) != maxInbound {
		t.Fatalf("filters %d inbound %d", len(tb.filters), len(tb.inbound))
	}
	tb.NoteUnsolicitedInbound(v4P, netip.Addr{})
	tb.NoteUnsolicitedInbound(v4P, ip("192.0.2.1")) // repeated
	tb.AddFilter(FilterEvidence{Socket: v4P, Observer: 0, ExtraDeclared: 200, ExtraSeen: 1})
	tb.AddFilter(FilterEvidence{Socket: v4P, Observer: 0, ExtraDeclared: 200, ExtraSeen: 1})
	if f := tb.filters[0]; f.ExtraDeclared != 255 || f.ExtraSeen != 2 || len(tb.inbound) != maxInbound {
		t.Fatalf("filter %+v", f)
	}
}

func TestSnapshot(t *testing.T) {
	f := newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:50001", "", "203.0.113.5:50003")
	f.probe(v4S, 0, "203.0.113.5:50010")
	k := f.send(v4P, SourceServerAlt, 8)
	f.t.Record(k, ap("203.0.113.5:50020"), f.at, 0, 0) // answered, RTT unknown
	f.t.Record(PointKey{Socket: v4P, Source: SourceSTUN, Observer: 1}, ap("203.0.113.5:50001"), f.at, 40*time.Millisecond, 0)
	f.t.AddFilter(FilterEvidence{Socket: v4P, Observer: 1, ExtraDeclared: 1, ExtraSeen: 1})
	f.t.AddFilter(FilterEvidence{Socket: v4P, Observer: 2, ExtraDeclared: 1})
	f.peer("192.0.2.1:9", "203.0.113.5:50001") // not reported
	fr := f.t.Snapshot()
	if err := validReport(fr); err != nil {
		t.Fatal(err)
	}
	if fr.Family != protocol.FamilyUDP4 || len(fr.Sockets) != 2 || fr.Sockets[0].Kind != protocol.SocketPrimary || fr.Sockets[1].Kind != protocol.SocketSecond {
		t.Fatalf("report %+v", fr)
	}
	rows := fr.Sockets[0].Rows
	if len(rows) != 4 {
		t.Fatalf("rows %+v", rows)
	}
	if r := rows[0]; r.Observer != 0 || r.Observed != ap("203.0.113.5:50001") || r.FirstSeq != 1 || r.SentMs != 1 || r.RTTMs != 20 || r.Cookie != 7 {
		t.Fatalf("row0 %+v", r)
	}
	if r := rows[1]; r.Observer != 1 || r.Observed.IsValid() || r.RTTMs != 0 || r.Cookie != 0 || r.FirstSeq != 2 {
		t.Fatalf("unanswered row %+v", r)
	}
	if r := rows[3]; r.Observer != 8 || r.RTTMs != 1 {
		t.Fatalf("alt row %+v", r)
	}
	if len(fr.STUN) != 1 || fr.STUN[0].Observer != 1 || fr.STUN[0].RTTMs != 40 {
		t.Fatalf("stun %+v", fr.STUN)
	}
	if len(fr.Filters) != 1 || fr.Filters[0].Observer != 1 || fr.Filters[0].ExtraSeen != 1 {
		t.Fatalf("filters %+v", fr.Filters)
	}
	// an empty table, and a socket without a concrete local address, still validate
	if err := validReport(NewTable(protocol.FamilyUDP6, nil, nil).Snapshot()); err != nil {
		t.Fatal(err)
	}
	tb := NewTable(protocol.FamilyUDP4, []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("0.0.0.0:5000")}}, mainObservers())
	if fr := tb.Snapshot(); len(fr.Sockets) != 0 || validReport(fr) != nil {
		t.Fatalf("wildcard local reported: %+v", fr)
	}
}

// The latest cookie belongs to the latest answer; the first value is reported.
func TestSnapshotDriftRow(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	k := f.send(v4P, SourceServer, 0)
	f.t.Record(k, ap("203.0.113.5:41000"), time.Second, 0, 1)
	f.t.Record(k, ap("203.0.113.5:42000"), 2*time.Second, 0, 2)
	r := f.t.Snapshot().Sockets[0].Rows[0]
	if r.Observed != ap("203.0.113.5:41000") || r.Cookie != 2 {
		t.Fatalf("row %+v", r)
	}
}

// The report caps rows per socket and STUN rows.
func TestSnapshotBounds(t *testing.T) {
	var obs []Observer
	for i := range 20 {
		obs = append(obs, Observer{ID: uint8(i), Addr: netip.AddrPortFrom(ip("198.51.100.1"), uint16(1000+i))})
	}
	tb := NewTable(protocol.FamilyUDP4, []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("10.0.0.2:1")}}, obs)
	for i := range 20 {
		k := PointKey{Socket: v4P, Source: SourceServer, Observer: uint8(i)}
		tb.NoteSent(k, uint32(i+1), time.Duration(i))
		tb.Record(PointKey{Socket: v4P, Source: SourceSTUN, Observer: uint8(i)}, ap("203.0.113.5:9"), 0, 0, 0)
	}
	fr := tb.Snapshot()
	if len(fr.Sockets[0].Rows) != maxReportRows || len(fr.STUN) != maxReportSTUN || validReport(fr) != nil {
		t.Fatalf("rows %d stun %d", len(fr.Sockets[0].Rows), len(fr.STUN))
	}
}

func TestTableConcurrent(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				f.t.Record(PointKey{Socket: v4P, Source: SourcePeer, Peer: netip.AddrPortFrom(ip("192.0.2.1"), uint16(g*1000+i+1))}, ap("203.0.113.5:1"), 1, 0, 0)
				_ = f.t.Classify()
				_ = f.t.Snapshot()
				_ = f.t.Endpoints()
			}
		})
	}
	wg.Wait()
}

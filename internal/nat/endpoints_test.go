package nat

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// serverTable builds a server-side table: rows as natprobe's merge records them.
func serverTable(socks []SocketMeta, rows ...Row) *ObsTable {
	tb := NewTable(protocol.FamilyUDP4, socks, mainObservers())
	for _, r := range rows {
		tb.RecordServer(r)
	}
	return tb
}

func srow(sock, obs uint8, observed string, seq uint32, verified bool) Row {
	return Row{Key: PointKey{Socket: sock, Source: SourceServer, Observer: obs}, Observed: ap(observed), FirstSeq: seq, FirstSent: -1, Verified: verified}
}

func TestEndpointsVerifiedOnly(t *testing.T) {
	socks := []SocketMeta{
		{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("192.168.1.10:40000")},
		{ID: v4S, Kind: protocol.SocketSecond, Local: ap("192.168.1.10:40001")},
		{ID: v4B, Kind: protocol.SocketSibling, Local: ap("10.8.0.2:40000")},
	}
	tb := serverTable(socks,
		srow(v4P, 1, "203.0.113.5:50002", 2, true),
		srow(v4P, 0, "203.0.113.5:50001", 1, true),
		srow(v4P, 2, "198.18.9.9:50003", 3, false), // forged source: recorded, cookie not echoed
		srow(v4S, 0, "203.0.113.5:50010", 4, true),
		srow(v4B, 0, "203.0.113.77:40000", 5, true),
		srow(v4P, 30, "203.0.113.5:50099", 6, true), // an observer the table does not know
	)
	if ips := tb.VerifiedIPs(); len(ips) != 2 || ips[0] != ip("203.0.113.5") || ips[1] != ip("203.0.113.77") {
		t.Fatalf("verified %v", ips)
	}
	// self-reported: STUN on a verified IP (kept) and elsewhere (refused), a
	// port mapping on a shared-space address (LAN/CGNAT candidate) and on a
	// foreign IP
	for _, r := range []Row{
		{Key: PointKey{Socket: v4P, Source: SourceSTUN, Observer: 0}, Observed: ap("203.0.113.5:50001")},
		{Key: PointKey{Socket: v4P, Source: SourceSTUN, Observer: 1}, Observed: ap("1.2.3.4:5")},
		{Key: PointKey{Socket: v4P, Source: SourcePortMap}, Observed: ap("100.70.0.9:40000")},
		{Key: PointKey{Socket: v4P, Source: SourcePortMap}, Observed: ap("1.2.3.4:6")},
		{Key: PointKey{Socket: v4P, Source: SourceSTUN, Observer: 2}, Observed: ap("203.0.113.77:41000")},
	} {
		tb.RecordServer(r)
	}
	eps := tb.Endpoints()
	want := []protocol.Endpoint{
		{Addr: ap("203.0.113.5:50001"), Source: protocol.EndpointServer, Socket: v4P, Verified: true},
		{Addr: ap("203.0.113.5:50002"), Source: protocol.EndpointServer, Socket: v4P, Verified: true},
		{Addr: ap("203.0.113.5:50010"), Source: protocol.EndpointSecond, Socket: v4S, Verified: true},
		{Addr: ap("203.0.113.77:40000"), Source: protocol.EndpointSibling, Socket: v4B, Verified: true},
		{Addr: ap("203.0.113.77:41000"), Source: protocol.EndpointSTUN, Socket: v4P},
		{Addr: ap("100.70.0.9:40000"), Source: protocol.EndpointPortmap, Socket: v4P},
		{Addr: ap("203.0.113.5:40000"), Source: protocol.EndpointLocalPort, Socket: v4P}, // the local port on the first verified IP
		{Addr: ap("192.168.1.10:40000"), Source: protocol.EndpointLAN, Socket: v4P},
		{Addr: ap("10.8.0.2:40000"), Source: protocol.EndpointLAN, Socket: v4B},
	}
	if len(eps) != len(want) {
		t.Fatalf("endpoints %+v", eps)
	}
	for i := range want {
		if eps[i] != want[i] {
			t.Fatalf("endpoint %d = %+v, want %+v (all %+v)", i, eps[i], want[i], eps)
		}
	}
	view := protocol.PeerView{Families: []protocol.FamilyView{{Family: protocol.FamilyUDP4, Traits: tb.Classify(), Endpoints: eps}}}
	if err := validView(protocol.FamilyUDP4, view); err != nil {
		t.Fatalf("summary with these endpoints: %v", err)
	}
}

func TestAdmitSelfReported(t *testing.T) {
	verified := []netip.Addr{ip("203.0.113.5")}
	cases := []struct {
		src  Source
		a    string
		want bool
	}{
		{SourceSTUN, "203.0.113.5:1", true},
		{SourceSTUN, "[::ffff:203.0.113.5]:1", true},
		{SourceSTUN, "203.0.113.6:1", false},
		{SourceSTUN, "10.0.0.1:1", false},
		{SourcePortMap, "203.0.113.5:1", true},
		{SourcePortMap, "10.0.0.1:1", true},
		{SourcePortMap, "100.100.0.1:1", true},
		{SourcePortMap, "203.0.113.6:1", false},
		{SourcePortMap, "127.0.0.1:1", false},
		{SourcePortMap, "203.0.113.5:0", false},
		{SourceServer, "203.0.113.5:1", false},
		{SourcePeer, "203.0.113.5:1", false},
	}
	for _, c := range cases {
		if got := AdmitSelfReported(c.src, ap(c.a), verified); got != c.want {
			t.Errorf("AdmitSelfReported(%d, %s) = %v", c.src, c.a, got)
		}
	}
	if AdmitSelfReported(SourceSTUN, netip.AddrPort{}, verified) {
		t.Error("zero address")
	}
}

// TestLANCandidates checks the LAN rule; 100.64/10 is overlay space,
// never LAN.
func TestLANCandidates(t *testing.T) {
	verified := []netip.Addr{ip("203.0.113.5")}
	cases := map[string]bool{
		"192.168.1.10:1": true, "10.0.0.1:1": true, "100.64.0.1:1": false, "100.101.102.103:1": false, "169.254.3.3:1": true, "[fd00::1]:1": true,
		"127.0.0.1:1": false, "[::1]:1": false, "[fe80::1]:1": false, "224.0.0.1:1": false, "0.0.0.0:1": false,
		"203.0.113.5:1": true, "203.0.113.6:1": false, "10.0.0.1:0": false,
	}
	for a, want := range cases {
		if got := lanCandidate(ap(a), verified); got != want {
			t.Errorf("lanCandidate(%s) = %v", a, got)
		}
	}
}

func TestEndpointBounds(t *testing.T) {
	socks := []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("192.168.1.2:1")}}
	for i := range 5 {
		socks = append(socks, SocketMeta{ID: SocketID(protocol.FamilyUDP4, uint8(2+i)), Kind: protocol.SocketSibling,
			Local: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), 1)})
	}
	var rows []Row
	for i := range 20 {
		rows = append(rows, srow(v4P, uint8(i%3), netip.AddrPortFrom(ip("203.0.113.5"), uint16(1000+i)).String(), uint32(i+1), true))
	}
	if eps := serverTable(socks, rows...).Endpoints(); len(eps) != protocol.MaxEndpoints {
		t.Fatalf("%d endpoints", len(eps))
	}
	// LAN only fills what is left and never more than four
	lan := 0
	for _, e := range serverTable(socks, srow(v4P, 0, "203.0.113.5:1000", 1, true)).Endpoints() {
		if e.Source == protocol.EndpointLAN {
			lan++
		}
	}
	if lan != protocol.MaxLANTargets {
		t.Fatalf("%d LAN endpoints", lan)
	}
	// a private observer's verified row is no server endpoint while global
	// observers exist
	tb := NewTable(protocol.FamilyUDP4, socks[:1], append(mainObservers(), Observer{ID: 16, Addr: ap("10.1.0.1:3478"), Group: 2}))
	tb.RecordServer(srow(v4P, 16, "10.1.0.20:40000", 1, true))
	for _, e := range tb.Endpoints() {
		if e.Verified {
			t.Fatalf("private observer endpoint %+v", e)
		}
	}
}

// TestOverlayEndpoints checks overlay endpoints on the server side: reported
// overlay addresses become unverified overlay endpoints at the primary socket's
// port, at most two, after the LAN ones; addresses of another family or no
// unicast address are dropped.
func TestOverlayEndpoints(t *testing.T) {
	socks := []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("192.168.1.2:40000")}}
	tb := serverTable(socks, srow(v4P, 0, "203.0.113.5:41000", 1, true))
	tb.NoteOverlay([]netip.Addr{ip("100.101.102.103"), ip("fd7a:115c:a1e0::1"), ip("127.0.0.1"), ip("10.147.17.4"), ip("10.9.9.9")})
	var got []protocol.Endpoint
	for _, e := range tb.Endpoints() {
		if e.Source == protocol.EndpointOverlay {
			got = append(got, e)
		}
	}
	want := []protocol.Endpoint{
		{Addr: ap("100.101.102.103:40000"), Source: protocol.EndpointOverlay, Socket: v4P},
		{Addr: ap("10.147.17.4:40000"), Source: protocol.EndpointOverlay, Socket: v4P},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("overlay endpoints %+v, want %+v", got, want)
	}
	tb.NoteOverlay(nil)
	for _, e := range tb.Endpoints() {
		if e.Source == protocol.EndpointOverlay {
			t.Fatalf("overlay endpoint %+v after NoteOverlay(nil)", e)
		}
	}
}

// TestEndpointLocalPort: the primary socket's local port on its first
// verified IP is a candidate of its own when natprobe saw another port, and
// none when an observation already holds it.
func TestEndpointLocalPort(t *testing.T) {
	socks := []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("192.168.1.10:40000")}}
	for _, c := range []struct {
		observed string
		want     bool
	}{{"203.0.113.5:50001", true}, {"203.0.113.5:40000", false}} {
		tb := serverTable(socks, srow(v4P, 0, c.observed, 1, true))
		got := slices.ContainsFunc(tb.Endpoints(), func(e protocol.Endpoint) bool {
			return e.Source == protocol.EndpointLocalPort && e.Addr == ap("203.0.113.5:40000") && !e.Verified
		})
		if got != c.want {
			t.Errorf("observed %s: local_port candidate %v, want %v (%+v)", c.observed, got, c.want, tb.Endpoints())
		}
	}
	// No verified row of the primary: no IP to put the port on.
	if eps := serverTable(socks, srow(v4P, 0, "203.0.113.5:50001", 1, false)).Endpoints(); slices.ContainsFunc(eps,
		func(e protocol.Endpoint) bool { return e.Source == protocol.EndpointLocalPort }) {
		t.Errorf("unverified: %+v", eps)
	}
}

// A client the public observers saw only at its private address is
// LAN-observed: its traits say nothing of its NAT, it has no verified IP,
// and its STUN and port-mapping addresses become endpoints only with the
// reported fallback on.
func TestLANObservedReportedFallback(t *testing.T) {
	local := "192.168.1.50:40000"
	socks := []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap(local)}}
	stun := Row{Key: PointKey{Socket: v4P, Source: SourceSTUN, Observer: 0}, Observed: ap("203.0.113.10:40000")}
	pm := Row{Key: PointKey{Socket: v4P, Source: SourcePortMap}, Observed: ap("203.0.113.10:40001")}
	for _, fallback := range []bool{false, true} {
		tb := serverTable(socks, srow(v4P, 0, local, 1, true), srow(v4P, 1, local, 2, true), srow(v4P, 2, local, 3, true))
		tb.SetReportedFallback(fallback)
		for _, r := range []Row{stun, pm} {
			if got := tb.AdmitReported(r.Key.Source, r.Observed); got != fallback {
				t.Fatalf("fallback %v: AdmitReported(%v) = %v", fallback, r.Observed, got)
			}
			tb.RecordServer(r)
		}
		tr := tb.Classify()
		if !tr.LANObserved || tr.Mapping != protocol.MapUnknown || tr.Filtering != protocol.FiltUnknown ||
			tr.NoNAT != protocol.TriUnknown || tr.Samples != 3 || tr.PublicIP != ip("192.168.1.50") {
			t.Fatalf("traits %+v", tr)
		}
		if tb.STUNConflicts() != 0 || len(tb.VerifiedIPs()) != 0 {
			t.Fatalf("conflicts %d, verified %v", tb.STUNConflicts(), tb.VerifiedIPs())
		}
		var srcs []protocol.EndpointSource
		for _, e := range tb.Endpoints() {
			if e.Verified {
				t.Fatalf("verified endpoint %+v", e)
			}
			srcs = append(srcs, e.Source)
		}
		want := []protocol.EndpointSource{protocol.EndpointLAN}
		if fallback {
			want = []protocol.EndpointSource{protocol.EndpointSTUN, protocol.EndpointPortmap, protocol.EndpointLAN}
		}
		if !slices.Equal(srcs, want) {
			t.Fatalf("fallback %v: endpoint sources %v, want %v", fallback, srcs, want)
		}
	}

	// A client natprobe saw at its public address is not LAN-observed, and
	// the fallback admits nothing more for it.
	tb := serverTable(socks, srow(v4P, 0, "198.51.100.9:50000", 1, true), srow(v4P, 1, "198.51.100.9:50000", 2, true))
	tb.SetReportedFallback(true)
	if tb.Classify().LANObserved || tb.AdmitReported(SourceSTUN, ap("203.0.113.10:40000")) {
		t.Fatal("a publicly observed client counted as LAN-observed")
	}
	// Private observers (a private-scope deployment) observe a LAN; their
	// private values are no LAN-observed evidence.
	priv := NewTable(protocol.FamilyUDP4, socks, []Observer{{ID: 0, Addr: ap("10.0.0.1:3478")}, {ID: 1, Addr: ap("10.0.0.1:3479")}})
	priv.RecordServer(srow(v4P, 0, local, 1, true))
	priv.RecordServer(srow(v4P, 1, local, 2, true))
	if priv.Classify().LANObserved {
		t.Fatal("a private-scope deployment counted as LAN-observed")
	}
}

// A view from the client's own report follows the Endpoints rules with
// nothing verified: observations by socket kind and creation order, STUN
// and port mapping, the local-port guess, LAN addresses without the shared
// space, the host's global addresses at the primary port, and overlays.
func TestSelfReportedView(t *testing.T) {
	fr := protocol.FamilyReport{
		Family: protocol.FamilyUDP4,
		Sockets: []protocol.SocketReport{
			{ID: v4B, Kind: protocol.SocketSibling, Local: ap("100.64.0.7:40002"),
				Rows: []protocol.RowReport{{Observed: ap("203.0.113.5:50020"), FirstSeq: 1}}},
			{ID: v4P, Kind: protocol.SocketPrimary, Local: ap("192.168.1.10:40000"),
				Rows: []protocol.RowReport{{Observed: ap("203.0.113.5:50002"), FirstSeq: 3}, {Observed: ap("203.0.113.5:50001"), FirstSeq: 2},
					{Observed: ap("0.0.0.0:1"), FirstSeq: 4}, {Observed: ap("127.0.0.1:50003"), FirstSeq: 5},
					{Observed: ap("255.255.255.255:50004"), FirstSeq: 6}}},
		},
		STUN:       []protocol.RowReport{{Observed: ap("203.0.113.5:50001")}, {Observed: ap("203.0.113.9:50005")}, {Observed: ap("127.0.0.2:50006")}},
		PortMap:    &protocol.PortMapReport{External: ap("10.0.0.1:6000")},
		LocalAddrs: []netip.Addr{ip("192.168.1.10"), ip("198.51.100.4"), ip("2001:db8::1")},
		Overlay:    []netip.Addr{ip("100.100.1.1"), ip("127.0.0.1")},
		Traits:     protocol.Traits{PortAnchorMs: 77},
	}
	fv := SelfReportedView(fr)
	want := []protocol.Endpoint{
		{Addr: ap("203.0.113.5:50001"), Source: protocol.EndpointServer, Socket: v4P},
		{Addr: ap("203.0.113.5:50002"), Source: protocol.EndpointServer, Socket: v4P},
		{Addr: ap("203.0.113.5:50020"), Source: protocol.EndpointSibling, Socket: v4B},
		{Addr: ap("203.0.113.9:50005"), Source: protocol.EndpointSTUN, Socket: v4P},
		{Addr: ap("10.0.0.1:6000"), Source: protocol.EndpointPortmap, Socket: v4P},
		{Addr: ap("203.0.113.5:40000"), Source: protocol.EndpointLocalPort, Socket: v4P},
		{Addr: ap("192.168.1.10:40000"), Source: protocol.EndpointLAN, Socket: v4P},
		{Addr: ap("198.51.100.4:40000"), Source: protocol.EndpointLAN, Socket: v4P},
		{Addr: ap("100.100.1.1:40000"), Source: protocol.EndpointOverlay, Socket: v4P},
	}
	if !slices.Equal(fv.Endpoints, want) {
		t.Fatalf("endpoints\n%v\nwant\n%v", fv.Endpoints, want)
	}
	if fv.Family != protocol.FamilyUDP4 || fv.Traits.Family != protocol.FamilyUDP4 || fv.Traits.PortAnchorMs != 0 || fv.Traits.Samples != 1 {
		t.Fatalf("traits %+v", fv.Traits)
	}
}

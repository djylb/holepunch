package holepunch

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// FuzzDispatch feeds arbitrary datagrams to a socket's dispatcher, before
// and while punching: nothing panics, nothing is answered that did not
// authenticate.
func FuzzDispatch(f *testing.F) {
	f.Add([]byte{}, false)
	f.Add([]byte{0x05, 1, 2, 3}, true)
	f.Add(append([]byte{0x0F}, make([]byte, 60)...), true)
	f.Add([]byte{0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42}, false)
	_, h := simHost(f)
	rt := newTestRuntime(f, fakeClock(f), h)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		f.Fatal(err)
	}
	// An opener around a plain sealed datagram: its FINGERPRINT is valid,
	// which the fuzzer would hardly find, so mutations reach the packet
	// inside.
	f.Add(rt.codec.Wrap(nil, append([]byte{0x0F}, make([]byte, 60)...)), true)
	from := netip.MustParseAddrPort("198.51.100.7:4000")
	f.Fuzz(func(t *testing.T, pkt []byte, punching bool) {
		rt.punch.active.Store(punching)
		rt.dispatch(s, append([]byte(nil), pkt...), from)
		if got := rt.fam(protocol.FamilyUDP4).cnt.byStage[txReply].Load(); got != 0 {
			t.Fatalf("answered a forged packet (%d replies)", got)
		}
	})
}

// FuzzIntercept feeds arbitrary control frames to the dispatcher in every
// state it can be in before the session: it never panics or blocks.
func FuzzIntercept(f *testing.F) {
	ps := protocol.PunchStart{SessionID: "fuzz", Role: protocol.RoleInitiator, Token: protocol.NewToken(),
		Wire: protocol.NewWireSpec(), Control: protocol.DefaultControlSpec(), Probe: protocol.ProbeSpec{V: protocol.ProbeSpecVersion}}
	start, _ := msgframe.Encode(ps)
	f.Add(uint8(controlwire.TypePunchStart), start.Payload, true)
	f.Add(uint8(controlwire.TypePunchGo), []byte(`{"session_id":"fuzz","round":2,"window_ms":800}`), true)
	f.Add(uint8(controlwire.TypeAssist), []byte(`{"session_id":"fuzz","kind":"peer_seen","round":1,"family":"udp4","sock":0,"cand":0,"type":6}`), true)
	f.Add(uint8(controlwire.TypePing), []byte(`{"seq":1}`), true)
	a, b := net.Pipe()
	f.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	conn, err := controlwire.NewConn(a, controlwire.ConnOptions{})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = conn.Close() })
	go func() { _, _ = io.Copy(io.Discard, b) }()
	f.Fuzz(func(t *testing.T, typ uint8, payload []byte, accepted bool) {
		ct := newControl(&runtime{})
		if accepted {
			ct.sessionID, ct.accepted, ct.seenStart, ct.seenSummary = "fuzz", true, true, true
		}
		ct.intercept(conn, controlwire.Frame{Type: controlwire.Type(typ), Payload: payload})
	})
}

// The client runtime links neither the server side nor a port-mapping
// implementation.
func TestDependencies(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skip("go list unavailable:", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch {
		case strings.Contains(dep, "goupnp"), strings.Contains(dep, "jackpal"),
			strings.HasSuffix(dep, "holepunch/coord"), strings.HasSuffix(dep, "holepunch/natprobe"),
			strings.HasSuffix(dep, "holepunch/portmapper"), strings.HasSuffix(dep, "holepunch/nattest"):
			t.Errorf("root package links %s", dep)
		}
	}
}

// BenchmarkDispatchPunch measures the receive pipeline of one peer packet:
// precheck, pre-AEAD limit, AEAD open, role and replay checks.
func BenchmarkDispatchPunch(b *testing.B) {
	_, h := simHost(b)
	rt := newTestRuntime(b, nil, h)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		b.Fatal(err)
	}
	peer, _ := udpwire.NewCodec(rt.start.Token, rt.start.Wire.RouteID, udpwire.RoleResponder, udpwire.PadPolicy{Min: 60, Max: 160}, nil)
	from := netip.MustParseAddrPort("198.51.100.7:4000")
	pkts := make([][]byte, b.N)
	for i := range pkts {
		hd := udpwire.Header{Type: udpwire.TSuccess, Role: udpwire.RoleResponder, Seq: peer.NextSeq(), Cand: 1}
		tl := udpwire.TLVs{Observed: from}
		pkts[i], _ = peer.Seal(nil, &hd, &tl, 0)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		s.rateTokens = preRateBurst // measure the pipeline, not the flood limit
		rt.dispatch(s, pkts[i], from)
	}
}

// BenchmarkSendGate measures one initiated packet through the gate: limits,
// seal and write.
func BenchmarkSendGate(b *testing.B) {
	_, h := simHost(b)
	rt := newTestRuntime(b, nil, h)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		b.Fatal(err)
	}
	budget := protocol.CeilingBudget()
	budget.MaxPPS = 0 // unlimited: measure the gate, not the rate
	rt.sender.setBudget(budget)
	m := newRoundMeter(protocol.FamilyUDP4, 1, protocol.FamilySide{MaxPackets: 1 << 30}, &roundCeiling{})
	to := netip.MustParseAddrPort("198.51.100.9:5000")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		hd := udpwire.Header{Type: udpwire.TPunch, Round: 1, Cand: 1}
		rt.sender.mu.Lock()
		rt.sender.initiated = 0
		m.granted = 0
		rt.sender.mu.Unlock()
		if err := rt.sender.Send(context.Background(), s, to, &hd, nil, sendOpt{class: classInitiate, stage: txDirect, round: m}); err != nil {
			b.Fatal(err)
		}
	}
}

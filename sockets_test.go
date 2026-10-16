package holepunch

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
)

// Every round's sandwich helper is a new socket — a new internal
// endpoint, so that both of its probes map anew on any NAT — which holds a
// place in the socket budget until the round releases it; release closes
// it and ends its read loop.
func TestSandwichHelperPerRound(t *testing.T) {
	_, h := simHost(t)
	rt := newTestRuntime(t, fakeClock(t), h)
	ctx := context.Background()
	primary, err := rt.socks.open(ctx, protocol.FamilyUDP4, netipAP("0.0.0.0", 0), PurposeProbe, nat.IndexPrimary, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	rt.socks.setLimit(2)
	a := rt.socks.sandwichHelper(ctx, primary)
	if a == nil || a.id != nat.SocketID(protocol.FamilyUDP4, nat.IndexSandwich) || a.local.Addr() != primary.local.Addr() {
		t.Fatalf("helper %+v", a)
	}
	if b := rt.socks.sandwichHelper(ctx, primary); b != nil {
		t.Fatal("a second helper past the socket budget")
	}
	rt.socks.release(a)
	select {
	case <-a.readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the released helper's read loop still runs")
	}
	b := rt.socks.sandwichHelper(ctx, primary)
	if b == nil || b.local == a.local {
		t.Fatalf("next round's helper %+v, the last one %+v", b, a)
	}
	if rt.socks.byAddr(a.local) != nil || rt.socks.byAddr(b.local) != b {
		t.Fatal("the pool still holds the released helper")
	}
	rt.socks.release(b)
}

// A datagram larger than any holepunch packet is not this session's, and
// anyone can send one: the read loop drops it and reads on. Windows fails
// the read with WSAEMSGSIZE where Unix truncates the datagram.
func TestReadLoopSurvivesOversizedDatagram(t *testing.T) {
	rt := newTestRuntime(t, nil, SystemNetwork())
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netipAP("127.0.0.1", 0), PurposeProbe, nat.IndexPrimary, primaryRecvBuffer)
	if err != nil {
		t.Skip("no IPv4 loopback:", err)
	}
	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netipAP("127.0.0.1", 0)))
	if err != nil {
		t.Skip("no IPv4 loopback:", err)
	}
	defer func() { _ = peer.Close() }()
	for _, n := range []int{3 * readBufferSize, 200} {
		if _, err := peer.WriteToUDPAddrPort(bytes.Repeat([]byte{0xFF}, n), s.local); err != nil {
			t.Fatal(err)
		}
	}
	foreign := &rt.fam(protocol.FamilyUDP4).cnt.drops[dropForeign]
	deadline := time.Now().Add(5 * time.Second)
	for foreign.Load() < 2 {
		select {
		case <-s.readDone:
			t.Fatal("the read loop ended")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of 2 datagrams dropped as foreign", foreign.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

// A paced socket the session's socket budget refuses counts in
// bind_failed but is no bind failure of the host: however many come in a
// row, they never halt a background round, whose open sockets keep
// sending. haltBindRun binds the host refuses in a row do.
func TestPacedSocketRefusals(t *testing.T) {
	_, h := simHost(t)
	slots := 2*haltBindRun + 1
	for _, c := range []struct {
		name string
		netw Network
		halt bool
	}{
		{"socket budget", h, false},
		{"host", refuseBinds{Network: h, purpose: pacedPurpose}, true},
	} {
		rt := newTestRuntime(t, fakeClock(t), c.netw)
		primary, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netipAP("0.0.0.0", 0), PurposeProbe, nat.IndexPrimary, primaryRecvBuffer)
		if err != nil {
			t.Fatal(err)
		}
		if !c.halt {
			rt.socks.setLimit(1)
		}
		fr := &familyRound{rt: rt, run: &roundRun{plan: protocol.RoundPlan{Budget: protocol.BudgetBackground}},
			w:     &worker{fam: protocol.FamilyUDP4, fs: rt.fam(protocol.FamilyUDP4), primary: primary},
			paced: make([]*udpSock, slots), tried: make([]bool, slots)}
		for slot := 1; slot < slots; slot++ {
			if s := fr.pacedSocket(context.Background(), slot); s != nil {
				t.Fatalf("%s: slot %d bound %v", c.name, slot, s.local)
			}
		}
		want := slots - 1
		if c.halt {
			want = haltBindRun
		}
		if fr.halted.Load() != c.halt || int(fr.lateFailed.Load()) != want {
			t.Fatalf("%s: halted %v, %d bind failures", c.name, fr.halted.Load(), fr.lateFailed.Load())
		}
	}
}

// refuseBinds is a Network that refuses every bind of one purpose, as a
// host out of ports would.
type refuseBinds struct {
	Network
	purpose string
}

func (r refuseBinds) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	if purpose == r.purpose {
		return nil, syscall.EADDRINUSE
	}
	return r.Network.ListenPacket(ctx, network, laddr, purpose)
}

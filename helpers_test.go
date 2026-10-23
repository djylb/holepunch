package holepunch

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

func errClosedForTest() error { return net.ErrClosed }

// newTestRuntime is a runtime with the pieces a unit test of the send gate,
// the sockets or the dispatcher needs, as if punch_start had been accepted.
func newTestRuntime(t testing.TB, clk clock.Clock, netw Network) *runtime {
	t.Helper()
	rt := newRuntime(context.Background(), Options{Clock: clk, Network: netw, ControlSecurity: protocol.ControlSecurityDeclared})
	st := protocol.PunchStart{
		SessionID: "unit", Role: protocol.RoleInitiator, Token: protocol.NewToken(),
		Wire:     protocol.WireSpec{RouteID: protocol.NewRouteID(), PayloadMin: 60, PayloadMax: 160},
		Timeouts: testTimeouts(),
	}
	if err := rt.setupSession(st, rt.clk.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.g.Close(time.Second) })
	return rt
}

// openPrimary opens a socket of rt on any IPv4 address, with the primary
// socket's index and receive buffer.
func openPrimary(t testing.TB, rt *runtime) *udpSock {
	t.Helper()
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, nat.IndexPrimary, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// peerOf is the view of role r's peer among the server's views of both
// roles.
func peerOf(r protocol.Role, views [2]protocol.PeerView) protocol.PeerView {
	return views[1-roleIndex(r)]
}

// peerAddr is the first verified endpoint of the first family of role r's
// peer.
func peerAddr(r protocol.Role, views [2]protocol.PeerView) netip.AddrPort {
	for _, e := range peerOf(r, views).Families[0].Endpoints {
		if e.Verified {
			return e.Addr
		}
	}
	return netip.AddrPort{}
}

// simHost is a public host of a fresh simulated network.
func simHost(t testing.TB, opts ...nattest.Option) (*nattest.Network, *nattest.Host) {
	t.Helper()
	n := nattest.NewNetwork(opts...)
	t.Cleanup(func() { _ = n.Close() })
	return n, n.PublicHost(netip.IPv4Unspecified())
}

// fakeClock returns a fake clock reporting to t.
func fakeClock(t testing.TB) *clock.Fake { return clock.NewFake(t, time.Time{}) }

func netipAP(ip string, port int) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(port))
}

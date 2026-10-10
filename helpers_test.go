package holepunch

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/clock"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

func errClosedForTest() error { return net.ErrClosed }

// newTestRuntime is a runtime with the pieces a unit test of the send gate,
// the sockets or the dispatcher needs, as if punch_start had been accepted.
func newTestRuntime(t testing.TB, clk Clock, netw Network) *runtime {
	t.Helper()
	rt := newRuntime(context.Background(), Options{Clock: clk, Network: netw, ControlSecurity: protocol.ControlSecurityDeclared})
	token, route := protocol.NewToken(), protocol.NewRouteID()
	codec, err := udpwire.NewCodec(token, route, udpwire.RoleInitiator, udpwire.PadPolicy{Min: 60, Max: 160}, rt.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	rt.start = protocol.PunchStart{SessionID: "unit", Role: protocol.RoleInitiator, Token: token, Wire: protocol.WireSpec{RouteID: route}}
	rt.role, rt.codec, rt.started = protocol.RoleInitiator, codec, true
	rt.opener = newOpener(codec)
	rt.startAt = rt.clk.Now()
	rt.pace = newPacer(token, route, udpwire.RoleInitiator)
	rt.initCounters()
	rt.timeouts = testTimeouts().Normalize()
	t.Cleanup(func() { _ = rt.g.Close(time.Second) })
	return rt
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

package holepunch

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpsock"
)

// Windows sets the unicast TTL of both families through setsockopt, and the
// value found at creation comes back on restore.
func TestWindowsHopLimit(t *testing.T) {
	for _, tc := range []struct {
		network string
		addr    netip.AddrPort
	}{{"udp4", netipAP("127.0.0.1", 0)}, {"udp6", netipAP("::1", 0)}} {
		t.Run(tc.network, func(t *testing.T) {
			c, err := SystemNetwork().ListenPacket(context.Background(), tc.network, tc.addr, PurposeProbe)
			if err != nil {
				t.Skip("no loopback:", err)
			}
			defer func() { _ = c.Close() }()
			h := newHopCtl(c, new(atomic.Int64))
			if !h.ok || h.orig < 0 {
				t.Fatalf("hop control %+v", h)
			}
			if err := h.set(4); err != nil {
				t.Fatal(err)
			}
			if v, err := udpsock.HopLimit(c); err != nil || v != 4 {
				t.Fatalf("hop limit %d, %v", v, err)
			}
			if err := h.set(0); err != nil {
				t.Fatal(err)
			}
			if v, _ := udpsock.HopLimit(c); v != h.orig {
				t.Fatalf("restored %d want %d", v, h.orig)
			}
		})
	}
}

// A send to a closed port draws ICMP "port unreachable". Windows reports it
// on the socket's next read unless the report is switched off; either way
// the read loop lives on and reads the next datagram. SystemNetwork
// switches the reports off; an injected Network may leave them on, and the
// read loop takes the report for the soft signal it is.
func TestReadLoopSurvivesPortUnreachable(t *testing.T) {
	cases := []struct {
		name    string
		netw    Network
		reports bool
	}{
		{"system network", SystemNetwork(), false},
		{"injected network with reports on", reportsOnNetwork{SystemNetwork()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, nil, tc.netw)
			rt.punch.activate()
			rt.punch.newRound(1, []protocol.Family{protocol.FamilyUDP4})
			ctx := context.Background()
			s, err := rt.socks.open(ctx, protocol.FamilyUDP4, netipAP("127.0.0.1", 0), PurposeProbe, 0, primaryRecvBuffer)
			if err != nil {
				t.Skip("no IPv4 loopback:", err)
			}
			if _, err := s.write(ctx, []byte("gone"), closedLoopbackPort(t), 0); err != nil {
				t.Fatal(err)
			}
			if tc.reports {
				testkit.WaitFor(t, "the ICMP report", func() bool {
					return rt.punch.evidence().icmpMax > 0
				})
			}
			peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netipAP("127.0.0.1", 0)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			cnt := &rt.fam(protocol.FamilyUDP4).cnt
			before := cnt.rx.Load()
			if _, err := peer.WriteToUDPAddrPort([]byte("after the report"), s.local); err != nil {
				t.Fatal(err)
			}
			testkit.WaitFor(t, "the next datagram", func() bool { return cnt.rx.Load() > before })
			select {
			case <-s.readDone:
				t.Fatal("the read loop ended")
			default:
			}
		})
	}
}

// reportsOnNetwork is the OS network with the Windows ICMP reports left on,
// like a caller's Network that never switches them off.
type reportsOnNetwork struct{ Network }

func (n reportsOnNetwork) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	c, err := n.Network.ListenPacket(ctx, network, laddr, purpose)
	if err != nil {
		return nil, err
	}
	if err := udpsock.EnableICMPReports(c); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// closedLoopbackPort returns a loopback port that nothing listens on.
func closedLoopbackPort(t *testing.T) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netipAP("127.0.0.1", 0)))
	if err != nil {
		t.Fatal(err)
	}
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = c.Close()
	return ap
}

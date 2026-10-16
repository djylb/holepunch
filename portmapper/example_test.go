package portmapper_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/djylb/holepunch/portmapper"
	"github.com/djylb/holepunch/protocol"
)

// osNetwork stands in for holepunch.SystemNetwork(), which is what a real
// caller passes as Config.Network.
type osNetwork struct{}

func (osNetwork) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, _ string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, laddr.String())
}

func (osNetwork) OutboundAddr(ctx context.Context, network string) (netip.Addr, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, "192.0.2.1:9") // connecting a UDP socket sends nothing
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr(), nil
}

// ExampleMapper maps a UDP socket on the local gateway and reports the
// external address to peers; the caller keeps the socket and the release
// function. It is only compiled: it needs a real gateway.
func ExampleMapper() {
	m := portmapper.New(portmapper.Config{Network: osNetwork{}})
	defer func() { _ = m.Close() }() // deletes every mapping still held

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return
	}
	defer func() { _ = pc.Close() }()
	info, release, err := m.Map(ctx, pc, protocol.PortMappingPolicy{LeaseSeconds: 3600})
	if err != nil {
		// No gateway, or none that maps ports: carry on without a mapping.
		fmt.Println("no port mapping:", err)
		return
	}
	defer func() { _ = release() }() // before the socket is closed
	fmt.Printf("peers can reach %s via %s (port_map %+v)\n", info.Internal, info.External, info.Report())
}

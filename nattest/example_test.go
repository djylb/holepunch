package nattest_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/djylb/holepunch/nattest"
)

// network is the method set of holepunch.Network,
// repeated to show that *nattest.Host satisfies it structurally.
type network interface {
	ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error)
	InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error)
	OutboundAddr(ctx context.Context, network string) (netip.Addr, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// udpConn is what the sockets of a Host offer beyond net.PacketConn.
type udpConn interface {
	net.PacketConn
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	SetHopLimit(int) error
}

// A rendezvous server observes both mappings; then a host behind a
// port-restricted NAT and a host behind a sequential symmetric NAT punch
// through. The port-restricted side opens its NAT with a low-TTL packet that
// dies in the core, and the symmetric side's next mapping takes the
// predicted port. With zero-delay links every packet is delivered inside
// WriteTo, so the run is deterministic.
func Example() {
	n := nattest.NewNetwork(nattest.WithSeed(1))
	defer func() { _ = n.Close() }()

	server := n.PublicHost(netip.IPv4Unspecified())
	prc := n.NAT(nattest.PortRestricted())
	sym := n.NAT(nattest.SymmetricSeq(1))
	var a, b network = prc.Host(), sym.Host()

	ctx := context.Background()
	stun := netip.AddrPortFrom(server.Addrs()[0], 3478)
	srv, _ := server.Listen("udp4", stun)
	pa, _ := a.ListenPacket(ctx, "udp4", netip.AddrPortFrom(netip.Addr{}, 40000), "probe")
	pb, _ := b.ListenPacket(ctx, "udp4", netip.AddrPortFrom(netip.Addr{}, 40000), "probe")
	ca, cb, cs := pa.(udpConn), pb.(udpConn), srv.(udpConn)

	observe := func(c udpConn) netip.AddrPort {
		_, _ = c.WriteToUDPAddrPort([]byte{0x05}, stun)
		_, from, _ := cs.ReadFromUDPAddrPort(make([]byte, 16))
		return from
	}
	ma, mb := observe(ca), observe(cb)
	fmt.Println("A seen as", ma, "B seen as", mb)

	// A opens its own NAT towards B's next port without reaching B's NAT.
	predicted := netip.AddrPortFrom(mb.Addr(), mb.Port()+1)
	_ = ca.SetHopLimit(4)
	_, _ = ca.WriteToUDPAddrPort([]byte{0x07}, predicted)
	_ = ca.SetHopLimit(0)
	// B's new mapping towards A takes the next sequential port.
	_, _ = cb.WriteToUDPAddrPort([]byte{0x09}, ma)
	buf := make([]byte, 16)
	_, from, err := ca.ReadFromUDPAddrPort(buf)
	fmt.Println("A got", buf[0], "from", from, err)

	st := n.Stats()
	fmt.Println("dropped by TTL:", st.Dropped.TTL, "filtered:", st.FilteredInbound)
	fmt.Println("B mappings:", len(sym.Mappings()))
	// Output:
	// A seen as 203.0.113.2:40000 B seen as 203.0.113.3:32744
	// A got 9 from 203.0.113.3:32745 <nil>
	// dropped by TTL: 1 filtered: 0
	// B mappings: 2
}

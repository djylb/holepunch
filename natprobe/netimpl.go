package natprobe

import (
	"context"
	"net"
	"net/netip"

	"github.com/djylb/holepunch/udpsock"
)

// The only places where natprobe reaches the operating system's network
// directly (lintcheck nodirectnet). Everything else goes through
// ServerConfig.Listen, which tests and nattest inject.

// defaultListen is ServerConfig.Listen when the caller leaves it nil. It
// switches the Windows ICMP reports off: a client that went away turns the
// next reply into "port unreachable", which Windows would report on the
// listener's next read. Best effort, since the
// reader skips the reports anyway.
//
//holepunch:netimpl
func defaultListen(network string, laddr netip.AddrPort) (net.PacketConn, error) {
	c, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(laddr))
	if err != nil {
		return nil, err // never a typed-nil *UDPConn in the interface
	}
	_ = udpsock.DisableICMPReports(c)
	return c, nil
}

// interfacePrefixes lists the host's interface addresses for the
// wildcard_multi_ip check.
//
//holepunch:netimpl
func interfacePrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// systemLookup resolves host with the operating system's resolver
// (ResolveSTUN's default).
//
//holepunch:netimpl
func systemLookup(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

package portmapper

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Config configures a Mapper. Network is required; the other fields have
// defaults.
type Config struct {
	// Network opens the Mapper's UDP request sockets (PCP, NAT-PMP, SSDP) with
	// purpose "portmap" and reports the local address that routes out of the
	// host. holepunch.SystemNetwork(), any holepunch.Network and nattest hosts
	// satisfy it. Its methods, and those of the connections it returns, are
	// called behind a recover boundary: a panic fails that one request. They
	// must honour ctx.
	Network interface {
		ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error)
		OutboundAddr(ctx context.Context, network string) (netip.Addr, error)
	}

	// AttemptTimeout bounds each network phase of a method: the PCP mapping
	// request and the NAT-PMP and UPnP probes (which run in parallel), each
	// NAT-PMP or UPnP mapping request, and each renewal. Default 1.2 s.
	AttemptTimeout time.Duration

	// DiscoverTimeout bounds how long a Map waits to learn the default
	// gateway and, for a socket bound to a wildcard address, the local address
	// that routes out (Network.OutboundAddr). Default 1 s.
	DiscoverTimeout time.Duration

	// Gateway returns the IPv4 default gateway; nil reads the operating
	// system's routing table. The lookup runs in a goroutine of the Mapper,
	// one at a time, behind a recover boundary, and its result is cached for a
	// minute (a failure for 5 s). A Map stops waiting for it after
	// DiscoverTimeout; ctx ends when the Mapper is closed.
	Gateway func(ctx context.Context) (netip.Addr, error)
}

const (
	defaultAttemptTimeout  = 1200 * time.Millisecond
	defaultDiscoverTimeout = time.Second
)

func (c Config) withDefaults() Config {
	if c.AttemptTimeout <= 0 {
		c.AttemptTimeout = defaultAttemptTimeout
	}
	if c.DiscoverTimeout <= 0 {
		c.DiscoverTimeout = defaultDiscoverTimeout
	}
	return c
}

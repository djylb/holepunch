// Package portmapper asks the local NAT gateway to forward a UDP port to a
// socket — with PCP (RFC 6887), NAT-PMP (RFC 6886) or UPnP IGD — and keeps
// the mapping alive until it is released.
//
// Stability: beta. The API may change in a minor release.
//
// # Use
//
// *Mapper satisfies holepunch.PortMapper without glue: pass portmapper.New(cfg)
// as holepunch.Options.PortMapper; the client runtime itself never links this
// package. Map takes and returns the protocol types and only reads the
// socket's local address. It does not wrap, read, write or close the socket,
// so the caller keeps every capability of it (syscall.Conn, HopLimiter) and
// owns the release function; the winning socket's release moves to
// Session.Close. Mapper.Close is the backstop that deletes whatever is left.
//
// # How a mapping is made
//
// Map waits at most Config.DiscoverTimeout for the IPv4 default gateway. It
// then runs three things in parallel, each bounded by Config.AttemptTimeout:
// a PCP MAP request, a NAT-PMP external-address request and a UPnP discovery
// (SSDP, device description, GetExternalIPAddress). Only the PCP request has
// an effect on the gateway. The most preferred method that answered —
// PCP, then NAT-PMP, then UPnP — provides the mapping, so a less preferred
// mapping is never created and left behind. A mapping that Map created but
// does not hand out, or that the gateway may have created although its answer
// was lost, is deleted in the background.
//
// The gateway lookup reads the operating system's routing table — Linux
// /proc/net/route, the darwin and BSD routing table through sysctl
// (NET_RT_DUMP, parsed here), Windows GetIpForwardTable — unless Config.Gateway
// replaces it. It runs at most once at a time per Mapper and its result is
// cached; a gateway that answers nothing is looked up again by the next Map.
// A lookup that fails — Android may refuse /proc/net/route to ordinary apps
// — makes Map return ErrNoGateway: port mapping is off for that session and
// hole punching goes on without it.
//
// # Concurrency
//
// Every method is safe for concurrent use. Each Mapper runs the package's
// goroutines: the parallel phase of each Map, the
// gateway lookup, one renewal goroutine per mapping that expires, and the
// background deletes. Close cancels them and joins them. Besides these, only
// the callbacks of context.AfterFunc that close request sockets and the
// connection goroutines of net/http run, and neither outlives its request.
// A panic in a step — including one in Config.Network, in the connections it
// returns or in Config.Gateway, all called behind a recover boundary — fails
// only that step: a renewal stops, an attempt counts as failed, and Map
// returns the panic as an error. There is no package-level state; the gateway
// cache and its single-flight lookup belong to the Mapper, and a caller
// typically creates one Mapper per process.
//
// Network waits (retransmissions, attempt and release bounds) use real time,
// because socket deadlines are wall-clock times. The renewal schedule and the
// gateway cache use the Mapper's clock, which is clock.System
// outside tests.
//
// # Resource ownership
//
// Every UDP socket the Mapper opens comes from Config.Network with purpose
// "portmap" and network "udp4", has the Windows ICMP reports switched off,
// belongs to a single request (one create, renewal or delete, or
// one SSDP search) and is closed when the request ends. The end of the
// request's context closes it at once; that is how a blocked read is
// interrupted, so no read deadline is ever moved from another goroutine.
// UPnP's HTTP requests go through the Mapper's own
// net/http client, which dials TCP itself because holepunch.Network has no
// TCP; keep-alive is off, so no connection outlives its request.
//
// # Bounds
//
// Map returns within Config.DiscoverTimeout plus twice Config.AttemptTimeout,
// or earlier when its context ends. release and Close return within 2 s; a
// gateway that does not confirm a delete makes them return an error, and the
// mapping then expires with its lease.
package portmapper

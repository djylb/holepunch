// Package nattest is an in-process NAT simulator for deterministic
// end-to-end tests of UDP hole punching: no real sockets, no root privileges
// and no dependence on the machine's network.
//
// Stability: experimental. The package is not covered by semantic versioning.
//
// # Topology
//
// A [Network] is the public core. NAT devices hang off the core
// ([Network.NAT]) or off another NAT ([NAT.NAT], a home router behind a
// carrier-grade NAT). Hosts live on the core ([Network.PublicHost]) or in a
// NAT's LAN ([NAT.Host]). Control links that cross no NAT, such as the TCP
// connections to the coordinator, are pipes ([Network.Pipe]).
//
//	n := nattest.NewNetwork(nattest.WithSeed(1))
//	defer n.Close()
//	server := n.PublicHost()
//	a := n.NAT(nattest.PortRestricted()).Host()
//	b := n.NAT(nattest.SymmetricSeq(1)).Host()
//	ctlA, srvA := n.Pipe(nattest.PipeConfig{A: a, B: server, DelayAB: 20 * time.Millisecond})
//
// A *Host has the method set of holepunch.Network (ListenPacket,
// InterfaceAddrs, OutboundAddr, LookupNetIP), built from standard library
// types only, so it is passed to the library without an adapter and without
// this package importing the client runtime. [Host.Listen] has the signature
// of natprobe.ServerConfig.Listen. The sockets implement
// holepunch.HopLimiter.
//
// # Behaviour
//
// NAT devices follow RFC 4787: mapping (EIM, ADM, APDM), filtering (EIF, ADF,
// APDF), port allocation (Preserve, Sequential with a signed step, Random,
// PreserveThenSequential, PreserveThenRandom, Pool), mapping timeouts with
// outbound and optionally inbound refresh, conntrack flows (the reply to an
// inbound packet a filter admitted leaves through the mapping that admitted
// it), hairpinning, several exit addresses, nested NATs, IP TTL (a packet
// creates state on every device it gets through, so a low-TTL packet opens the
// local NAT without reaching the peer), link impairments, loss beyond a device
// toward chosen destinations after it mapped the packet ([NAT.DropUpstream]),
// an outbound protocol classifier that cuts a flow whose first five datagrams
// hold no STUN message ([Classifier]), destination-dependent paths with a
// translation of their own, proxies among them ([NATConfig].Routes), scan
// detection and the port consumption of other subscribers. IPv6 runs without
// NAT behind a stateful firewall, with NPTv6 or with NAT66. [Network.Dump]
// explains every drop.
//
// For assertions about packet uniqueness, [HostStats] records the shape of
// every packet a host sends, per socket and therefore per session: the first
// byte, the length and the byte offsets that never changed — STUN messages
// apart, with the flows they opened.
//
// # Scheduling and concurrency
//
// Every exported method is safe for concurrent use. A packet is processed
// hop by hop at the simulated time it reaches each hop. The first NAT on its
// path translates it synchronously inside WriteTo, on the caller's goroutine
// and under that NAT's lock, so WriteTo never blocks and its effect on the
// local NAT is visible when it returns. A hop behind a link with a delay is
// queued on the network's scheduler, a min-heap ordered by (arrival time,
// sequence), and judged by the state of the remote device at arrival time,
// which is what makes simultaneous open work. Zero-delay paths never touch
// the scheduler: the packet is in the destination socket's queue (1024
// packets, then dropped and counted) before WriteTo returns.
//
// Locks are taken in the order topology, NAT device, then the leaf locks of
// links, hosts, sockets, pipes and statistics, never the other way round.
//
// # Time and determinism
//
// By default the network runs on the real clock, and its single scheduler
// goroutine waits for the earliest event. With [WithClock] and a
// *clock.Fake (or a clock that keeps its AdvanceTo) no goroutine runs:
// packets with a delay, pipe data and deadlines move only while the test
// advances the Fake, which makes a single-goroutine test reproducible packet
// by packet. Randomness (port allocation, port noise, loss, jitter,
// reordering, ephemeral ports) comes from independent generators derived
// from [WithSeed]. With the real clock and concurrent senders the order in
// which mappings are created depends on goroutine scheduling, so a seed
// reproduces the statistics, not every packet; a failure is replayed from
// [Network.Dump].
//
// # Resource ownership
//
// The Network owns every NAT, host, socket and pipe created from it. Sockets
// and pipe ends belong to the caller that opened them until they are closed;
// [Host.Crash] and [Network.Close] close them regardless. Each deadline that
// is set holds one clock timer, stopped when the socket closes. Close stops
// the scheduler, joining its goroutine for at most one second, drops the
// packets in flight and closes everything; afterwards no goroutine of the
// network is left.
package nattest

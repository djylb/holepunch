// Package holepunch is the client runtime of holepunch, a UDP hole-punching
// library: given a control connection to a holepunch coordinator, it finds a
// direct UDP path to the peer the coordinator pairs it with and hands the
// winning socket to the caller.
//
// # Integration
//
// The caller establishes an authenticated, encrypted stream to the
// coordinator (TLS, an encrypted bridge, a QUIC stream), sends whatever it
// needs before the session, and calls AttachSession with it. The library
// reads the first frame, punch_start, and then runs the session the server
// drives:
//
//  1. probing: it binds its sockets through Options.Network, measures the
//     NAT against the natprobe observers listed in punch_start and reports,
//     with the host's overlay addresses — tunnels such as Tailscale or
//     WireGuard, 100.64/10 — kept apart from its LAN ones (hostaddrs.go);
//  2. preparation: it takes the summary — both sides' NAT view and the first
//     round's plan — admits the targets, pre-binds the round's sockets and
//     reports ready;
//  3. punching: it runs every round the server starts with punch_go, at the
//     instant the server aligned for both sides, sending only to admitted
//     peer addresses and only through its send gate (budget, rate, new
//     targets, distinct ports); the first datagram of every flow — socket
//     and remote endpoint — leaves as a STUN Binding Request carrying the
//     packet (opener.go), for networks that cut flows that do not
//     start like WebRTC; a round that hears nothing from the peer
//     re-observes its own mapping halfway, so that a mapping the NAT moved
//     reaches the peer through the server (reobserve.go); a round may
//     bind fresh sockets at ports drawn from its seed, for a NAT that keeps
//     a fresh socket's port, or open its sockets slowly over a long
//     window, the slow birthday of a Background session, which a spike of
//     bind or write failures halts; both are closed when the round
//     ends unless they heard the peer;
//  4. handover: once a candidate pair carries traffic both ways, the
//     nomination handshake (nominate, accept, ready, handover_ack) confirms
//     it over UDP alone — the server is no longer needed — and the socket is
//     handed over clean: no read loop, no deadline, normal TTL.
//
// With Options.MaxPaths above 1 the session also hands over up to
// MaxPaths-1 extra paths that already carried the peer's packets — another
// family, another kind of network, other sockets — each confirmed on its
// own pair within the handover.
//
// The result is a *Session (the sockets, the Result and the Diagnostics) or
// an *Error whose Reason is one of the 26 protocol.Reason values, with the
// server's advice for the next attempt (Error.Advice: stay on the relay and
// punch again in Background mode, or relay only). Options.Mode accepts a
// Background session the server offers: the caller already relays and
// nobody waits. The control connection always remains the caller's.
//
// # Concurrency
//
// AttachSession runs the phases on the caller's goroutine. Every other
// goroutine starts through internal/life.Group.Go, which recovers panics:
// the control connection's reader and writer (controlwire), one read loop
// per socket, one prober and one port-mapping attempt per family, one
// goroutine per family and round, the nomination goroutine that owns the
// candidate state machine, a few bounded peer_seen follow-ups, and the
// OnProgress delivery goroutine. User code — Network, PortMapper,
// HopLimiter, Clock callbacks, OnProgress — is called outside every lock
// and inside a recover boundary. Every UDP write passes the send gate, one
// packet of a family at a time, so that the gate judges the sequence of
// destination ports in the order the packets actually leave. Nothing polls:
// an idle session sleeps on its channels and on the timers of its next
// deadline.
//
// # Ownership
//
// The session group owns every socket, every port-mapping release and every
// goroutine; the punching group, inside it, holds the goroutines that may
// write the winning socket. A single cleanup path serves success and failure
// alike (finish): it disowns and detaches the winner — and the extra paths'
// sockets — stops and joins the punching goroutines and their read loops,
// clears their deadlines and TTL, writes punch_result, releases the control
// connection and closes the rest. After AttachSession returns, the library
// neither reads nor writes the control connection or a handed-over socket
// again.
//
// Every wait is bounded by its own deadline, so AttachSession returns within
// the session cap T (71 s by default, 150 s at most) even with
// context.Background().
package holepunch

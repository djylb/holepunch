// Package holepunch is the client side of holepunch, a UDP hole-punching
// library: given a control connection to a holepunch coordinator (package
// coord), Punch finds a direct UDP path to the peer the coordinator pairs it
// with and hands the confirmed socket to the caller.
//
// # Usage
//
// The caller opens an authenticated, encrypted stream to the coordinator —
// TLS works as is — sends whatever its application needs first, and calls
// Punch:
//
//	sess, err := holepunch.Punch(ctx, conn, holepunch.Options{})
//	if err != nil {
//		// a *holepunch.Error: keep relaying, maybe retry (see below)
//	}
//	defer sess.Close()
//	pc := sess.PacketConn()               // the punched UDP socket, now the caller's
//	peer := sess.Result().Path.RemoteAddr // the peer's address on it
//
// The control connection stays the caller's throughout: Punch never closes
// it, and closing it is how a caller stops a running Punch. A stream that is
// not TLS but protected by an outer layer needs Options.ControlSecurity
// protocol.ControlSecurityDeclared.
//
// # The control channel
//
// The control channel is any reliable, ordered byte stream the caller has
// authenticated, with net.Conn's deadline semantics: a deadline in the past
// makes a blocked Read or Write return a timeout error at once. TLS over TCP
// is the usual one; a stream of a multiplexed connection the application
// already has (a QUIC stream, a stream of its own multiplexer over TLS, an
// encrypted bridge) works as well. One stream carries one session: run each Punch on a stream of its
// own. The coordinator may also run in the same process as one of the
// clients, or in the application's own server: coord.Session.Attach takes
// the other end of the stream, for example one end of net.Pipe with the
// other given to Punch (ControlSecurityDeclared on both sides: the pipe
// never leaves the process).
//
// The server decides the session: its punch_start carries the policy, the
// timeouts and the observers. Options.Policy can only tighten the server's
// policy (protocol.Tighten), and the timeouts are clamped to the protocol's
// ranges (protocol.Timeouts.Normalize), whatever either side asks for.
//
// # What a session hands over
//
// A Session holds the sockets of the confirmed paths: the primary path
// (PacketConn, Result.Path) and, with Options.MaxPaths above 1, extra paths
// on another family or kind of network (Result.ExtraPaths, PacketConns).
// When Punch returns, the library is done with them: it no longer reads or
// writes them, their deadlines are cleared and their TTL restored. The
// caller reads and writes them freely; the Session owns them until Close,
// which releases their port mappings and closes them, or Detach, which
// hands both over to the caller. Each Path says what kind of network it
// crosses (public, LAN, overlay, port mapping), its RTT and the keepalive
// that keeps its NAT mappings open. An upper layer other than QUIC reads
// through Session.FilterResidual, which drops the peer's last handshake
// packets; QUIC needs nothing.
//
// # Failures
//
// Every failure is an *Error whose Reason is one of the protocol.Reason
// values, with the phase it happened in, a detail and, from the server,
// advice for the next attempt (Error.Advice: relay and punch again in
// Background mode, or relay only) and a RetryAfter. NextAttempt turns them
// into a retry policy — retry after a backoff, switch to Background mode,
// stay on the relay for hours, or give up:
//
//	switch next := holepunch.NextAttempt(err, failures); next.Action {
//	case holepunch.ActionRetry, holepunch.ActionBackground:
//		// keep relaying; punch again after next.Delay
//		// (ActionBackground: with Options.AcceptBackground)
//	case holepunch.ActionRelayOnly:
//		// keep relaying; do not punch this pair for next.Delay
//	case holepunch.ActionGiveUp:
//		// stopped by the caller, or a configuration error
//	}
//
// Diagnostics — on the Session and on the Error — tell how the session went:
// both sides' NAT traits, the rounds run, counters, timings, warnings and
// hints for people (HintHostFirewall, HintServerSeesLAN). Options.Logger
// logs the milestones and the failure of each session.
//
// # Related packages
//
//   - coord and natprobe are the server side; portmapper adds UPnP, NAT-PMP
//     and PCP port mappings (Options.PortMapper).
//   - stun, udpsock and hostaddr are standalone tools the library is built
//     on: STUN queries and a server, ICMP reports and TTLs of UDP sockets,
//     and the host's LAN, public and overlay addresses.
//   - nattest simulates NATs and networks in process, and clock provides
//     the Fake clock that drives a whole deployment deterministically; the
//     package example runs one.
//
// # Guarantees
//
// Punch does not panic: user code — Network, PortMapper, HopLimiter, Clock,
// OnProgress, the Logger's handler — runs outside every lock and inside a
// recover boundary, and a panic in the library becomes an *Error with
// Reason internal. When Punch
// returns, every goroutine it started has exited and every resource it did
// not hand over is released, on success and failure alike. Every wait has
// its own deadline, so Punch returns within the session cap (71 s by
// default, 150 s at most) even with context.Background(), plus a TLS
// handshake it ran for the caller (15 s at most). Nothing polls: an
// idle session sleeps until its next deadline.
package holepunch

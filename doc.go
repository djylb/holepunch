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
// # What a session hands over
//
// A Session holds the sockets of the confirmed paths: the primary path
// (PacketConn, Result.Path) and, with Options.MaxPaths above 1, extra paths
// on another family or kind of network (Result.ExtraPaths, PacketConns).
// The library no longer reads or writes them; their deadlines are cleared
// and their TTL restored. Each Path says what kind of network it crosses
// (public, LAN, overlay, port mapping), its RTT and the keepalive that keeps
// its NAT mappings open. An upper layer other than QUIC reads through
// Session.FilterResidual, which drops the peer's last handshake packets;
// QUIC needs nothing. Close the Session, not the sockets, so that a port
// mapping is released too.
//
// # Failures
//
// Every failure is an *Error whose Reason is one of the protocol.Reason
// values, with the phase it happened in, a detail and, from the server,
// advice for the next attempt (Error.Advice: relay and punch again in
// Background mode, or relay only) and a RetryAfter:
//
//	if e, ok := errors.AsType[*holepunch.Error](err); ok && e.Reason == protocol.ReasonServerBusy {
//		time.Sleep(e.RetryAfter)
//	}
//
// Diagnostics — on the Session and on the Error — tell how the session went:
// both sides' NAT traits, the rounds run, counters, timings, warnings and
// hints for people (HintHostFirewall, HintServerSeesLAN).
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
// OnProgress — runs outside every lock and inside a recover boundary, and a
// panic in the library becomes an *Error with Reason internal. When Punch
// returns, every goroutine it started has exited and every resource it did
// not hand over is released, on success and failure alike. Every wait has
// its own deadline, so Punch returns within the session cap (71 s by
// default, 150 s at most) even with context.Background(), plus a TLS
// handshake it ran for the caller (15 s at most). Nothing polls: an
// idle session sleeps until its next deadline.
package holepunch

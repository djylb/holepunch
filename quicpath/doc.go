// Package quicpath runs QUIC (quic-go) on the sockets a holepunch Session
// hands over: one QUIC connection — a pipe — per confirmed path.
//
// # Usage
//
// Each side builds the TLS configuration of its role and connects; the
// initiator dials, the responder accepts:
//
//	id, _ := quicpath.NewIdentity("my-app")      // once; one serves any number of sessions
//	opts := holepunch.Options{TransportMode: "quic", TransportData: id.TransportData()}
//	sess, err := holepunch.Punch(ctx, ctl, opts) // ...
//	conf, err := id.TLSConfig(sess.Result())     // pins the peer's certificate
//	var conn *quicpath.Conn
//	if sess.Result().Role == protocol.RoleInitiator {
//		conn, err = quicpath.Dial(ctx, sess, conf, nil)
//	} else {
//		conn, err = quicpath.Accept(ctx, sess, conf, nil)
//	}
//	if err != nil {
//		_ = sess.Close() // on failure the session stays the caller's
//		return err
//	}
//	defer conn.Close() // the QUIC connection, its transport and the session
//
// Dial and Accept run on the primary path and give the Conn the session: its
// Close closes the QUIC connection, the QUIC transport and the Session, which
// releases the port mappings. An Endpoint runs a pipe on any confirmed path,
// extra paths included, and owns the session itself.
//
// # Authentication
//
// An Identity is a self-signed certificate whose SHA-256 pin travels to the
// peer as the session's TransportData, through the coordinator's
// authenticated control connection. Its TLSConfig checks the peer's
// certificate against the pin the peer announced (Result.PeerTransportData)
// on every handshake and never resumes a TLS session, so the two sides are
// mutually authenticated without a certificate authority. A caller with its
// own trust model passes its own tls.Config instead; it must name an
// application protocol (NextProtos).
//
// # The path
//
// QUIC takes the raw socket, without Session.FilterResidual: the peer's late
// handshake packets that may still arrive after the handover have a first
// byte with its two high bits clear, which QUIC stacks classify as non-QUIC
// and drop, and a wrapper would cost quic-go the socket's batch and ECN
// paths. The responder takes connections from the confirmed peer address of
// the path only and refuses every other before its handshake starts.
//
// The QUIC keep-alive period and idle timeout default to the path's
// keepalive advice (Path.Keepalive.Interval and Timeout), so the QUIC
// connection keeps the NAT mappings open and notices a dead path; Dial and
// Accept wait at most the session's TransportTimeout. A quic.Config passed
// in overrides the defaults field by field.
//
// # Liveness
//
// Conn.Done is closed when the pipe dies, and Conn.Err then says why:
// ErrIdleTimeout for a path that went silent, ErrPeerClosed when the peer
// closed or reset the connection, ErrClosed after a local Close or once its
// socket was closed, or
// quic-go's own error. An upper layer running over several pipes watches
// Done and replaces or drops the pipe.
//
// # Concurrency and ownership
//
// The package starts no goroutine of its own; quic-go runs its transport
// and connections. Every method is safe for concurrent use, and every Close
// is idempotent.
package quicpath

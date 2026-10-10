// Package quicforward forwards TCP connections over QUIC (quic-go) on the UDP
// path a standalone session punched.
//
// # Model
//
// The host side (Serve, ServeSession) listens for QUIC on the punched socket
// and forwards every stream the dialer opens to a TCP target that both its
// own HostConfig.Targets and the session's AccessPolicy allow. The dialer side
// (Connect) opens a session with the host, dials QUIC on the punched socket
// and forwards every connection accepted on a local listener over a new
// stream; when the QUIC connection is lost, the next local connection opens a
// new session. A stream starts with a small request naming the target and the
// host's answer, then carries the bytes both ways with half-closes.
//
// Both sides use an Identity: a self-signed certificate whose pin travels to
// the peer as the session's TransportData through the coordinator, whose
// control streams are authenticated TLS. Each side verifies the other's
// certificate against that pin, so the QUIC connection is mutually
// authenticated without any certificate authority.
//
// The QUIC layer takes the raw winning socket (Session.Holepunch()) and no
// residual filter: quic-go drops holepunch's late handshake packets by their
// first byte, and a wrapper would cost it the socket's batch and ECN paths. The
// sockets' deadlines are cleared before QUIC takes them, defensively.
//
// # Bounds
//
//   - The host waits at most the session's TransportTimeout for the dialer's
//     QUIC connection; then it closes the listener, the QUIC transport and
//     the session's socket.
//   - The dialer makes at most three attempts within the same bound and stops
//     at once when the socket is closed.
//   - The host reports the transport's outcome to the server
//     (client.Session.ReportTransport); a failed report is only logged and
//     never closes an established QUIC connection.
//   - The QUIC keepalive and idle timeout follow the session's keepalive
//     advice.
//
// # Concurrency and ownership
//
// Each forward connection owns a life.Group with one goroutine per stream
// plus one per relay direction, and the target connections it opened; the
// group is closed, and joined within 2 s, when the QUIC connection ends.
// Connect's group also holds the listener and a goroutine that closes it
// when Connect's context ends; both are gone when Connect returns. User hooks
// (HostConfig.Dial) run inside a recover boundary.
package quicforward

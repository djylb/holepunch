// Package client is the client side of the standalone deployment: it opens
// holepunch sessions with registered hosts (Open) and, registered as a host,
// serves the sessions dialers open with it (Serve).
//
// # Model
//
// Every request is a fresh TLS stream to the server (Config.Dial, Config.TLS).
// Open sends proto.Open, reads the SessionInfo and runs
// holepunch.AttachSession on the same stream as the initiator. Serve keeps a
// registration link: it registers the host ID, answers and sends heartbeats,
// and for every Incoming opens a new stream, joins the session with the
// ticket it carried and runs AttachSession as the responder before passing
// the Session to the Handler. A lost link is re-established with a backoff
// (1 s doubling to 30 s), presenting the previous registration's credential
// so that the host takes its ID over at once.
//
// After AttachSession the server is no longer needed: the control stream is
// closed and the Session holds the punched UDP socket.
// Session.PacketConn wraps it in udpwire.DropResidual for upper layers that are
// not QUIC; a QUIC layer takes Session.Holepunch().PacketConn(), the raw
// socket, since quic-go drops the residual handshake packets by itself.
//
// # Concurrency
//
// Every goroutine runs in the Client's life.Group: per registration link a
// reader (the Serve caller's goroutine), a heartbeat writer and a watcher
// that closes the link when Serve's context or the Client ends; one per
// incoming session, which also runs the Handler inside a recover boundary.
// Writes on a link are serialised by a mutex and bounded by the heartbeat
// interval. Config.Dial is called outside every lock, inside a recover
// boundary.
//
// # Ownership
//
// A Session returned by Open belongs to the caller. A Session passed to a
// Handler belongs to the Client: it is closed when the Handler returns. Close
// closes the registration link, cancels the Handlers' context and waits at
// most 2 s for the goroutines, so that Handlers end their sessions in order;
// a Handler that ignores its context is left behind, counted in the returned
// ErrCloseTimeout, and its session is closed under it.
package client

// Package server is the network front end of the standalone deployment: it
// accepts the clients' TLS streams, authenticates them, keeps the hosts'
// registration links and hands every session stream to the broker, whose
// coordinator runs the session.
//
// # Streams
//
// Each accepted connection is TLS-terminated (Config.TLS) and its first
// message (package proto) decides what it is:
//
//   - Register: after the shared-token check (constant time, through SHA-256
//     digests) and Config.Authorize, the host is registered with the
//     broker and the stream becomes its registration link: the server
//     answers every Heartbeat, forwards Incoming notices, passes Transport
//     reports to Config.OnTransport, and drops the link after three silent
//     heartbeat intervals.
//   - Open: after the same checks the broker matches the dialer with the
//     host; the server answers SessionInfo and attaches the stream to the
//     session as the initiator.
//   - Join: the ticket from Incoming is the credential; the server answers
//     SessionInfo and attaches the stream as the responder.
//
// A refused request gets a proto.Fail and the stream is closed.
//
// # Concurrency
//
// Each connection is served by one goroutine of the server's life.Group,
// inside a recover boundary: a panic ends that connection only. A connection
// that is handed to a session has no server goroutine any more; the
// coordinator's two per link take over. A registration link keeps its
// goroutine, which reads the link; writes to it are serialised by a mutex
// and bounded by Config.WriteTimeout. User hooks (Authorize, OnTransport) run
// outside every lock, inside a recover boundary.
//
// # Ownership
//
// The server owns its listeners and every connection until it hands the
// connection to a broker session, which takes it unconditionally. Close
// closes the listeners and the connections the server still owns and joins
// its goroutines within 2 s. The broker is the caller's: close it after the
// server.
package server

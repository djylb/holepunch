// Package broker is the matchmaker of the standalone deployment: a registry
// of hosts and the pairing of a dialer with a registered host into a
// holepunch session, which a coord.Coordinator owned by the broker then runs.
//
// # Model
//
// A host registers under its ID (Register) with a Signal, the server's handle
// on the host's registration link. A dialer opens a session with a host by ID
// (Open): the broker asks its Authorize hook for the session's AccessPolicy,
// creates the coord session, draws a one-time ticket and tells the host
// through its Signal (proto.Incoming). The host joins with the ticket (Join)
// on a new stream. Each side's stream is then handed to the session with
// Session.Attach; from there on the coordinator runs the session and the
// broker only forgets it when the coordinator reports its Result.
//
// A live host ID can only be taken over with the credential of the
// registration that holds it (Host.Credential, sent to the host when it
// registered), so that a host that lost its link can come back at once while
// nobody else can steal its ID. Credentials and tickets are compared through
// their SHA-256 digests in constant time.
//
// # Concurrency
//
// Every method is safe for concurrent use. One mutex guards the registry and
// the session index; the user hooks (Authorize, Signal) and the coordinator
// are always called outside it, the hooks inside a recover boundary. The
// broker starts no goroutine of its own: the coordinator runs the sessions.
//
// # Ownership
//
// The broker owns its coordinator and closes it in Close. It never owns a
// registration link: the Signal's owner closes it, and Revoke asks it to.
// Session.Attach takes the stream unconditionally: on success the coordinator
// owns it, on failure Attach closes it and aborts the session, so a caller
// never has a stream left to clean up.
package broker

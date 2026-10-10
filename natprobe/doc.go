// Package natprobe is holepunch's server-side NAT observer.
//
// It has four parts:
//
//   - Registry: the table of registered probe routes. It is an instance (no
//     package state) of 64 copy-on-write shards whose read path, taken by
//     every UDP packet, is lock-free and allocation-free. It starts no
//     goroutine: expired entries disappear lazily, on Register and on Sweep,
//     which the single sweeper calls (coord's housekeeping, or the Server
//     when natprobe runs alone).
//   - Handle: one session's registration, held by the coordinator session:
//     Observations, Merge (the server's authoritative traits and endpoints,
//     with return-path cookie verification and the constraints on
//     self-reported endpoints), Registered (the origin, on the Registry's
//     clock, of the slot times and of Traits.PortAnchorMs), Extend and Close.
//   - Server: the observer listeners, bound per IP (ObserverGroup) so that
//     replies leave from the probed address, with a fixed extra-reply socket
//     pool per group and change-IP replies from the alt group.
//   - TraitsMemory: the cross-session traits memory, a 24 h LRU that only
//     fills gaps or raises one confidence level and never overturns direct
//     evidence.
//
// # Wire invariants
//
// A reply goes only to the probe's source. The reply bytes of one probe
// never exceed its bytes, at most two packets answer it and their lengths
// are random within the legal range. A probe may come as a STUN-wrapped
// opener (udpwire.Unwrap); its replies then leave as openers too, with the
// opener's bytes counted in that bound, and no per-flow state is kept.
// Unregistered routes are never decrypted; AEAD failures, replays and
// over-limit probes are dropped silently.
//
// # Concurrency
//
// Registry, Handle, Server and the TraitsMemory of NewTraitsMemory are safe
// for concurrent use. Each listener has ReadersPerListener reader goroutines
// that process packets inline, without queues; a session's state is guarded
// by a mutex per role, and replies are sealed and sent after it is released.
// The sandwich sink and the Logger are called outside every lock.
//
// # Ownership and failures
//
// A Server owns its sockets and its goroutines, all in one life.Group: Start
// opens them, and Start's failure path and Close close them and join the
// goroutines for at most 2 s. A Server does not own its Registry, which
// several Servers may share and the coordinator normally owns. Every packet
// is handled inside a recover boundary: a panic drops that packet, is
// counted, and is logged without a stack at most once a second; a panic in a
// reader loop itself only stops its listener.
package natprobe

// Package natprobe is holepunch's server-side NAT observer.
//
// A deployment creates one Registry, shares it between its Servers and its
// coord.Coordinator, and starts the Servers:
//
//   - Registry: the table of the sessions' probe routes, which the
//     coordinator fills and the Servers read. It is an instance (no package
//     state) of 64 copy-on-write shards whose read path, taken by every UDP
//     packet, is lock-free and allocation-free. It starts no goroutine and
//     needs no upkeep: a closed entry leaves at once, expired ones whenever
//     a registration rewrites their shard, and all of them when the table
//     is full.
//   - Server: the observer listeners, bound per IP (ObserverGroup) so that
//     replies leave from the probed address, with a fixed extra-reply socket
//     pool per group and change-IP replies from the alt group. ProbeSpec
//     describes them for coord.Config.
//   - TraitsMemory: the cross-session traits memory, a 24 h LRU that only
//     fills gaps or raises one confidence level and never overturns direct
//     evidence; coord.Config.TraitsMemory takes it or an implementation of
//     the caller's, a persistent one for example.
//   - ResolveSTUN: third-party STUN servers (stun.DefaultServers) for
//     ProbeSpec.STUN.
//
// # Wire invariants
//
// A reply goes only to the probe's source. The reply bytes of one probe
// never exceed its bytes, at most two packets answer it and their lengths
// are random within the legal range. A probe may come as a STUN-wrapped
// opener; its replies then leave as openers too, with the
// opener's bytes counted in that bound, and no per-flow state is kept.
// Unregistered routes are never decrypted; AEAD failures, replays and
// over-limit probes are dropped silently.
//
// # Concurrency
//
// Registry, Server and the TraitsMemory of NewTraitsMemory are safe for
// concurrent use. Each listener has ReadersPerListener reader goroutines
// that process packets inline, without queues; a session's state is guarded
// by a mutex per role, and replies are sealed and sent after it is released.
// The sandwich sink and the Logger are called outside every lock.
//
// # Ownership and failures
//
// A Server owns its sockets and its goroutines: Start
// opens them, and Start's failure path and Close close them and join the
// goroutines for at most 2 s. A Server does not own its Registry, which
// several Servers may share and the coordinator normally owns. Every packet
// is handled inside a recover boundary: a panic drops that packet, is
// counted, and is logged without a stack at most once a second; a panic in a
// reader loop itself only stops its listener.
package natprobe

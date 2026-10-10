// Package candidate is the client's candidate scoring/selection and the UDP
// nomination/handover state machine.
//
// It is a pure, deterministic state machine: the caller injects the current
// time into every method and the machine returns the UDP actions to take
// (send nominate/accept/ready/handover_ack, confirm, hand over, fail). It
// starts no goroutines and does no I/O. The root runtime drives it from one
// goroutine: it feeds the packet facts of its read loops, re-arms a single
// timer at NextDeadline after every call and calls Tick when it fires.
//
// Two concerns:
//
//   - Scoring and selection (Table): candidates are tiered responsive > direct
//     (LAN > observed) > peer_targets > predicted > random > birthday. Tier
//     scores differ by more than the 32-point selection hysteresis and a tier
//     shares its reason, so the nominee only ever changes to a higher tier; it
//     is chosen when the collection window ends and on every epoch roll. Each
//     candidate carries the minimum RTT measured on its own pair, so the
//     nomination round-trip timer uses the winning pair's samples. A peer's
//     overlay address (Tailscale, WireGuard, ZeroTier …) is no tier of the
//     order: it is nominated only when no other pair answered, or when its RTT
//     is at most 0.8 × the best other pair's. The table holds at most 256 pairs
//     and evicts the least useful one when full.
//
//   - Nomination (Manager): the initiator collects for NominationDelay, then
//     nominates the best candidate at a session-monotonic epoch (unique across
//     families); the responder adopts an observed pair and accepts; the
//     initiator confirms on accept and sends ready; the responder confirms on
//     ready, bursts handover_ack at 0/15/30 ms (an extra ready gets an extra
//     ack at once, at most two) and hands over when the burst ends. The
//     initiator hands over 30 ms after its first ack once it has three, 45 ms
//     after the first at the latest, at once on an upper-layer datagram from
//     the winning remote, or after 500 ms of silence: by then the
//     responder's read loop has stopped, so the initiator's first upper-layer
//     datagram is never swallowed by it. Resends follow the rto schedule (no
//     RTT sample: rto = 150 ms); after MaxNominateResends unanswered resends
//     the epoch rolls at once and the pair cools down; each roll of a pair
//     doubles its rto, up to 1200 ms. The responder never adopts an
//     epoch below the one it has, and every message is checked against the
//     epoch it answers. A single session-level confirm gate lets the first
//     Confirm win — being one machine per session, a second Confirm is
//     structurally impossible, so there is no late-confirm counter.
//     ReadFailed closes the pairs of a socket whose read loop failed; on the
//     winning socket it disables the quiet evidence.
//
//   - Extra paths (paths.go): with Config.MaxPaths above 1 the
//     initiator also nominates, by slot, the most different pairs that
//     answered, the responder adopts them within its adoption of the primary
//     path, and the first ready commits the accepted ones on both sides. The
//     primary path's handshake is unchanged; Describe tells the machine each
//     pair's kind of network and the peer's socket, which decide what counts
//     as a duplicate path.
//
// The package depends only on the standard library and protocol.
package candidate

// Package probe is the client NAT prober of one address family.
//
// A Prober never owns, reads or closes a socket. The session runtime
// owns every socket in its life.Group and runs one read pump per socket; the
// pump decodes each datagram (udpwire Open, CheckRole, the server SeqWindow)
// and hands probe-class replies to Deliver, STUN responses to DeliverSTUN
// and ICMP read errors to NoteUnreachable. Probes leave through
// SocketHandle.WriteTo, which the runtime implements on its single send gate
// (probe class). Probing therefore never sets a read
// deadline and cannot race a handover.
//
// Run is a state machine on one goroutine, driven by one reusable timer of
// the injected clock.Clock. The primary socket probes
// every main-group observer (WANT_EXTRA; observer 0 WANT_ALT when an alt group
// exists), retransmits only to observers without an ack at
// lastSend + T1·2^(k−1), where T1 is 1.5·RTT + 20 ms clamped to
// [80 ms, 400 ms], and waits extraWait for each declared extra. The
// prober opens a second socket when the primary looks APDM, probes the
// siblings once, runs the optional STUN sub-probe on the primary socket and,
// only once the unsolicited change-IP test is settled, the solicited alt
// probe. Run returns at DONE, at the probe_timeout_ms hard limit, when ctx
// ends, when every send to the server of two consecutive rounds failed
// (udp_blocked/send_failed) or when ICMP unreachable answered two rounds
// without any ack (udp_blocked/icmp_unreachable); rounds that also probed a
// STUN server or a LAN observer from the primary socket do not count, since
// the ICMP may be theirs, and neither does such ICMP fail a family whose
// server stayed silent at the hard limit.
//
// STUN is a hint: the family's STUN servers (at most 8) are asked at once,
// and a STUN server that fails, stays silent or answers with ICMP delays
// DONE by at most 150 ms and changes no result — 1 s while a LAN-observed
// family (the server saw only private addresses) has no STUN answer yet,
// since one is the only public address it can report; its answer enters
// the table, where nat.ObsTable.Classify lets it neither raise nor overturn
// natprobe's conclusions.
//
// After Run, Hairpin runs the conditional hairpin self-test on the primary
// socket, at most once per prober. Result.Table stays live: the runtime keeps
// adding peer_seen rows and unsolicited-inbound evidence while punching.
//
// # Concurrency
//
// Run and Hairpin each run on one goroutine of the session's life.Group;
// Hairpin only after Run returned. Deliver, DeliverSTUN and NoteUnreachable
// are safe to call from any number of read pumps at any time and never
// block: replies wait in a bounded inbox and are dropped and counted
// when it is full.
//
// # Ownership and failures
//
// The prober holds no OS resource: it writes through the runtime's handles
// and asks the runtime, through openSecond, for the second socket, which the
// runtime owns. Its only timer is stopped before Run or Hairpin returns. A
// panic inside the prober, or in the runtime's handle methods, never escapes:
// a panicking write is a failed send, and any other panic fails only this
// family with internal (detail panic:probe/<family>), the recovered
// *life.PanicError in Result.Panic.
package probe

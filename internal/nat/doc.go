// Package nat is the NAT observation model that the client prober
// (internal/probe) and natprobe's authoritative merge (nat.ProbeHandle.Merge)
// share.
//
// It has four parts:
//
//   - ObsTable: per address family, what observers saw of this host's
//     mappings, keyed by observation point (socket, source, observer); the
//     filtering evidence (declared and seen extra/alt replies); evidence of
//     unsolicited inbound packets; the hairpin result. Two values at one point
//     are drift; different values at different points are evidence of the
//     mapping behaviour.
//   - Classify: the classification of a table into protocol.Traits:
//     mapping, filtering and port allocation with independent confidences,
//     signed step, allocation velocity, port block, NoNAT, MultiExit,
//     MultiHomed, Drifted and CGNAT. STUN rows are a hint that neither raises
//     nor overturns natprobe's evidence; STUNConflicts counts those that
//     contradict it.
//   - Endpoints and AdmitSelfReported: the addresses a server-side table may
//     hand to the peer, verified by the return-path cookie or allowed by
//     the self-reported endpoint constraints (anti-reflection).
//   - DisplayName, Fingerprint and ClassBits for people, logs and
//     coord.StrategyKey; Correction for punch_result.traits.
//   - The natprobe → coord bridge: RegisterProbe, ProbeHandle and their
//     types (Registration, Observation, MergeDiag, SandwichEvent), so that
//     a session's registration stays out of natprobe's public API.
//
// # Concurrency
//
// An ObsTable is safe for concurrent use: one mutex guards it, and no method
// calls out of the package while holding it. The prober writes a table while
// probing and the client runtime keeps adding peer evidence to the same table
// while punching. Classify, Snapshot and Endpoints only read.
//
// # Ownership
//
// The package does no I/O and starts no goroutine. Tables are plain memory
// owned by whoever created them. The only package-level variable is
// RegisterProbe, which natprobe assigns once in its init.
//
// The package depends on protocol and the standard library only.
package nat

// Package protocol is the holepunch control plane as data: the twelve
// control messages and their shared structures, the domain model they
// carry (Traits and its
// predicates, plans, Policy and Budget), the client Phase, the 26 failure
// Reasons with their classes, and ControlSecurity.
//
// # Encoding and checking
//
// Marshal, Unmarshal and Decode convert between controlwire frames and
// messages; the frame-type table itself (numbers, caps, directions) lives in
// controlwire. Decoding enforces the JSON rules of a control payload — a
// UTF-8 object nested at most 8 levels — and then Validate, the structural
// check: required fields, enumeration values, string and list limits. A
// violation is a *ValidationError whose Reason (protocol_violation or
// control_version_mismatch) and Detail (the field path) go on the wire.
// Normalize is separate: it returns the message with the receiver-side
// clamps applied and whether anything changed, which the client reports as
// punch_ready.families[].clamped. Assists are checked by direction (see
// Assist).
//
// # Concurrency and ownership
//
// The package does no I/O, starts no goroutines and keeps no state. Messages
// are plain values: concurrent reads are safe, and a decoded message belongs
// to the caller.
//
// # Secrets
//
// Token and RouteID never print their value: fmt and log/slog show a
// placeholder or the 4-hex-digit route prefix, and PunchStart, ProbeReport
// and ProbeSummary log without key material or transport data. Only the JSON
// encoding carries them.
//
// protocol depends only on the standard library and controlwire.
package protocol

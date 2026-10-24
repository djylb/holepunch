package protocol

// Reason is the single failure-code enumeration of holepunch: the client's
// *Error.Reason, coord.Result.Reason and the wire field code of
// punch_result, round_result and punch_abort. Only the 26 names below exist on
// the wire; a receiver treats any other code as unknown: a punch_abort carrying one
// fails the client with aborted_by_server or aborted_by_peer.
// Fine-grained information goes into a separate detail string.
//
// Reason is a plain wire code, not an error: errors carry it in a field, such
// as holepunch's *Error and *ValidationError, and are matched with errors.As.
type Reason string

// The 26 reasons.
const (
	ReasonNoCommonFamily         Reason = "no_common_family"
	ReasonNoProbeEndpoint        Reason = "no_probe_endpoint"
	ReasonProbeTimeout           Reason = "probe_timeout"
	ReasonUDPBlocked             Reason = "udp_blocked"
	ReasonLocalPortBindFailed    Reason = "local_port_bind_failed"
	ReasonControlInterrupted     Reason = "control_interrupted"
	ReasonControlTimeout         Reason = "control_timeout"
	ReasonNotSynchronized        Reason = "not_synchronized"
	ReasonOneWayUDPOnly          Reason = "one_way_udp_only"
	ReasonTokenMismatch          Reason = "token_mismatch"
	ReasonCandidateTimeout       Reason = "candidate_timeout"
	ReasonHardSymmetricRandom    Reason = "hard_symmetric_random"
	ReasonPacketBudgetExceeded   Reason = "packet_budget_exceeded"
	ReasonHandoverTimeout        Reason = "handover_timeout"
	ReasonControlVersionMismatch Reason = "control_version_mismatch"
	ReasonProtocolViolation      Reason = "protocol_violation"
	ReasonInvalidArgument        Reason = "invalid_argument"
	ReasonPeerOffline            Reason = "peer_offline"
	ReasonSessionExpired         Reason = "session_expired"
	ReasonServerBusy             Reason = "server_busy"
	ReasonServerShutdown         Reason = "server_shutdown"
	ReasonTransportMismatch      Reason = "transport_mismatch"
	ReasonAbortedByPeer          Reason = "aborted_by_peer"
	ReasonAbortedByServer        Reason = "aborted_by_server"
	ReasonCanceled               Reason = "canceled"
	ReasonInternal               Reason = "internal"
)

// Reasons returns the 26 reasons in their canonical order.
func Reasons() []Reason {
	return []Reason{
		ReasonNoCommonFamily, ReasonNoProbeEndpoint, ReasonProbeTimeout, ReasonUDPBlocked,
		ReasonLocalPortBindFailed, ReasonControlInterrupted, ReasonControlTimeout, ReasonNotSynchronized,
		ReasonOneWayUDPOnly, ReasonTokenMismatch, ReasonCandidateTimeout, ReasonHardSymmetricRandom,
		ReasonPacketBudgetExceeded, ReasonHandoverTimeout, ReasonControlVersionMismatch, ReasonProtocolViolation,
		ReasonInvalidArgument, ReasonPeerOffline, ReasonSessionExpired, ReasonServerBusy,
		ReasonServerShutdown, ReasonTransportMismatch, ReasonAbortedByPeer, ReasonAbortedByServer,
		ReasonCanceled, ReasonInternal,
	}
}

// Known reports whether r is one of the 26 reasons.
func (r Reason) Known() bool { return r.Class() != ClassNone }

// ReasonClass groups reasons for retry decisions: none (unknown reason) |
// fatal | transient | nat_hard | canceled. With the summary's Advice it is
// what a retry decision rests on; holepunch.NextAttempt is a policy built on
// both.
type ReasonClass uint8

// Reason classes.
const (
	ClassNone ReasonClass = iota
	ClassFatal
	ClassTransient
	ClassNATHard
	ClassCanceled
)

func reasonClassNames() [5]string {
	return [5]string{"none", "fatal", "transient", "nat_hard", "canceled"}
}

// String returns the wire name of c.
//
//goland:noinspection GoMixedReceiverTypes
func (c ReasonClass) String() string { n := reasonClassNames(); return enumString(n[:], uint8(c)) }

// MarshalText encodes c as its name; an out-of-range value is an error.
//
//goland:noinspection GoMixedReceiverTypes
func (c ReasonClass) MarshalText() ([]byte, error) {
	n := reasonClassNames()
	return enumMarshal("reason class", n[:], uint8(c))
}

// UnmarshalText accepts exactly the names.
//
//goland:noinspection GoMixedReceiverTypes
func (c *ReasonClass) UnmarshalText(b []byte) error {
	n := reasonClassNames()
	return enumParse(c, "reason class", n[:], b)
}

// Class is r's class; ClassNone for an unknown reason.
func (r Reason) Class() ReasonClass {
	switch r {
	case ReasonNoCommonFamily, ReasonNoProbeEndpoint, ReasonUDPBlocked, ReasonLocalPortBindFailed,
		ReasonTokenMismatch, ReasonControlVersionMismatch, ReasonProtocolViolation, ReasonInvalidArgument,
		ReasonTransportMismatch, ReasonInternal:
		return ClassFatal
	case ReasonProbeTimeout, ReasonControlInterrupted, ReasonControlTimeout, ReasonNotSynchronized,
		ReasonHandoverTimeout, ReasonPeerOffline, ReasonSessionExpired, ReasonServerBusy,
		ReasonServerShutdown, ReasonAbortedByPeer, ReasonAbortedByServer:
		return ClassTransient
	case ReasonOneWayUDPOnly, ReasonCandidateTimeout, ReasonHardSymmetricRandom, ReasonPacketBudgetExceeded:
		return ClassNATHard
	case ReasonCanceled:
		return ClassCanceled
	}
	return ClassNone
}

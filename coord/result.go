package coord

import (
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Outcome is how a session ended.
type Outcome uint8

// Outcomes.
const (
	// OutcomeSucceeded means at least one client confirmed a UDP path, which
	// proves it both ways (half-confirmed successes included).
	OutcomeSucceeded Outcome = iota + 1
	// OutcomeFailed means the punch failed — a NATHard reason, or
	// probe_timeout, not_synchronized, udp_blocked, no_common_family,
	// no_probe_endpoint, local_port_bind_failed or transport_mismatch.
	OutcomeFailed
	// OutcomeAborted means everything else — control plane, caller, limits,
	// protocol, internal.
	OutcomeAborted
)

// String returns the outcome name.
func (o Outcome) String() string {
	switch o {
	case OutcomeSucceeded:
		return "succeeded"
	case OutcomeFailed:
		return "failed"
	case OutcomeAborted:
		return "aborted"
	}
	return "unknown"
}

// Result is a session's end, produced exactly once; when it is delivered,
// all of the session's resources have been released.
type Result struct {
	SessionID  string
	Outcome    Outcome
	Reason     protocol.Reason    // "" on success, otherwise one of the 26 reasons
	Detail     string             // human readable, standard details (join_timeout, ...), never a stack
	FailedRole protocol.Role      // the side that caused the failure; "" for the server or the caller
	Attached   [2]bool            // [initiator, responder]
	Confirmed  [2]bool            // the role reported round_result{confirmed} or punch_result{ok}
	Warn       []protocol.Warning // at most 8: the server's own, such as peer_result_missing and unverified_targets
	Winner     *WinnerInfo        // non-nil on success
	PairClass  string             // the Planner's diagnostic pair class
	// StrategyKey is the hex StrategyKey of the pair ("" when no key was
	// derived); it contains no plain address.
	StrategyKey string
	MemoryHit   bool          // the first round's variant came from the strategy memory
	Rounds      []RoundRecord // <= 8, rescue round included
	RTT         [2]time.Duration
	ClockOffset [2]time.Duration // diagnostic only (pong.client_unix_ms)
	Timing      Timing
	Counters    Counters
	Timeline    []StageMark     // the latest <= 32 progress marks
	Clients     [2]*ClientFinal // the clients' punch_result, nil when none arrived
	Retry       RetryAdvice
	Labels      map[string]string // SessionOptions.Labels
}

// RoundRecord describes one round.
type RoundRecord struct {
	StartedAt time.Time
	Budget    protocol.BudgetClass // the class actually granted
	Granted   [2]int               // MaxPackets granted to each side
	Sent      [2]int               // initiated packets each side reported
	Round     int
	Duration  time.Duration
	Variant   VariantID
	Rescue    bool
	Class     RoundClass
}

// WinnerInfo is the confirmed path.
type WinnerInfo struct {
	Round   int
	Variant VariantID
	Family  protocol.Family
	Path    [2]*protocol.PathInfo // by role; nil for a side that did not report its path
	// ExtraPaths are, by role, the other paths each side handed over with
	// Path, from its punch_result; empty with one
	// path or without the report.
	ExtraPaths [2][]protocol.PathInfo
}

// ClientFinal is a client's punch_result.
type ClientFinal struct {
	OK         bool
	Reason     protocol.Reason
	Phase      protocol.Phase
	Detail     string
	Path       *protocol.PathInfo
	ExtraPaths []protocol.PathInfo // punch_result.extra_paths: the other paths handed over with Path
	Stats      protocol.Stats
	Timing     protocol.Timing
	Traits     []protocol.TraitsUpdate
	Warn       []protocol.Warning
}

// Timing are the instants of a session's milestones (zero: not reached).
type Timing struct {
	Created      time.Time
	Attached     [2]time.Time
	Summary      time.Time
	FirstGo      time.Time
	FirstConfirm time.Time
	Closed       time.Time
}

// Counters are a session's frame and relay counters.
type Counters struct {
	FramesIn        [2]uint64 // frames read per link, discarded ones included
	FramesOut       [2]uint64 // frames written per link
	UnknownFrames   uint64    // reserved or wrong-direction frames read and dropped
	AssistForwarded uint64
	AssistDropped   uint64 // over a rate or quota, or the peer link busy
	AssistRejected  uint64 // not peer_seen, server-only fields set, bad round or address
	ProgressDropped uint64
	TargetRejected  uint64 // targets refused by admission
	BudgetViolation uint64 // rounds a side sent more than granted × 1.1
	PlanClamped     uint64 // plan fields the coordinator changed
	PeerTargets     uint64 // peer_targets sent
	PingsSent       uint64
	STUNConflicts   uint64 // STUN values that contradicted natprobe's records; only counted
	Refreshes       uint64 // anchor refreshes asked of a side and family before a round
}

// StageMark is one progress report.
type StageMark struct {
	Role     protocol.Role
	Stage    string
	Status   protocol.ProgressStatus
	Round    int
	OffsetMs int64 // since the session was created
}

// RetryAdvice tells the caller whether and when a new attempt makes sense, and
// in which mode.
type RetryAdvice struct {
	// Advice is what a failed session suggests: background_viable — relay
	// and punch again with SessionOptions.Mode background — or relay_only;
	// "" after a success or for a pair a retry as before suits.
	Advice    protocol.Advice
	After     time.Duration
	Retryable bool
	// BackgroundOnly reports that the strategy memory saw this pair of exits
	// connect only through the slow birthday; the next session may go to the
	// relay and Background at once.
	BackgroundOnly bool
}

// outcomeOf maps an end code to its Outcome ("" is success).
func outcomeOf(code protocol.Reason) Outcome {
	switch code {
	case "":
		return OutcomeSucceeded
	case protocol.ReasonProbeTimeout, protocol.ReasonNotSynchronized, protocol.ReasonUDPBlocked,
		protocol.ReasonNoCommonFamily, protocol.ReasonNoProbeEndpoint, protocol.ReasonLocalPortBindFailed,
		protocol.ReasonTransportMismatch:
		return OutcomeFailed
	}
	if code.Class() == protocol.ClassNATHard {
		return OutcomeFailed
	}
	return OutcomeAborted
}

// Retry delays.
const (
	retryDisconnect   = 500 * time.Millisecond
	retryStalled      = time.Second
	retryShort        = time.Second
	retryBindFailed   = 5 * time.Second
	retryOneWay       = 15 * time.Second
	retryBudget       = time.Minute
	retryStreakStart  = 15 * time.Second
	retryStreakMax    = 2 * time.Minute
	retryStreakTrials = 3
)

// retryFor is the retry advice of an end code. streak counts the initiator
// key's consecutive candidate_timeout results, this one included.
func retryFor(code protocol.Reason, detail string, streak int) RetryAdvice {
	never := RetryAdvice{}
	at := func(d time.Duration) RetryAdvice { return RetryAdvice{Retryable: true, After: d} }
	switch code {
	case "":
		return never
	case protocol.ReasonPeerOffline:
		switch detail {
		case detailJoinTimeout:
			return at(0)
		case detailWriteTimeout, detailStalled:
			return at(retryStalled)
		}
		return at(retryDisconnect)
	case protocol.ReasonCandidateTimeout:
		if streak >= retryStreakTrials {
			d := retryStreakStart << min(streak-retryStreakTrials, 4)
			return at(min(d, retryStreakMax))
		}
		return at(retryShort)
	case protocol.ReasonLocalPortBindFailed:
		return at(retryBindFailed)
	case protocol.ReasonOneWayUDPOnly:
		return at(retryOneWay)
	case protocol.ReasonPacketBudgetExceeded:
		return at(retryBudget)
	case protocol.ReasonControlInterrupted, protocol.ReasonSessionExpired, protocol.ReasonCanceled,
		protocol.ReasonServerShutdown:
		return at(0)
	case protocol.ReasonProbeTimeout, protocol.ReasonNotSynchronized, protocol.ReasonInternal,
		protocol.ReasonServerBusy:
		return at(retryShort)
	}
	if code.Class() == protocol.ClassTransient {
		return at(retryShort)
	}
	return never
}

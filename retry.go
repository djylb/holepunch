package holepunch

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Action is what to do after a failed Punch (NextAttempt).
type Action uint8

// Actions. The zero value is ActionGiveUp.
const (
	// ActionGiveUp means: do not punch again on a timer. The caller stopped
	// the session, or the failure is one of configuration, version or a
	// bug, which the next attempt repeats; punch again only after something
	// changed (a new configuration, a network change).
	ActionGiveUp Action = iota
	// ActionRetry means: punch again in the same mode after Attempt.Delay.
	ActionRetry
	// ActionBackground means: keep relaying and punch again after
	// Attempt.Delay in a Background session — Options.AcceptBackground on
	// the clients, coord.SessionOptions.Mode on the server — where a pair
	// of hard NATs may take its time.
	ActionBackground
	// ActionRelayOnly means that no punch is expected to connect this pair:
	// keep the relay and do not punch for it again for Attempt.Delay
	// (hours).
	ActionRelayOnly
)

// String returns the action's name: give_up, retry, background or
// relay_only.
func (a Action) String() string {
	switch a {
	case ActionGiveUp:
		return "give_up"
	case ActionRetry:
		return "retry"
	case ActionBackground:
		return "background"
	case ActionRelayOnly:
		return "relay_only"
	}
	return "unknown"
}

// Attempt is NextAttempt's advice: an action and the wait before it.
type Attempt struct {
	Action Action
	Delay  time.Duration // 0 with ActionGiveUp
}

// Backoff schedule of NextAttempt: the delay of the n-th consecutive
// failure is base·2^(n-1), at most ceiling, drawn uniformly from its upper
// half.
const (
	retryBase         = time.Second
	retryCeiling      = 5 * time.Minute
	natHardBase       = 15 * time.Second
	natHardCeiling    = 30 * time.Minute
	backgroundBase    = 30 * time.Second
	backgroundCeiling = 30 * time.Minute
	relayOnlyBase     = time.Hour
	relayOnlyCeiling  = 24 * time.Hour
)

// NextAttempt maps the error of a failed Punch and the number of
// consecutive failures of this pair so far, this one included (attempt ≥ 1;
// less counts as 1), to the next step. It is a policy built on the error's
// Advice, Reason and RetryAfter, which a caller may follow or replace; the
// server's own view of the same failure is coord.Result.Retry.
//
//   - nil, ErrClosed, a canceled context and Reason canceled from one:
//     ActionGiveUp, since the caller ended the session. A context that
//     reached its deadline — a caller's per-attempt timeout — is transient.
//   - Advice relay_only, and the reasons that rule a direct path out for
//     this host or pair (udp_blocked, no_common_family): ActionRelayOnly
//     after 30–60 min, the step doubling up to 24 h.
//   - Advice background_viable, and hard_symmetric_random (only the slow
//     birthday of a Background session may connect such a pair):
//     ActionBackground after 15–30 s, doubling up to 30 min.
//   - The other NAT-hard reasons without advice (candidate_timeout,
//     one_way_udp_only, packet_budget_exceeded): ActionRetry after 7.5–15 s,
//     doubling up to 30 min.
//   - The transient reasons (timeouts, the peer offline, the server busy or
//     shutting down, aborts), local_port_bind_failed, internal, unknown
//     reasons and errors that are not an *Error: ActionRetry after 0.5–1 s,
//     doubling up to 5 min.
//   - The other fatal reasons (invalid_argument, protocol and version
//     mismatches, token_mismatch, transport_mismatch, no_probe_endpoint):
//     ActionGiveUp — the next attempt would fail the same way.
//
// Each delay is drawn uniformly from the upper half of its step, so that
// many clients that failed together do not come back together. The error's
// RetryAfter (the server's server_busy wait), at most the step's ceiling,
// is a floor, with up to a quarter of it added at random for the same
// reason.
func NextAttempt(err error, attempt int) Attempt {
	if err == nil || errors.Is(err, ErrClosed) || errors.Is(err, context.Canceled) {
		return Attempt{}
	}
	herr, ok := errors.AsType[*Error](err)
	if !ok {
		return Attempt{Action: ActionRetry, Delay: backoff(retryBase, retryCeiling, attempt)}
	}
	action, base, ceiling := ActionRetry, retryBase, retryCeiling
	switch r, class := herr.Reason, herr.Reason.Class(); {
	case class == protocol.ClassCanceled && !errors.Is(err, context.DeadlineExceeded):
		return Attempt{}
	case herr.Advice == protocol.AdviceRelayOnly, r == protocol.ReasonUDPBlocked, r == protocol.ReasonNoCommonFamily:
		action, base, ceiling = ActionRelayOnly, relayOnlyBase, relayOnlyCeiling
	case herr.Advice == protocol.AdviceBackgroundViable, r == protocol.ReasonHardSymmetricRandom:
		action, base, ceiling = ActionBackground, backgroundBase, backgroundCeiling
	case class == protocol.ClassNATHard:
		base, ceiling = natHardBase, natHardCeiling
	case class == protocol.ClassFatal && r != protocol.ReasonLocalPortBindFailed && r != protocol.ReasonInternal:
		return Attempt{}
	}
	a := Attempt{Action: action, Delay: backoff(base, ceiling, attempt)}
	if ra := min(herr.RetryAfter, ceiling); ra > 0 {
		a.Delay = max(a.Delay, ra+rand.N(ra/4+1))
	}
	return a
}

// backoff is the delay of the attempt-th consecutive failure:
// base·2^(attempt-1), at most ceiling, drawn uniformly from [d/2, d].
func backoff(base, ceiling time.Duration, attempt int) time.Duration {
	d := min(base, ceiling)
	for n := max(attempt, 1) - 1; n > 0 && d < ceiling; n-- {
		d = min(2*d, ceiling) // ceiling ≤ 24 h: 2·d never overflows
	}
	return d/2 + rand.N(d/2+1)
}

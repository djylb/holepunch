package holepunch

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

func TestNextAttempt(t *testing.T) {
	herr := func(r protocol.Reason, adv protocol.Advice, after time.Duration) error {
		return fmt.Errorf("wrapped: %w", &Error{Reason: r, Advice: adv, RetryAfter: after})
	}
	for _, tc := range []struct {
		name     string
		err      error
		attempt  int
		action   Action
		min, max time.Duration
	}{
		{"success", nil, 1, ActionGiveUp, 0, 0},
		{"closed", &Error{Reason: protocol.ReasonCanceled, Err: ErrClosed}, 1, ActionGiveUp, 0, 0},
		{"canceled", herr(protocol.ReasonCanceled, "", 0), 1, ActionGiveUp, 0, 0},
		{"context", context.Canceled, 1, ActionGiveUp, 0, 0},
		{"plain error", errors.New("dial"), 1, ActionRetry, 500 * time.Millisecond, time.Second},
		{"transient", herr(protocol.ReasonPeerOffline, "", 0), 1, ActionRetry, 500 * time.Millisecond, time.Second},
		{"transient third", herr(protocol.ReasonControlTimeout, "", 0), 3, ActionRetry, 2 * time.Second, 4 * time.Second},
		{"transient capped", herr(protocol.ReasonProbeTimeout, "", 0), 1000, ActionRetry, 150 * time.Second, 5 * time.Minute},
		{"zero attempt", herr(protocol.ReasonProbeTimeout, "", 0), 0, ActionRetry, 500 * time.Millisecond, time.Second},
		{"retry after", herr(protocol.ReasonServerBusy, "", time.Minute), 1, ActionRetry, time.Minute, 75 * time.Second},
		{"retry after capped", herr(protocol.ReasonServerBusy, "", 49*24*time.Hour), 1, ActionRetry, 5 * time.Minute, 375 * time.Second},
		{"relay only long run", herr(protocol.ReasonUDPBlocked, "", 0), 23, ActionRelayOnly, 12 * time.Hour, 24 * time.Hour},
		{"relay only longer", herr(protocol.ReasonUDPBlocked, "", 0), 30, ActionRelayOnly, 12 * time.Hour, 24 * time.Hour},
		{"background long run", herr(protocol.ReasonHardSymmetricRandom, "", 0), 30, ActionBackground, 15 * time.Minute, 30 * time.Minute},
		{"huge attempt", herr(protocol.ReasonProbeTimeout, "", 0), math.MaxInt, ActionRetry, 150 * time.Second, 5 * time.Minute},
		{"deadline", &Error{Reason: protocol.ReasonCanceled, Err: context.DeadlineExceeded}, 1, ActionRetry, 500 * time.Millisecond, time.Second},
		{"plain deadline", context.DeadlineExceeded, 1, ActionRetry, 500 * time.Millisecond, time.Second},
		{"unknown reason", herr("future_reason", "", 0), 1, ActionRetry, 500 * time.Millisecond, time.Second},
		{"bind failed", herr(protocol.ReasonLocalPortBindFailed, "", 0), 1, ActionRetry, 500 * time.Millisecond, time.Second},
		{"nat hard retry", herr(protocol.ReasonCandidateTimeout, "", 0), 2, ActionRetry, 15 * time.Second, 30 * time.Second},
		{"nat hard", herr(protocol.ReasonHardSymmetricRandom, "", 0), 1, ActionBackground, 15 * time.Second, 30 * time.Second},
		{"background advice", herr(protocol.ReasonProbeTimeout, protocol.AdviceBackgroundViable, 0), 2, ActionBackground, 30 * time.Second, time.Minute},
		{"background capped", herr(protocol.ReasonHardSymmetricRandom, "", 0), 40, ActionBackground, 15 * time.Minute, 30 * time.Minute},
		{"nat hard capped", herr(protocol.ReasonOneWayUDPOnly, "", 0), 100, ActionRetry, 15 * time.Minute, 30 * time.Minute},
		{"relay advice", herr(protocol.ReasonCandidateTimeout, protocol.AdviceRelayOnly, 0), 1, ActionRelayOnly, 30 * time.Minute, time.Hour},
		{"udp blocked", herr(protocol.ReasonUDPBlocked, "", 0), 2, ActionRelayOnly, time.Hour, 2 * time.Hour},
		{"relay capped", herr(protocol.ReasonNoCommonFamily, "", 0), 9, ActionRelayOnly, 12 * time.Hour, 24 * time.Hour},
		{"fatal", herr(protocol.ReasonInvalidArgument, "", 0), 1, ActionGiveUp, 0, 0},
		{"internal", herr(protocol.ReasonInternal, "", 0), 1, ActionRetry, 500 * time.Millisecond, time.Second},
		{"token", herr(protocol.ReasonTokenMismatch, "", 0), 1, ActionGiveUp, 0, 0},
		{"fatal with advice", herr(protocol.ReasonTransportMismatch, protocol.AdviceRelayOnly, 0), 1, ActionRelayOnly, 30 * time.Minute, time.Hour},
	} {
		for range 20 { // the delay is random within its bounds
			a := NextAttempt(tc.err, tc.attempt)
			if a.Action != tc.action || a.Delay < tc.min || a.Delay > tc.max {
				t.Fatalf("%s: %v %v, want %v in [%v, %v]", tc.name, a.Action, a.Delay, tc.action, tc.min, tc.max)
			}
		}
	}
	for a, want := range map[Action]string{ActionGiveUp: "give_up", ActionRetry: "retry", ActionBackground: "background", ActionRelayOnly: "relay_only", 9: "unknown"} {
		if a.String() != want {
			t.Errorf("%d: %s", a, a.String())
		}
	}
}

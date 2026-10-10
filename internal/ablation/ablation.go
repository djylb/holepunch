package ablation

import (
	"context"
	"strings"
)

// Set is one combination of ablation switches. A true field turns the
// mechanism off; the zero value is the full product.
type Set struct {
	// SinglePortProbe: the server opens one probe port, sends no extra/alt
	// replies and merges nothing beyond the cookie (roughly a single STUN
	// query).
	SinglePortProbe bool
	// NoRTTAlign: no RTT measurement; both clients start on receiving go
	// (delay_ms = 0).
	NoRTTAlign bool
	// NoRoleAssign: no sender/receiver roles; both clients run the same plan,
	// with no low-TTL pre-opening and no use of host capabilities.
	NoRoleAssign bool
	// NoAssistRelay: the coordinator drops every punch_assist (peer_seen
	// forwarding and third-observer traits corrections) and takes no
	// punch-time drift; the client ignores the assists it gets and does not
	// re-observe its mapping.
	NoAssistRelay bool
	// NoSandwich: no sandwich probing and no peer_targets{source: sandwich}.
	NoSandwich bool
	// NoRefresh: the coordinator asks no side for an anchor refresh before a
	// round fires; a SEQ side's next ports are predicted from what natprobe saw
	// while probing and the mappings seen since.
	NoRefresh bool
	// NoRounds: max_rounds = 1; no preemption, rescue round or variant switch.
	NoRounds bool
	// NoMemory: the coordinator neither reads nor writes StrategyMemory and
	// natprobe neither reads nor writes TraitsMemory.
	NoMemory bool
	// NoEarlyAbort: no Reject at summary time and no conversion of
	// punch_result{ok: false} into a punch_abort for the peer; sessions run
	// to their deadline.
	NoEarlyAbort bool
	// NoPrediction: punch observed/direct targets only; no prediction,
	// random ports or birthday (reported only, not gated).
	NoPrediction bool
	// NoOpener: every datagram leaves as a bare sealed packet; no flow
	// starts with a STUN-wrapped opener. It is no control-link mechanism —
	// the opener needs no control link — and so not one of the Singles: it
	// shows what the opener is worth on a network that classifies outbound
	// flows. Ordinary hole punching has no opener, so Plain sets it.
	NoOpener bool
}

// switches returns the switches in declaration order with their names.
func (s Set) switches() [11]struct {
	name string
	on   bool
} {
	return [11]struct {
		name string
		on   bool
	}{
		{"SinglePortProbe", s.SinglePortProbe},
		{"NoRTTAlign", s.NoRTTAlign},
		{"NoRoleAssign", s.NoRoleAssign},
		{"NoAssistRelay", s.NoAssistRelay},
		{"NoSandwich", s.NoSandwich},
		{"NoRefresh", s.NoRefresh},
		{"NoRounds", s.NoRounds},
		{"NoMemory", s.NoMemory},
		{"NoEarlyAbort", s.NoEarlyAbort},
		{"NoPrediction", s.NoPrediction},
		{"NoOpener", s.NoOpener},
	}
}

// Plain returns the ordinary hole punching baseline: every switch set.
func Plain() Set {
	return Set{
		SinglePortProbe: true,
		NoRTTAlign:      true,
		NoRoleAssign:    true,
		NoAssistRelay:   true,
		NoSandwich:      true,
		NoRefresh:       true,
		NoRounds:        true,
		NoMemory:        true,
		NoEarlyAbort:    true,
		NoPrediction:    true,
		NoOpener:        true,
	}
}

// Singles returns the ten single-switch ablations of the control-link
// mechanisms in declaration order; NoOpener is not one of them.
func Singles() []Set {
	return []Set{
		{SinglePortProbe: true},
		{NoRTTAlign: true},
		{NoRoleAssign: true},
		{NoAssistRelay: true},
		{NoSandwich: true},
		{NoRefresh: true},
		{NoRounds: true},
		{NoMemory: true},
		{NoEarlyAbort: true},
		{NoPrediction: true},
	}
}

// names returns the names of the switches that are set, in declaration order.
func (s Set) names() []string {
	var names []string
	for _, sw := range s.switches() {
		if sw.on {
			names = append(names, sw.name)
		}
	}
	return names
}

// String names the set for reports: "full" for the zero Set, "plain" for
// Plain, otherwise the set switches joined by "+".
func (s Set) String() string {
	switch s {
	case Set{}:
		return "full"
	case Plain():
		return "plain"
	}
	return strings.Join(s.names(), "+")
}

type ctxKey struct{}

// With returns a context carrying s. A nil parent is treated as
// context.Background.
func With(parent context.Context, s Set) context.Context {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithValue(parent, ctxKey{}, s)
}

// From returns the Set carried by ctx, or the zero Set (full product) when
// there is none or ctx is nil.
func From(ctx context.Context) Set {
	if ctx == nil {
		return Set{}
	}
	s, _ := ctx.Value(ctxKey{}).(Set)
	return s
}

package coord

import "github.com/djylb/holepunch/internal/plan"

// Planner decides the punch. Both methods must be
// pure functions of their input; the coordinator calls them outside every
// lock and inside a recover boundary, and it does not trust the output: every
// decision is clamped to the budget classes, the session and key budgets and
// the protocol limits, and every target passes admission. A Planner that
// panics is replaced by internal/plan's DefaultPlanner for the rest of the
// session.
type Planner interface {
	// Classify runs once, when both probe reports are in.
	Classify(in ClassifyInput) Classification
	// Round runs before every round.
	Round(in RoundInput) RoundDecision
}

// The planner types are those of internal/plan, the strategy engine the
// coordinator and the client runtime share.
type (
	// ClassifyInput is the classification input: the merged views by role.
	ClassifyInput = plan.ClassifyInput
	// Classification is the one-shot classification; the coordinator derives
	// the StrategyKey from its SideA and the views.
	Classification = plan.Classification
	// RoundInput is the per-round planner input. Remaining is punchDeadline −
	// now and D the start margin the coordinator computed; FireAt and Mappings
	// are on the axis whose origin is the natprobe registration.
	RoundInput = plan.RoundInput
	// MappingSample is a side's external mapping seen while punching.
	MappingSample = plan.MappingSample
	// FamilyRound is what one shared family runs in a round.
	FamilyRound = plan.FamilyRound
	// RoundDecision is the per-round planner output.
	RoundDecision = plan.RoundDecision
	// RoundOutcome summarises a finished round; Budget is the class the
	// coordinator actually granted, Families the decision's families
	// under that grant, SeenFrom and Hit the round's own results.
	RoundOutcome = plan.RoundOutcome
	// Evidence accumulates both clients' round results across rounds.
	Evidence = plan.Evidence
	// VariantID identifies a round template (at most 32).
	VariantID = plan.VariantID
	// RoundClass is the coordinator's reading of a finished round.
	RoundClass = plan.RoundClass
)

// Round classes.
const (
	RoundNoReport    = plan.RCNoReport    // one side's round_result is missing
	RoundConfirmed   = plan.RCConfirmed   // a side confirmed
	RoundConfirmLost = plan.RCConfirmLost // both sides saw each other, no confirmation
	RoundOneWay      = plan.RCOneWay      // only one direction carried packets
	RoundNoContact   = plan.RCNoContact   // no peer packet either way
	RoundBlocked     = plan.RCBlocked     // udp_blocked or ICMP unreachable >= 50
)

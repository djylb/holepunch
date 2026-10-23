// Package plan is the contract between holepunch's server coordinator
// (package coord) and a punch planner: the Planner interface and the values
// it reads and returns.
//
// A Planner decides how two clients punch. Classify runs once, when both
// probe reports are in, and turns the merged views of the two sides into a
// Classification: the shared families, the primary family's ladder of round
// variants and its canonical side, or a reason not to punch at all. Round
// runs before every round and turns a RoundInput — the classification, the
// previous rounds' outcomes and the evidence, the time and packet budgets
// left, the current views — into a RoundDecision: each side's per-family
// plan, the round's class and window, or a reason to stop.
//
// Both methods are pure functions of their input. The coordinator calls them
// outside every lock and inside a recover boundary, and it does not trust
// them: every decision is clamped to the budget classes, the session and
// per-key budgets and the protocol limits, every target passes the clients'
// admission, and a planner that panics is replaced by the built-in one for
// the rest of the session (coord.Config.Planner).
//
// The built-in planner is coord.DefaultPlanner. Its Round derives everything
// it needs from its input, so a custom planner can wrap it, adjust its
// classification or its decisions and delegate the rest:
//
//	type relayFirst struct{ plan.Planner }
//
//	func (p relayFirst) Classify(in plan.ClassifyInput) plan.Classification {
//		cl := p.Planner.Classify(in)
//		if cl.PairClass == "rnd_x_rnd" {
//			cl.Reject = protocol.ReasonHardSymmetricRandom // straight to the relay
//		}
//		return cl
//	}
//
//	func (p relayFirst) Round(in plan.RoundInput) plan.RoundDecision {
//		in.MaxRounds = min(in.MaxRounds, 3)
//		return p.Planner.Round(in)
//	}
//
//	co, err := coord.New(coord.Config{Planner: relayFirst{coord.DefaultPlanner()}, ...})
//
// The package depends only on the standard library and protocol. Its values
// are plain data; Clone makes a deep copy of each.
package plan

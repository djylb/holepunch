package coord

import (
	engine "github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/plan"
)

// DefaultPlanner returns the built-in planner, the one a nil Config.Planner
// selects. A custom planner may wrap it and adjust its classifications and
// decisions: the built-in Round derives everything it needs from its
// plan.RoundInput, so it plans whatever Classification it is handed — the
// families of Classification.Families it shares, in that order, the
// primary one on Classification.Ladder (or RoundInput.Order).
func DefaultPlanner() plan.Planner { return engine.DefaultPlanner{} }

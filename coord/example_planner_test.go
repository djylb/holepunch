package coord_test

import (
	"log"

	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// relayFirst is the built-in planner, except that it sends pairs it
// classifies rnd_x_rnd straight to the relay and punches at most three
// rounds.
type relayFirst struct{ plan.Planner }

func (p relayFirst) Classify(in plan.ClassifyInput) plan.Classification {
	cl := p.Planner.Classify(in)
	if cl.PairClass == "rnd_x_rnd" {
		cl.Reject = protocol.ReasonHardSymmetricRandom
	}
	return cl
}

func (p relayFirst) Round(in plan.RoundInput) plan.RoundDecision {
	in.MaxRounds = min(in.MaxRounds, 3)
	return p.Planner.Round(in)
}

// ExampleDefaultPlanner wraps the built-in planner in a custom one. The
// coordinator clamps whatever a planner decides, so a wrapper only has to
// be right about what it changes.
func ExampleDefaultPlanner() {
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	var spec protocol.ProbeSpec // the natprobe server's ProbeSpec, as in Example
	co, err := coord.New(coord.Config{
		Registry:     reg,
		DefaultProbe: spec,
		Planner:      relayFirst{coord.DefaultPlanner()},
	})
	if err != nil {
		log.Print(err)
		return
	}
	defer func() { _ = co.Close() }()
}

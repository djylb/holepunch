package plan

import (
	"slices"

	"github.com/djylb/holepunch/protocol"
)

// Deep copies of the planner's inputs and outputs. A planner may write its
// input, and the coordinator keeps outcomes and classifications across
// rounds, so each Clone shares no pointer, slice or map with its receiver.

// Clone returns a deep copy of in.
func (in ClassifyInput) Clone() ClassifyInput {
	in.Initiator, in.Responder = in.Initiator.Clone(), in.Responder.Clone()
	in.Measured = [2]protocol.PeerView{in.Measured[0].Clone(), in.Measured[1].Clone()}
	in.Pair = in.Pair.Clone()
	in.Policy = in.Policy.Clone()
	in.Features = slices.Clone(in.Features)
	return in
}

// Clone returns a deep copy of c.
func (c Classification) Clone() Classification {
	c.Families = slices.Clone(c.Families)
	c.Ladder = slices.Clone(c.Ladder)
	return c
}

// Clone returns a deep copy of e.
func (e Evidence) Clone() Evidence {
	for r := range e.SeenFrom {
		e.SeenFrom[r] = slices.Clone(e.SeenFrom[r])
	}
	return e
}

// Clone returns a deep copy of o.
func (o RoundOutcome) Clone() RoundOutcome {
	for r := range o.SeenFrom {
		o.SeenFrom[r] = slices.Clone(o.SeenFrom[r])
	}
	o.Families = slices.Clone(o.Families)
	return o
}

// Clone returns a deep copy of in.
func (in RoundInput) Clone() RoundInput {
	in.Class = in.Class.Clone()
	in.Order = slices.Clone(in.Order)
	in.Prev = slices.Clone(in.Prev)
	for i := range in.Prev {
		in.Prev[i] = in.Prev[i].Clone()
	}
	in.Evidence = in.Evidence.Clone()
	in.Views = [2]protocol.PeerView{in.Views[0].Clone(), in.Views[1].Clone()}
	in.Measured = [2]protocol.PeerView{in.Measured[0].Clone(), in.Measured[1].Clone()}
	in.Pair = in.Pair.Clone()
	in.Policy = in.Policy.Clone()
	for r := range in.Mappings {
		in.Mappings[r] = slices.Clone(in.Mappings[r])
	}
	for r := range in.Refresh {
		in.Refresh[r] = slices.Clone(in.Refresh[r])
	}
	return in
}

// Clone returns a deep copy of d.
func (d RoundDecision) Clone() RoundDecision {
	for r := range d.Sides {
		d.Sides[r] = slices.Clone(d.Sides[r])
		for i := range d.Sides[r] {
			d.Sides[r][i] = d.Sides[r][i].Clone()
		}
	}
	d.Families = slices.Clone(d.Families)
	return d
}

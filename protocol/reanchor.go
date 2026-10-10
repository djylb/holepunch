package protocol

import (
	"bytes"
	"encoding/json"
	"slices"
)

// The round-1 anchor update, the one exception
// to "round 1's plan is the summary's". The coordinator writes the
// summaries and asks for the anchor refresh at once; by the time the
// refresh is back the clients have bound their sockets for the summary's
// plan, so the go of round 1 may carry that plan again with the predict
// stages re-aimed — a new anchor, a span no longer than before — and
// nothing else changed. The client checks exactly that.

// Reanchor returns the plan with the predict stage si of family side fi aimed
// at anchor over span, which must be at least 1 and at most the stage's span;
// otherwise, or for another kind of stage, the plan comes back as it is. The
// positions a shorter span cuts leave the side's MaxPackets and
// MaxDistinctPorts, which stay what the stages expand to. The plan's slices are
// copied, never written.
func (r RoundPlan) Reanchor(fi, si int, anchor, span uint16) RoundPlan {
	if fi < 0 || fi >= len(r.Sides) || si < 0 || si >= len(r.Sides[fi].Stages) {
		return r
	}
	st := r.Sides[fi].Stages[si]
	if st.Kind != StagePredict || span == 0 || span > st.Span {
		return r
	}
	cut := st.Span - span
	st.Anchor, st.Span = anchor, span
	s := r.Sides[fi]
	s.Stages = slices.Clone(s.Stages)
	s.Stages[si] = st
	s.MaxPackets -= min(uint32(cut), s.MaxPackets)
	s.MaxDistinctPorts = uint16(max(int(s.MaxDistinctPorts)-int(cut), 1))
	r.Sides = slices.Clone(r.Sides)
	r.Sides[fi] = s
	return r
}

// CheckAnchorUpdate reports whether u, the plan a round-1 go carries, is
// r — the summary's round-1 plan — re-aimed as Reanchor does, in any number
// of its predict stages, and otherwise the same: the same sides, stages,
// sockets, limits and window. Anything else is a protocol_violation with
// detail round1_plan.
func (r RoundPlan) CheckAnchorUpdate(u RoundPlan) error {
	if len(u.Sides) != len(r.Sides) {
		return violation("round1_plan", "%d family sides, the summary has %d", len(u.Sides), len(r.Sides))
	}
	want := r
	for fi, s := range r.Sides {
		if len(u.Sides[fi].Stages) != len(s.Stages) {
			return violation("round1_plan", "side %d: %d stages, the summary has %d", fi, len(u.Sides[fi].Stages), len(s.Stages))
		}
		for si, st := range s.Stages {
			us := u.Sides[fi].Stages[si]
			if st.Kind != StagePredict || us.Kind != StagePredict || us.Anchor == st.Anchor && us.Span == st.Span {
				continue
			}
			if us.Span == 0 || us.Span > st.Span {
				return violation("round1_plan", "side %d stage %d: span %d, the summary's is %d", fi, si, us.Span, st.Span)
			}
			want = want.Reanchor(fi, si, us.Anchor, us.Span)
		}
	}
	a, errA := json.Marshal(want)
	b, errB := json.Marshal(u)
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		return violation("round1_plan", "differs from the summary's plan beyond the predict anchors")
	}
	return nil
}

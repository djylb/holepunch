package protocol

import (
	"errors"
	"testing"
)

// The round-1 anchor update: a predict stage may
// take a new anchor and a span no longer than before, the cut leaving
// MaxPackets and MaxDistinctPorts; nothing else may change, and the
// summary's plan is never written.
func TestReanchor(t *testing.T) {
	p := sampleRoundPlan(1)
	const si = 1 // the predict stage
	up := p.Reanchor(0, si, 61020, 24)
	got, was := up.Sides[0], p.Sides[0]
	if st := got.Stages[si]; st.Anchor != 61020 || st.Span != 24 {
		t.Fatalf("stage %+v, want anchor 61020 span 24", st)
	}
	if got.MaxPackets != was.MaxPackets-8 || got.MaxDistinctPorts != was.MaxDistinctPorts-8 {
		t.Fatalf("max_packets %d max_distinct_ports %d, want %d %d", got.MaxPackets, got.MaxDistinctPorts, was.MaxPackets-8, was.MaxDistinctPorts-8)
	}
	if st := was.Stages[si]; st.Anchor != 61005 || st.Span != 32 || was.MaxPackets != 200 {
		t.Fatalf("the summary's plan changed: %+v", was)
	}
	for name, q := range map[string]RoundPlan{
		"longer span":        p.Reanchor(0, si, 61020, 33),
		"zero span":          p.Reanchor(0, si, 61020, 0),
		"not a predict":      p.Reanchor(0, 0, 61020, 1),
		"no such side":       p.Reanchor(1, si, 61020, 24),
		"no such stage":      p.Reanchor(0, 9, 61020, 24),
		"negative positions": p.Reanchor(-1, -1, 61020, 24),
	} {
		if err := p.CheckAnchorUpdate(q); err != nil {
			t.Errorf("%s: the plan should come back as it was: %v", name, err)
		}
	}
}

func TestCheckAnchorUpdate(t *testing.T) {
	p := sampleRoundPlan(1)
	with := func(f func(*RoundPlan)) RoundPlan { // f changes a copy deep enough for its writes
		q := p
		q.Sides = append([]FamilySide(nil), p.Sides...)
		for i := range q.Sides {
			q.Sides[i].Stages = append([]Stage(nil), p.Sides[i].Stages...)
		}
		f(&q)
		return q
	}
	for _, c := range []struct {
		name string
		u    RoundPlan
		ok   bool
	}{
		{"unchanged", p, true},
		{"new anchor", p.Reanchor(0, 1, 61040, 32), true},
		{"new anchor, shorter span", p.Reanchor(0, 1, 61040, 16), true},
		{"longer span", with(func(q *RoundPlan) { q.Sides[0].Stages[1].Span = 40; q.Sides[0].MaxPackets += 8 }), false},
		{"span cut without its packets", with(func(q *RoundPlan) { q.Sides[0].Stages[1].Span = 16 }), false},
		{"more sockets", with(func(q *RoundPlan) { q.Sides[0].Sockets++ }), false},
		{"another window", with(func(q *RoundPlan) { q.WindowMs++ }), false},
		{"a stage less", with(func(q *RoundPlan) { q.Sides[0].Stages = q.Sides[0].Stages[:3] }), false},
		{"a side more", with(func(q *RoundPlan) { q.Sides = append(q.Sides, q.Sides[0]) }), false},
		{"a direct target moved", with(func(q *RoundPlan) { q.Sides[0].Stages[0].Targets = q.Sides[0].Stages[0].Targets[:1] }), false},
		{"a random stage re-aimed", with(func(q *RoundPlan) { q.Sides[0].Stages[2].Lo++ }), false},
		{"predict steps changed", with(func(q *RoundPlan) { q.Sides[0].Stages[1].Steps = []int16{1} }), false},
		{"pairing dropped", with(func(q *RoundPlan) { q.Sides[0].Stages[1].Pair = false }), false},
	} {
		err := p.CheckAnchorUpdate(c.u)
		if c.ok != (err == nil) {
			t.Errorf("%s: err %v, want ok %v", c.name, err, c.ok)
			continue
		}
		var ve *ValidationError
		if err != nil && (!errors.As(err, &ve) || ve.Detail != "round1_plan" || ve.Reason != ReasonProtocolViolation) {
			t.Errorf("%s: %v, want protocol_violation round1_plan", c.name, err)
		}
	}
}

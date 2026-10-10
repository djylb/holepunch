package e2e

import (
	"time"

	"github.com/djylb/holepunch/protocol"
)

// linkView is what crossed one control link, decoded: the frames a test
// needs for its assertions.
type linkView struct {
	start   *protocol.PunchStart
	report  *protocol.ProbeReport
	summary *protocol.ProbeSummary
	// summaryAt is when the coordinator wrote the summary.
	summaryAt time.Time
	gos       []goFrame
	assists   []*protocol.Assist // server to client
	rounds    []*protocol.RoundResult
	result    *protocol.PunchResult
	aborts    []*protocol.Abort
	progress  []*protocol.Progress
}

// goFrame is a punch_go and the instant the coordinator wrote it.
type goFrame struct {
	msg *protocol.PunchGo
	at  time.Time
}

// view decodes a tap's log.
func view(t *tap) linkView {
	var v linkView
	for _, ev := range t.log() {
		switch m := ev.Msg.(type) {
		case *protocol.PunchStart:
			v.start = m
		case *protocol.ProbeReport:
			v.report = m
		case *protocol.ProbeSummary:
			v.summary, v.summaryAt = m, ev.At
		case *protocol.PunchGo:
			v.gos = append(v.gos, goFrame{msg: m, at: ev.At})
		case *protocol.Assist:
			if ev.Dir == toClient {
				v.assists = append(v.assists, m)
			}
		case *protocol.RoundResult:
			v.rounds = append(v.rounds, m)
		case *protocol.PunchResult:
			v.result = m
		case *protocol.Abort:
			v.aborts = append(v.aborts, m)
		case *protocol.Progress:
			v.progress = append(v.progress, m)
		}
	}
	return v
}

// plans returns the round plans the side was given: summary.plan.round1,
// then the plan of every later go (a round-1 go carries none).
func (v linkView) plans() []protocol.RoundPlan {
	var out []protocol.RoundPlan
	if v.summary != nil {
		out = append(out, v.summary.Plan.Round1)
	}
	for _, g := range v.gos {
		if g.msg.Plan != nil {
			out = append(out, *g.msg.Plan)
		}
	}
	return out
}

// roundResult returns the side's round_result of round k, or nil.
func (v linkView) roundResult(k uint8) *protocol.RoundResult {
	for _, r := range v.rounds {
		if r.Round == k {
			return r
		}
	}
	return nil
}

// goOf returns the go of round k, or nil.
func (v linkView) goOf(k uint8) *goFrame {
	for i := range v.gos {
		if v.gos[i].msg.Round == k {
			return &v.gos[i]
		}
	}
	return nil
}

// peerTargets counts the targets and window ports the coordinator pushed
// (peer_targets), by source.
func (v linkView) peerTargets() (n int, bySource map[protocol.TargetSource]int) {
	bySource = map[protocol.TargetSource]int{}
	for _, a := range v.assists {
		if a.Kind != protocol.AssistPeerTargets {
			continue
		}
		k := len(a.Targets)
		if a.Window != nil {
			k += int(a.Window.Hi) - int(a.Window.Lo) + 1
		}
		n += k
		bySource[a.Source] += k
	}
	return n, bySource
}

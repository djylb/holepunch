package holepunch

import (
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/protocol"
)

// The nomination goroutine's outcomes. The state machine's Confirm, HandOver
// and Fail actions end up here; each records itself in the punching state
// and wakes the orchestrator, which acts on it (punchLoop).

// onConfirm runs on the nomination goroutine at the local Confirm on the
// pair c: initiation stops at once on every family and socket, control
// faults become harmless, and the orchestrator is woken to write
// round_result{confirmed} and to arm the handover timeout.
func (rt *runtime) onConfirm(a candidate.Action, c candidate.Candidate, at time.Time) {
	rt.sender.stop()
	rt.ctl.confirm()
	path := rt.pathInfo(c, a.Epoch)
	rt.punch.confirm(at, path)
	rt.phases.advanceFamily(a.Family, protocol.PhaseConfirmed, stageConfirmed, at)
	rt.phases.advance(protocol.PhaseHandover, "handover_started", at)
	rt.progress(progressEvent{stage: stageConfirmed, status: protocol.StatusOK, family: a.Family, round: path.Round, remote: a.Remote})
	rt.punch.notify()
}

// onHandOver records the handover decision with the confirmed pair and the
// committed extra paths as the state machine holds them now, and wakes the
// orchestrator.
func (rt *runtime) onHandOver(a candidate.Action, winner candidate.Candidate, extras []candidate.Candidate) {
	rt.punch.handOver(a, winner, extras)
}

// onHandoverFailed records the handover timeout as the state machine saw it.
func (rt *runtime) onHandoverFailed() {
	rt.punch.handoverFailed()
}

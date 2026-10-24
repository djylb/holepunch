package holepunch

import (
	"log/slog"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

// milestones are the progress stages logged at Info; the others are logged
// at Debug.
func milestone(stage string) bool {
	switch stage {
	case stageSummaryReceived, stageGoReceived, stageRoundEnd, stageConfirmed, stageHandoverDone:
		return true
	}
	return false
}

// logEnabled reports whether Options.Logger would record level. The
// handler is the caller's code: it runs inside a recover boundary.
//
//holepunch:callback
func (rt *runtime) logEnabled(level slog.Level) (on bool) {
	if rt.opts.Logger == nil {
		return false
	}
	if life.Safe("log", func() { on = rt.opts.Logger.Enabled(rt.callerCtx, level) }) != nil {
		rt.cnt.callbackPanics.Add(1)
	}
	return on
}

// log records one message on Options.Logger with the session's id and role
// once punch_start was read. Nothing it logs carries the token, the route
// or transport data. The handler runs inline on a library goroutine, inside
// a recover boundary; a panic in it is counted like a callback's.
//
//holepunch:callback
func (rt *runtime) log(level slog.Level, msg string, args ...any) {
	if !rt.logEnabled(level) {
		return
	}
	if sid, _ := rt.ctl.session(); sid != "" {
		args = append(args, "session_id", sid, "role", string(rt.role))
	}
	if life.Safe("log", func() { rt.opts.Logger.Log(rt.callerCtx, level, msg, args...) }) != nil {
		rt.cnt.callbackPanics.Add(1)
	}
}

// logPhase is phaseTracker.onMove: the session's phase transitions, at
// Debug.
//
//holepunch:callback
func (rt *runtime) logPhase(from, to Phase, event string) {
	rt.log(slog.LevelDebug, "holepunch: phase", "from", string(from), "to", string(to), "event", event)
}

// logProgress logs one progress event: the milestones at Info, the rest at
// Debug.
//
//holepunch:callback
func (rt *runtime) logProgress(ev progressEvent) {
	level := slog.LevelDebug
	if milestone(ev.stage) {
		level = slog.LevelInfo
	}
	if !rt.logEnabled(level) {
		return
	}
	args := []any{"stage", ev.stage, "status", string(ev.status)}
	if ev.round > 0 {
		args = append(args, "round", int(ev.round))
	}
	if ev.family != "" {
		args = append(args, "family", string(ev.family))
	}
	if ev.detail != "" {
		args = append(args, "detail", ev.detail)
	}
	if ev.remote.IsValid() {
		args = append(args, "remote", ev.remote.String())
	}
	rt.log(level, "holepunch: progress", args...)
}

// logFailure logs a failed Punch at Warn.
//
//holepunch:callback
func (rt *runtime) logFailure(e *Error) {
	args := []any{"reason", string(e.Reason), "phase", string(e.Phase)}
	if e.Detail != "" {
		args = append(args, "detail", e.Detail)
	}
	if e.Round > 0 {
		args = append(args, "round", e.Round)
	}
	if e.AbortedBy != "" {
		args = append(args, "aborted_by", string(e.AbortedBy))
	}
	if e.Advice != "" {
		args = append(args, "advice", string(e.Advice))
	}
	if e.RetryAfter > 0 {
		args = append(args, "retry_after", e.RetryAfter)
	}
	if e.Err != nil {
		args = append(args, "err", e.Err.Error())
	}
	rt.log(slog.LevelWarn, "holepunch: session failed", args...)
}

// logDone logs a Punch that connected: the primary path at Info.
//
//holepunch:callback
func (rt *runtime) logDone(s *Session) {
	r := s.result
	rt.log(slog.LevelInfo, "holepunch: session done", "family", string(r.Path.Family), "kind", string(r.Path.Kind),
		"local", r.Path.LocalAddr.String(), "remote", r.Path.RemoteAddr.String(), "rtt", r.Path.RTT,
		"extra_paths", len(r.ExtraPaths), "rounds", r.Rounds, "variant", r.Variant, "total", r.Timing.Total)
}

// logStart logs the accepted punch_start.
//
//holepunch:callback
func (rt *runtime) logStart(m protocol.PunchStart) {
	rt.log(slog.LevelInfo, "holepunch: session started", "observers", len(m.Probe.Observers), "stun", len(m.Probe.STUN),
		"mode", string(m.Mode))
}

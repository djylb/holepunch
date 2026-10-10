package protocol

import "log/slog"

// Redacted log forms: the token never appears, the route only as its first
// 4 hex digits, and transport data (a QUIC certificate, for example) is
// replaced by its length. Token and RouteID
// redact themselves wherever they are printed; these LogValuers also keep
// the large and sensitive parts of the three messages out of structured logs.

// LogValue implements slog.LogValuer without the token and the full route.
func (m PunchStart) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("session_id", m.SessionID),
		slog.String("role", string(m.Role)),
		slog.String("route", m.Wire.RouteID.String()),
		slog.Int("payload_min", int(m.Wire.PayloadMin)),
		slog.Int("payload_max", int(m.Wire.PayloadMax)),
		slog.Any("features", m.Control.Features),
		slog.Int("observers", len(m.Probe.Observers)),
		slog.Any("timeouts", m.Timeouts),
	)
}

// LogValue implements slog.LogValuer without transport data.
func (m ProbeReport) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("session_id", m.SessionID),
		slog.String("role", string(m.Role)),
		slog.Any("features", m.Control.Features),
		slog.Int("families", len(m.Families)),
		slog.Int("elapsed_ms", int(m.ElapsedMs)),
		slog.String("transport", m.Transport.Mode),
		slog.Int("transport_data_len", len(m.Transport.Data)),
	)
}

// LogValue implements slog.LogValuer without the peer's transport data.
func (m ProbeSummary) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("session_id", m.SessionID),
		slog.String("plan", m.Plan.ID),
		slog.String("pair_class", m.Plan.PairClass),
		slog.Int("rounds_max", int(m.Plan.RoundsMax)),
		slog.String("transport", m.Transport.Mode),
		slog.Int("peer_data_len", len(m.Transport.PeerData)),
	)
}

// LogValue implements slog.LogValuer with the route shortened.
func (w WireSpec) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("route", w.RouteID.String()),
		slog.Int("payload_min", int(w.PayloadMin)),
		slog.Int("payload_max", int(w.PayloadMax)),
	)
}

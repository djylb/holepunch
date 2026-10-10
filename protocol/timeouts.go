package protocol

// Timeouts are the protocol timeouts in milliseconds. Zero fields mean the
// default; Normalize clamps to
// the ranges below.
type Timeouts struct {
	ProbeTimeoutMs     uint32 `json:"probe_timeout_ms"`     // default 2000, [500, 10000]
	SummaryWaitMs      uint32 `json:"summary_wait_ms"`      // server promise from writing punch_start; default 20000, [1000, 60000]
	GoWaitMs           uint32 `json:"go_wait_ms"`           // ready → first go, and between rounds; default 5000, [500, 15000]
	HandshakeTimeoutMs uint32 `json:"handshake_timeout_ms"` // from the first punch_go, all rounds; default 20000, [2000, 60000]
	HandoverTimeoutMs  uint32 `json:"handover_timeout_ms"`  // from local Confirm; default 2000, [500, 10000]
	TransportTimeoutMs uint32 `json:"transport_timeout_ms"` // passed through to the caller; default 10000, [1000, 60000]
	MaxRounds          uint8  `json:"max_rounds"`           // default 5, [1, 6]; excludes the one rescue round
}

// DefaultTimeouts are the defaults of every field.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		ProbeTimeoutMs:     2000,
		SummaryWaitMs:      20000,
		GoWaitMs:           5000,
		HandshakeTimeoutMs: 20000,
		HandoverTimeoutMs:  2000,
		TransportTimeoutMs: 10000,
		MaxRounds:          5,
	}
}

// Normalize returns t with zero fields set to their defaults and every field
// clamped to its range.
func (t Timeouts) Normalize() Timeouts {
	d := DefaultTimeouts()
	return Timeouts{
		ProbeTimeoutMs:     clampDefault(t.ProbeTimeoutMs, d.ProbeTimeoutMs, 500, 10000),
		SummaryWaitMs:      clampDefault(t.SummaryWaitMs, d.SummaryWaitMs, 1000, 60000),
		GoWaitMs:           clampDefault(t.GoWaitMs, d.GoWaitMs, 500, 15000),
		HandshakeTimeoutMs: clampDefault(t.HandshakeTimeoutMs, d.HandshakeTimeoutMs, 2000, 60000),
		HandoverTimeoutMs:  clampDefault(t.HandoverTimeoutMs, d.HandoverTimeoutMs, 500, 10000),
		TransportTimeoutMs: clampDefault(t.TransportTimeoutMs, d.TransportTimeoutMs, 1000, 60000),
		MaxRounds:          clampDefault(t.MaxRounds, d.MaxRounds, 1, 6),
	}
}

// Within normalizes t and limits each field to the normalized limit: the
// client applies the timeouts of probe_summary with
// summary.Timeouts.Within(start.Timeouts), because they may only be tighter
// than those of punch_start.
func (t Timeouts) Within(limit Timeouts) Timeouts {
	a, b := t.Normalize(), limit.Normalize()
	return Timeouts{
		ProbeTimeoutMs:     min(a.ProbeTimeoutMs, b.ProbeTimeoutMs),
		SummaryWaitMs:      min(a.SummaryWaitMs, b.SummaryWaitMs),
		GoWaitMs:           min(a.GoWaitMs, b.GoWaitMs),
		HandshakeTimeoutMs: min(a.HandshakeTimeoutMs, b.HandshakeTimeoutMs),
		HandoverTimeoutMs:  min(a.HandoverTimeoutMs, b.HandoverTimeoutMs),
		TransportTimeoutMs: min(a.TransportTimeoutMs, b.TransportTimeoutMs),
		MaxRounds:          min(a.MaxRounds, b.MaxRounds),
	}
}

func clampDefault[T uint8 | uint16 | uint32](v, def, lo, hi T) T {
	if v == 0 {
		v = def
	}
	return min(max(v, lo), hi)
}

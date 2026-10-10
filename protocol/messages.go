package protocol

import (
	"math"
	"time"

	"github.com/djylb/holepunch/controlwire"
)

// MessageType is the type byte of a control frame. The twelve types are
// numbered contiguously from 1;
// 13–255 are reserved. The numbers, caps, directions and write priorities are
// defined once, in controlwire's frame-type table; MessageType names them for
// the message layer.
type MessageType uint8

// The twelve message types.
const (
	MsgPunchStart   = MessageType(controlwire.TypePunchStart)   // S→C
	MsgProbeReport  = MessageType(controlwire.TypeProbeReport)  // C→S
	MsgProbeSummary = MessageType(controlwire.TypeProbeSummary) // S→C
	MsgPunchReady   = MessageType(controlwire.TypePunchReady)   // C→S
	MsgPunchGo      = MessageType(controlwire.TypePunchGo)      // S→C
	MsgProgress     = MessageType(controlwire.TypeProgress)     // C→S, telemetry only
	MsgAssist       = MessageType(controlwire.TypeAssist)       // C→S→C and S→C
	MsgAbort        = MessageType(controlwire.TypeAbort)        // S→C only
	MsgPing         = MessageType(controlwire.TypePing)         // S→C
	MsgPong         = MessageType(controlwire.TypePong)         // C→S
	MsgRoundResult  = MessageType(controlwire.TypeRoundResult)  // C→S
	MsgPunchResult  = MessageType(controlwire.TypePunchResult)  // C→S
)

// String is the wire name of the type ("punch_go"), or "type(N)".
func (t MessageType) String() string { return controlwire.Type(t).String() }

// MaxPayload is the type's payload cap.
func (t MessageType) MaxPayload() int { return controlwire.Type(t).Cap() }

// Known reports whether t is one of the twelve message types.
func (t MessageType) Known() bool { return controlwire.Type(t).Known() }

// Message is implemented by the twelve message types (values and pointers).
// Each type also has a Normalize method, which returns the message with the
// receiver-side clamps applied and whether a value changed.
type Message interface {
	// MessageType is the frame type the message travels in.
	MessageType() MessageType
	// Validate checks the message's structure: required fields, enumeration
	// values, string and list lengths. Numeric limits that the receiver clamps
	// are not errors; see Normalize.
	Validate() error
}

// ---- 1 punch_start (S→C, one per side) ----

// PunchStart opens a session on a control link: the first library frame.
// Token and route appear on the wire only here; its
// LogValue redacts them.
type PunchStart struct {
	SessionID string      `json:"session_id"` // 1..64 bytes of [A-Za-z0-9_-]
	Role      Role        `json:"role"`       // the receiver's role; the peer's is Role.Peer()
	Token     Token       `json:"token"`      // base64url of 32 random bytes
	Wire      WireSpec    `json:"wire"`
	Control   ControlSpec `json:"control"` // version == frame major; features offered
	Probe     ProbeSpec   `json:"probe"`
	Timeouts  Timeouts    `json:"timeouts"`
	Policy    *Policy     `json:"policy,omitempty"` // this side's ceiling; the client may only tighten
	// Mode is the server's offer: background
	// only when the caller of the coordinator runs the session behind a
	// relay; "" is interactive. The client may only decline it.
	Mode SessionMode `json:"mode,omitempty"`
}

// ---- 9 ping (S→C) / 10 pong (C→S): link-level, no session_id ----

// Ping asks for a pong; answered in every phase.
type Ping struct {
	Seq uint8 `json:"seq"` // 1..8, increasing per link
}

// Pong answers a ping.
type Pong struct {
	Seq          uint8  `json:"seq"`            // echoed
	HoldUs       uint32 `json:"hold_us"`        // ping read → pong written, local monotonic
	ClientUnixMs int64  `json:"client_unix_ms"` // the client's wall clock; diagnostic only
}

// PongFor is the answer to ping p read at readAt (Frame.At) and written at
// now: hold_us covers the local time between the two (the server subtracts
// it from the RTT sample); client_unix_ms is now's wall clock, for
// clock-skew diagnostics only.
func PongFor(p Ping, readAt, now time.Time) Pong {
	hold := max(now.Sub(readAt).Microseconds(), 0)
	return Pong{Seq: p.Seq, HoldUs: uint32(min(hold, math.MaxUint32)), ClientUnixMs: now.UnixMilli()}
}

// ---- 2 probe_report (C→S) ----

// ProbeReport carries the client's probe results. It is not sent when probing
// failed for every family (punch_result{ok:false} instead).
type ProbeReport struct {
	SessionID string         `json:"session_id"`
	Role      Role           `json:"role"`    // consistency check only
	Control   ControlSpec    `json:"control"` // version + accepted features
	Caps      ClientCaps     `json:"caps"`
	ElapsedMs uint32         `json:"elapsed_ms"` // punch_start received → this frame written (an RTT sample)
	Families  []FamilyReport `json:"families"`   // 1..2
	Clock     ClockSample    `json:"clock"`
	Transport Transport      `json:"transport"`
	// Mode is the mode this client accepts: background only when
	// punch_start offered it and the caller asked for it.
	Mode SessionMode `json:"mode,omitempty"`
}

// ---- 3 probe_summary (S→C, one per side, receiver's view) ----

// ProbeSummary is the server's merged view and the first round's plan.
type ProbeSummary struct {
	SessionID string        `json:"session_id"`
	Self      PeerView      `json:"self"` // the receiver as the server sees it
	Peer      PeerView      `json:"peer"` // endpoints: verified or constrained self-reported
	Pair      PairFacts     `json:"pair"`
	Transport TransportPick `json:"transport"`
	Timeouts  Timeouts      `json:"timeouts"` // only tighter than punch_start's
	Plan      PlanSpec      `json:"plan"`
}

// ---- 4 punch_ready (C→S) ----

// PunchReady reports that the sockets for round 1 are bound.
type PunchReady struct {
	SessionID string        `json:"session_id"`
	Role      Role          `json:"role"`
	ElapsedMs uint32        `json:"elapsed_ms"` // summary received → this frame written (an RTT sample)
	Families  []FamilyReady `json:"families"`   // 1..2
}

// ---- 5 punch_go (S→C, one per round per side) ----

// PunchGo starts a round: fire at (the instant the frame was read) + DelayMs.
type PunchGo struct {
	Plan      *RoundPlan `json:"plan,omitempty"` // round 1: absent (the plan is summary.plan.round1); round >= 2: required
	SessionID string     `json:"session_id"`
	DelayMs   uint16     `json:"delay_ms"`         // clamped to [0, 2000]
	WindowMs  uint16     `json:"window_ms"`        // = plan.window_ms; clamped to 10000, 45000 for a background round
	RTTMs     uint16     `json:"rtt_ms,omitempty"` // server's estimate of this link's RTT
	Round     uint8      `json:"round"`            // 1..8, strictly increasing; a larger round preempts
	Final     bool       `json:"final,omitempty"`
}

// ---- 6 punch_progress (C→S, telemetry only) ----

// Progress is telemetry: droppable, rate limited, never an input of any
// server decision.
type Progress struct {
	Counters  map[string]uint32 `json:"counters,omitempty"` // <= 16 keys
	Meta      map[string]string `json:"meta,omitempty"`     // <= 16 keys, values <= 64 B; caller pass-through
	SessionID string            `json:"session_id"`
	Role      Role              `json:"role"`
	Stage     string            `json:"stage"` // open enumeration, [a-z][a-z0-9_]{0,63}
	Status    ProgressStatus    `json:"status,omitempty"`
	Detail    string            `json:"detail,omitempty"` // <= 128 B
	AtMs      uint32            `json:"at_ms"`            // since punch_start, monotonic
	Seq       uint16            `json:"seq"`              // sender's monotonic sequence
	Round     uint8             `json:"round,omitempty"`  // <= 8
}

// ProgressStatus is Progress.Status.
type ProgressStatus string

// Progress statuses.
const (
	StatusOK   ProgressStatus = "ok"
	StatusFail ProgressStatus = "fail"
	StatusInfo ProgressStatus = "info"
)

// ---- 8 punch_abort (S→C only) ----

// Abort ends a session from the server. The server never forwards a client's
// frame; it always writes a new one. A client never sends it: a client's
// terminal report is punch_result, and a punch_abort arriving at the server is
// a wrong-direction frame (controlwire discards and counts it).
type Abort struct {
	SessionID    string `json:"session_id"`
	By           Role   `json:"by"`                       // initiator | responder | server: where the failure came from
	Code         Reason `json:"code"`                     // empty or unknown: AbortReason maps to aborted_by_*
	Detail       string `json:"detail,omitempty"`         // <= 256 B
	RetryAfterMs uint32 `json:"retry_after_ms,omitempty"` // suggested retry delay (server_busy, ...)
}

// ---- 11 round_result (C→S) ----

// RoundResult reports a round: at window end, on budget exhaustion, on a
// fatal local error, and immediately on local Confirm (status confirmed — the
// server's signal to stop new rounds and wind down). A preempted round sends
// none.
type RoundResult struct {
	Path       *PathInfo       `json:"path,omitempty"` // required when confirmed
	SessionID  string          `json:"session_id"`
	Role       Role            `json:"role"`
	Status     RoundStatus     `json:"status"`
	Code       Reason          `json:"code,omitempty"` // status fatal: udp_blocked | local_port_bind_failed | ...
	Families   []FamilyOutcome `json:"families"`       // <= 2
	ElapsedMs  uint32          `json:"elapsed_ms"`     // the round's punch_go read → this frame written (sample Sk)
	FireSkewMs int16           `json:"fire_skew_ms"`   // actual fire − (t_recv + delay_ms)
	Round      uint8           `json:"round"`          // 1..8
}

// RoundStatus is RoundResult.Status.
type RoundStatus string

// Round statuses.
const (
	RoundWindowEnd       RoundStatus = "window_end"
	RoundBudgetExhausted RoundStatus = "budget_exhausted"
	RoundConfirmed       RoundStatus = "confirmed" // sent at the instant of local Confirm
	RoundFatal           RoundStatus = "fatal"
)

// ---- 12 punch_result (C→S, terminal, exactly one per side) ----

// PunchResult is a client's terminal report (success after the UDP handover,
// failure or cancellation before cleanup), best effort with a bounded flush.
type PunchResult struct {
	SessionID  string         `json:"session_id"`
	Role       Role           `json:"role"`
	OK         bool           `json:"ok"`
	Code       Reason         `json:"code,omitempty"`        // required when !ok
	Phase      Phase          `json:"phase"`                 // the client phase at the end
	Detail     string         `json:"detail,omitempty"`      // <= 256 B, human readable, no key material
	Path       *PathInfo      `json:"path,omitempty"`        // required when ok, with confirmed_by
	ExtraPaths []PathInfo     `json:"extra_paths,omitempty"` // only when ok: the other paths handed over with Path, <= MaxPaths-1, each with confirmed_by
	Stats      Stats          `json:"stats"`
	Timing     Timing         `json:"timing"`
	Traits     []TraitsUpdate `json:"traits,omitempty"` // <= 2: corrections of this side's traits
	Warn       []string       `json:"warn,omitempty"`   // <= 8
}

// MessageType implements Message.
func (PunchStart) MessageType() MessageType { return MsgPunchStart }

// MessageType implements Message.
func (ProbeReport) MessageType() MessageType { return MsgProbeReport }

// MessageType implements Message.
func (ProbeSummary) MessageType() MessageType { return MsgProbeSummary }

// MessageType implements Message.
func (PunchReady) MessageType() MessageType { return MsgPunchReady }

// MessageType implements Message.
func (PunchGo) MessageType() MessageType { return MsgPunchGo }

// MessageType implements Message.
func (Progress) MessageType() MessageType { return MsgProgress }

// MessageType implements Message.
func (Assist) MessageType() MessageType { return MsgAssist }

// MessageType implements Message.
func (Abort) MessageType() MessageType { return MsgAbort }

// MessageType implements Message.
func (Ping) MessageType() MessageType { return MsgPing }

// MessageType implements Message.
func (Pong) MessageType() MessageType { return MsgPong }

// MessageType implements Message.
func (RoundResult) MessageType() MessageType { return MsgRoundResult }

// MessageType implements Message.
func (PunchResult) MessageType() MessageType { return MsgPunchResult }

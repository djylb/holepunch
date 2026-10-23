// Package wiretype is the frame type table of the control protocol: the
// major version every frame header carries, and each type's number, wire
// name, payload cap, direction and write priority. It is the only
// definition of the numbering; package protocol names the types as
// messages, package controlwire frames and queues them. It depends on the
// standard library only.
package wiretype

import "strconv"

// Version is the protocol major version carried in every frame header.
const Version = 1

// DiscardCap is the payload cap of a reserved type (13–255), whose frames
// are read and dropped.
const DiscardCap = 4 << 10

// Type is the frame type byte. Types 1–12 are the control messages of
// protocol version 1 (numbered contiguously); 0 is invalid and 13–255 are
// reserved.
type Type uint8

// Frame types of protocol version 1.
const (
	PunchStart   Type = 1  // S→C
	ProbeReport  Type = 2  // C→S
	ProbeSummary Type = 3  // S→C
	PunchReady   Type = 4  // C→S
	PunchGo      Type = 5  // S→C
	Progress     Type = 6  // C→S, telemetry only
	Assist       Type = 7  // both directions
	Abort        Type = 8  // S→C
	Ping         Type = 9  // S→C
	Pong         Type = 10 // C→S
	RoundResult  Type = 11 // C→S
	PunchResult  Type = 12 // C→S
)

// Direction says which side may send a type.
type Direction uint8

// Directions.
const (
	ServerToClient Direction = iota + 1
	ClientToServer
	BothWays
)

// Priority orders the write queues: P0 is written first.
type Priority uint8

// Write priorities.
const (
	P0            Priority = iota // pong
	P1                            // reliable protocol frames
	P2                            // punch_assist
	P3                            // punch_progress
	NumPriorities                 // the number of priorities
)

// Info is one row of the type table.
type Info struct {
	Name string // the wire name
	Cap  int    // the payload cap
	Dir  Direction
	Prio Priority
}

// Info is t's row of the table; false for type 0 and the reserved types.
func (t Type) Info() (Info, bool) {
	switch t {
	case PunchStart:
		return Info{"punch_start", 16 << 10, ServerToClient, P1}, true
	case ProbeReport:
		return Info{"probe_report", 32 << 10, ClientToServer, P1}, true
	case ProbeSummary:
		return Info{"probe_summary", 48 << 10, ServerToClient, P1}, true
	case PunchReady:
		return Info{"punch_ready", 1 << 10, ClientToServer, P1}, true
	case PunchGo:
		return Info{"punch_go", 8 << 10, ServerToClient, P1}, true
	case Progress:
		return Info{"punch_progress", 2 << 10, ClientToServer, P3}, true
	case Assist:
		return Info{"punch_assist", 1 << 10, BothWays, P2}, true
	case Abort:
		return Info{"punch_abort", 1 << 10, ServerToClient, P1}, true
	case Ping:
		// P1, not P0: ping#1 is flushed together with punch_start, which must
		// stay the first frame of the link; RTT samples use the time the write
		// returned, so queue position does not bias them.
		return Info{"ping", 256, ServerToClient, P1}, true
	case Pong:
		return Info{"pong", 256, ClientToServer, P0}, true
	case RoundResult:
		return Info{"round_result", 4 << 10, ClientToServer, P1}, true
	case PunchResult:
		return Info{"punch_result", 8 << 10, ClientToServer, P1}, true
	}
	return Info{}, false
}

// Known reports whether t is one of the twelve version-1 types.
func (t Type) Known() bool {
	_, ok := t.Info()
	return ok
}

// Cap is the payload limit of t; reserved types use DiscardCap.
func (t Type) Cap() int {
	if inf, ok := t.Info(); ok {
		return inf.Cap
	}
	return DiscardCap
}

// String returns the wire name of t ("punch_go"), or "type(N)" when reserved.
func (t Type) String() string {
	if inf, ok := t.Info(); ok {
		return inf.Name
	}
	return "type(" + strconv.Itoa(int(t)) + ")"
}

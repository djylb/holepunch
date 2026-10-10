package controlwire

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"time"
)

// Frame header layout: 'h' 'p' | major | type | length (uint32, big endian).
const (
	// Version is the protocol major version carried in every frame header.
	// It must match exactly; any other value is ErrVersion.
	Version = 1
	// HeaderSize is the length of the frame header.
	HeaderSize = 8
	// MaxPayload is the global payload limit. Every type has a smaller Cap.
	MaxPayload = 64 << 10
	// DiscardCap is the limit for frames that are read and dropped: reserved
	// types (13–255) and types sent in the wrong direction.
	DiscardCap = 4 << 10
	// MaxDiscarded is the number of discarded frames a link tolerates; one
	// more is ErrTooManyUnknown (protocol_violation).
	MaxDiscarded = 16
	// DefaultMaxFrames is the per-link limit on received frames; one more is
	// ErrFlood (protocol_violation, detail control_flood).
	DefaultMaxFrames = 512
	// DefaultWriteTimeout is the per-frame write deadline of a client link.
	// Servers use 3 s (ConnOptions.WriteTimeout).
	DefaultWriteTimeout = 2 * time.Second
)

const (
	magic0 = 'h'
	magic1 = 'p'
)

// Type is the frame type byte. Types 1–12 are the control messages of
// protocol version 1 (numbered contiguously); 0 is invalid and 13–255 are
// reserved. The table below is the only definition of the numbering, the
// per-type payload caps, directions and write priorities; package protocol
// builds on it.
type Type uint8

// Frame types of protocol version 1.
const (
	TypePunchStart   Type = 1  // S→C
	TypeProbeReport  Type = 2  // C→S
	TypeProbeSummary Type = 3  // S→C
	TypePunchReady   Type = 4  // C→S
	TypePunchGo      Type = 5  // S→C
	TypeProgress     Type = 6  // C→S
	TypeAssist       Type = 7  // both directions
	TypeAbort        Type = 8  // S→C
	TypePing         Type = 9  // S→C
	TypePong         Type = 10 // C→S
	TypeRoundResult  Type = 11 // C→S
	TypePunchResult  Type = 12 // C→S
)

// direction says which side may send a type.
type direction uint8

const (
	serverToClient direction = iota + 1
	clientToServer
	bothWays
)

// priority orders the write queues: P0 is written first.
type priority uint8

const (
	prioP0 priority = iota // pong
	prioP1                 // reliable protocol frames
	prioP2                 // punch_assist
	prioP3                 // punch_progress
	numPriorities
)

// queueCap is the bound of each write queue. P0–P2 refuse a new frame when
// full (ErrQueueFull); P3 evicts its oldest frame instead.
func (p priority) queueCap() int {
	switch p {
	case prioP0:
		return 8
	case prioP1:
		return 16
	case prioP2:
		return 32
	default:
		return 64
	}
}

type typeInfo struct {
	name string
	cap  int
	dir  direction
	prio priority
}

// info is the frame type table.
func (t Type) info() (typeInfo, bool) {
	switch t {
	case TypePunchStart:
		return typeInfo{"punch_start", 16 << 10, serverToClient, prioP1}, true
	case TypeProbeReport:
		return typeInfo{"probe_report", 32 << 10, clientToServer, prioP1}, true
	case TypeProbeSummary:
		return typeInfo{"probe_summary", 48 << 10, serverToClient, prioP1}, true
	case TypePunchReady:
		return typeInfo{"punch_ready", 1 << 10, clientToServer, prioP1}, true
	case TypePunchGo:
		return typeInfo{"punch_go", 8 << 10, serverToClient, prioP1}, true
	case TypeProgress:
		return typeInfo{"punch_progress", 2 << 10, clientToServer, prioP3}, true
	case TypeAssist:
		return typeInfo{"punch_assist", 1 << 10, bothWays, prioP2}, true
	case TypeAbort:
		return typeInfo{"punch_abort", 1 << 10, serverToClient, prioP1}, true
	case TypePing:
		// P1, not P0: ping#1 is flushed together with punch_start, which must
		// stay the first frame of the link; RTT samples use the time the write
		// returned, so queue position does not bias them.
		return typeInfo{"ping", 256, serverToClient, prioP1}, true
	case TypePong:
		return typeInfo{"pong", 256, clientToServer, prioP0}, true
	case TypeRoundResult:
		return typeInfo{"round_result", 4 << 10, clientToServer, prioP1}, true
	case TypePunchResult:
		return typeInfo{"punch_result", 8 << 10, clientToServer, prioP1}, true
	}
	return typeInfo{}, false
}

// Known reports whether t is one of the twelve version-1 types.
func (t Type) Known() bool {
	_, ok := t.info()
	return ok
}

// Cap is the payload limit of t; reserved types use DiscardCap.
func (t Type) Cap() int {
	if inf, ok := t.info(); ok {
		return inf.cap
	}
	return DiscardCap
}

// String returns the wire name of t ("punch_go"), or "type(N)" when reserved.
func (t Type) String() string {
	if inf, ok := t.info(); ok {
		return inf.name
	}
	return "type(" + strconv.Itoa(int(t)) + ")"
}

// Side is the end of a link a Conn sits on.
type Side uint8

// Link sides.
const (
	SideClient Side = iota
	SideServer
)

// String returns "client" or "server".
func (s Side) String() string {
	if s == SideServer {
		return "server"
	}
	return "client"
}

// Sends reports whether side s may send frames of type t.
func (s Side) Sends(t Type) bool {
	inf, ok := t.info()
	if !ok {
		return false
	}
	switch inf.dir {
	case bothWays:
		return true
	case serverToClient:
		return s == SideServer
	default:
		return s == SideClient
	}
}

// Receives reports whether side s accepts frames of type t. Frames it does
// not accept are read (up to DiscardCap), dropped and counted.
func (s Side) Receives(t Type) bool {
	peer := SideServer
	if s == SideServer {
		peer = SideClient
	}
	return peer.Sends(t)
}

// Frame is one control frame.
type Frame struct {
	Type    Type
	Payload []byte
	// At is the monotonic time at which the reading goroutine finished
	// reading the frame. It is zero for frames built locally. Start delays
	// (punch_go) and pong hold times are measured from it.
	At time.Time
}

// AppendFrame appends the encoded frame (header and payload) to dst; f.At is
// not encoded. It fails for type 0 and for payloads longer than the type's Cap.
func AppendFrame(dst []byte, f Frame) ([]byte, error) {
	if f.Type == 0 {
		return dst, ErrZeroType
	}
	if len(f.Payload) > f.Type.Cap() {
		return dst, fmt.Errorf("%w: %v payload %d > %d", ErrFrameTooLarge, f.Type, len(f.Payload), f.Type.Cap())
	}
	dst = append(dst, magic0, magic1, Version, byte(f.Type), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(dst[len(dst)-4:], uint32(len(f.Payload)))
	return append(dst, f.Payload...), nil
}

// ParseHeader validates a frame header before anything else is read: magic
// (ErrBadMagic), major version (ErrVersion), type 0 (ErrZeroType) and length
// against capFor(type) and MaxPayload (ErrFrameTooLarge). capFor nil means
// Type.Cap. A caller that checks the header with ParseHeader never allocates
// or reads a payload that is too large.
func ParseHeader(h [HeaderSize]byte, capFor func(Type) int) (Type, int, error) {
	if h[0] != magic0 || h[1] != magic1 {
		return 0, 0, ErrBadMagic
	}
	if h[2] != Version {
		return 0, 0, fmt.Errorf("%w: major %d", ErrVersion, h[2])
	}
	t := Type(h[3])
	if t == 0 {
		return 0, 0, ErrZeroType
	}
	n := binary.BigEndian.Uint32(h[4:])
	limit := MaxPayload
	if capFor != nil {
		limit = min(limit, capFor(t))
	} else {
		limit = min(limit, t.Cap())
	}
	if n > uint32(limit) {
		return t, 0, fmt.Errorf("%w: %v length %d > %d", ErrFrameTooLarge, t, n, limit)
	}
	return t, int(n), nil
}

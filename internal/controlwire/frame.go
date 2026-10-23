package controlwire

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/djylb/holepunch/internal/wiretype"
)

// Frame header layout: 'h' 'p' | major | type | length (uint32, big endian).
const (
	// HeaderSize is the length of the frame header.
	HeaderSize = 8
	// MaxPayload is the global payload limit. Every type has a smaller Cap.
	MaxPayload = 64 << 10
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

// Type is the frame type byte: the table of package wiretype, the only
// definition of the numbering, the per-type payload caps, directions and
// write priorities. Types 1–12 are the control messages of protocol version
// 1; 0 is invalid and 13–255 are reserved.
type Type = wiretype.Type

// queueCap is the bound of the write queue of priority p. P0–P2 refuse a
// new frame when full (ErrQueueFull); P3 evicts its oldest frame instead.
func queueCap(p wiretype.Priority) int {
	switch p {
	case wiretype.P0:
		return 8
	case wiretype.P1:
		return 16
	case wiretype.P2:
		return 32
	default:
		return 64
	}
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
	inf, ok := t.Info()
	if !ok {
		return false
	}
	switch inf.Dir {
	case wiretype.BothWays:
		return true
	case wiretype.ServerToClient:
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
	dst = append(dst, magic0, magic1, wiretype.Version, byte(f.Type), 0, 0, 0, 0)
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
	if h[2] != wiretype.Version {
		return 0, 0, fmt.Errorf("%w: major %d", ErrVersion, h[2])
	}
	t := Type(h[3])
	if t == 0 {
		return 0, 0, ErrZeroType
	}
	n := binary.BigEndian.Uint32(h[4:])
	limit := t.Cap()
	if capFor != nil {
		// A negative cap admits only an empty payload; converted as it is,
		// it would wrap around to a limit of nearly 4 GiB.
		limit = max(capFor(t), 0)
	}
	limit = min(limit, MaxPayload)
	if n > uint32(limit) {
		return t, 0, fmt.Errorf("%w: %v length %d > %d", ErrFrameTooLarge, t, n, limit)
	}
	return t, int(n), nil
}

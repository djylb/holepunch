package proto

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/djylb/holepunch/internal/life"
)

const (
	// Version is the protocol version carried in every frame header.
	Version = 1
	// HeaderSize is the size of a frame header: version, type and the
	// big-endian uint16 payload length.
	HeaderSize = 4
	// MaxPayload bounds the JSON payload of one frame.
	MaxPayload = 16 << 10
)

// Type is a message type. The values are consecutive from 1; every other
// value is unknown.
type Type uint8

// Message types.
const (
	TypeRegister    Type = iota + 1 // client → server: a host registration link
	TypeRegistered                  // server → client: the registration is accepted
	TypeOpen                        // client → server: a dialer asks for a session with a host
	TypeJoin                        // client → server: the host takes up a session it was told about
	TypeSessionInfo                 // server → client: the session; punch_start follows on the stream
	TypeIncoming                    // server → host, on the registration link: a dialer opened a session
	TypeHeartbeat                   // both ways on the registration link
	TypeTransport                   // host → server, on the registration link: an upper-layer transport outcome
	TypeFail                        // server → client: the request is refused and the stream closed
)

// String returns the message name.
func (t Type) String() string {
	switch t {
	case TypeRegister:
		return "register"
	case TypeRegistered:
		return "registered"
	case TypeOpen:
		return "open"
	case TypeJoin:
		return "join"
	case TypeSessionInfo:
		return "session_info"
	case TypeIncoming:
		return "incoming"
	case TypeHeartbeat:
		return "heartbeat"
	case TypeTransport:
		return "transport"
	case TypeFail:
		return "fail"
	}
	return fmt.Sprintf("type_%d", uint8(t))
}

// Message is one signalling message. The concrete types are the pointer
// types of this package's message structs.
type Message interface {
	// Type returns the message type.
	Type() Type
	validate() error
}

// Framing errors. A decoding error that concerns one field wraps
// ErrInvalid.
var (
	ErrVersion    = errors.New("proto: unsupported protocol version")
	ErrType       = errors.New("proto: unknown message type")
	ErrTooLarge   = errors.New("proto: frame payload too large")
	ErrInvalid    = errors.New("proto: invalid message")
	ErrUnexpected = errors.New("proto: unexpected message")
)

// newMessage returns an empty message of type t.
func newMessage(t Type) Message {
	switch t {
	case TypeRegister:
		return &Register{}
	case TypeRegistered:
		return &Registered{}
	case TypeOpen:
		return &Open{}
	case TypeJoin:
		return &Join{}
	case TypeSessionInfo:
		return &SessionInfo{}
	case TypeIncoming:
		return &Incoming{}
	case TypeHeartbeat:
		return &Heartbeat{}
	case TypeTransport:
		return &Transport{}
	case TypeFail:
		return &Fail{}
	}
	return nil
}

// Encode validates m and returns its frame.
func Encode(m Message) ([]byte, error) {
	if life.IsNil(m) {
		return nil, fmt.Errorf("%w: nil message", ErrInvalid)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("proto: encode %v: %w", m.Type(), err)
	}
	if len(payload) > MaxPayload {
		return nil, fmt.Errorf("%w: %v of %d bytes", ErrTooLarge, m.Type(), len(payload))
	}
	frame := make([]byte, HeaderSize, HeaderSize+len(payload))
	frame[0] = Version
	frame[1] = byte(m.Type())
	binary.BigEndian.PutUint16(frame[2:], uint16(len(payload)))
	return append(frame, payload...), nil
}

// Decode reads exactly one frame from r — never a byte more — and returns its
// validated message.
func Decode(r io.Reader) (Message, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != Version {
		return nil, fmt.Errorf("%w: %d", ErrVersion, hdr[0])
	}
	t := Type(hdr[1])
	m := newMessage(t)
	if m == nil {
		return nil, fmt.Errorf("%w: %d", ErrType, hdr[1])
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	if n > MaxPayload {
		return nil, fmt.Errorf("%w: %v of %d bytes", ErrTooLarge, t, n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, unexpectedEOF(err)
	}
	if err := json.Unmarshal(payload, m); err != nil {
		return nil, fmt.Errorf("%w: %v: %v", ErrInvalid, t, err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// unexpectedEOF reports a stream that ends inside a frame as such.
func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// Write writes m on conn within timeout: the write deadline is set for the
// frame and cleared afterwards. A non-positive timeout writes without a
// deadline.
func Write(conn net.Conn, m Message, timeout time.Duration) error {
	frame, err := Encode(m)
	if err != nil {
		return err
	}
	if timeout > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
	}
	_, werr := conn.Write(frame)
	if timeout > 0 {
		if err := conn.SetWriteDeadline(time.Time{}); err != nil && werr == nil {
			werr = err
		}
	}
	return werr
}

// Read reads one message from conn. The end of ctx interrupts a blocked read
// (life.InterruptRead), in which case Read returns ctx's cause. The read
// deadline is cleared again before Read returns; a connection on which that
// fails is closed already (the peer's last frame, a Fail typically, is still
// returned), and the next call on it reports so.
func Read(ctx context.Context, conn net.Conn) (Message, error) {
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	restore := life.InterruptRead(ctx, conn)
	m, err := Decode(conn)
	_ = restore()
	if err != nil {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		return nil, err
	}
	return m, nil
}

// Expect reads one message from conn (see Read) and returns it as T. A Fail
// is returned as the error; any other message wraps ErrUnexpected.
func Expect[T Message](ctx context.Context, conn net.Conn) (T, error) {
	var zero T
	m, err := Read(ctx, conn)
	if err != nil {
		return zero, err
	}
	switch v := m.(type) {
	case T:
		return v, nil
	case *Fail:
		return zero, v
	}
	return zero, fmt.Errorf("%w: %v", ErrUnexpected, m.Type())
}

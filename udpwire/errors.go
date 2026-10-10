package udpwire

import "strconv"

// DecodeError classifies why a received packet was dropped. Its
// String is the key of the drop counters (punch_result.stats.drops and
// natprobe's statistics). Failed packets are never answered, so the
// classification is for statistics and diagnosis only.
type DecodeError uint8

// Decode outcomes, in pipeline order.
const (
	// OK means the stage accepted the packet.
	OK DecodeError = iota
	// ErrShort means the packet is shorter than the envelope minimum.
	ErrShort
	// ErrForeign means the first byte is outside [B0Min, B0Max] or the packet
	// is longer than the envelope maximum — not holepunch (QUIC, KCP, ...).
	// From the winning remote during handover it signals that the peer's
	// upper layer started.
	ErrForeign
	// ErrRoute means, for natprobe only, an unknown route or a masked route
	// that does not match the codec. Such packets are never decrypted or
	// answered.
	ErrRoute
	// ErrRate means the caller's pre-AEAD token bucket dropped the packet.
	ErrRate
	// ErrAuth means the AEAD failed — wrong key, another or an old session,
	// another major version, tampering, or a foreign packet whose first byte
	// happens to fall in range.
	ErrAuth
	// ErrPayload means the packet is authentic but malformed — unknown type,
	// reserved bit, a sender role or flag the type does not allow, a TLV
	// overrun or invalid value, or a type that does not belong to the
	// envelope.
	ErrPayload
	// ErrRole means the sender role is wrong for this receiver
	// (self-reflection, loopback, hairpin echo).
	ErrRole
	// ErrReplay means the SeqWindow rejected the packet.
	ErrReplay
)

// String returns the drop-counter key.
func (e DecodeError) String() string {
	switch e {
	case OK:
		return "ok"
	case ErrShort:
		return "short"
	case ErrForeign:
		return "foreign"
	case ErrRoute:
		return "route"
	case ErrRate:
		return "rate"
	case ErrAuth:
		return "auth"
	case ErrPayload:
		return "payload"
	case ErrRole:
		return "role"
	case ErrReplay:
		return "replay"
	}
	return "DecodeError(" + strconv.Itoa(int(e)) + ")"
}

// codecError is the error type of NewCodec and Seal. It is a string constant
// type so the package needs no mutable error variables.
type codecError string

func (e codecError) Error() string { return string(e) }

const (
	errBadRole      codecError = "udpwire: role must be initiator, responder or server"
	errNoPad        codecError = "udpwire: client codec needs the session PadPolicy"
	errNilHeader    codecError = "udpwire: nil header"
	errBadType      codecError = "udpwire: unknown packet type"
	errRoleMismatch codecError = "udpwire: header role differs from the codec role"
	errNotSender    codecError = "udpwire: this role cannot send this packet type"
	errBadFlags     codecError = "udpwire: flags not permitted for this packet type"
	errZeroSeq      codecError = "udpwire: seq must be non-zero"
	errBadTLVs      codecError = "udpwire: TLVs missing, invalid or not carried by this packet type"
	errBadLength    codecError = "udpwire: plaintext length below content or above MaxPlaintext"
	errNoLength     codecError = "udpwire: reply packets need an explicit plaintext length"
)

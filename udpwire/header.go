package udpwire

import "encoding/binary"

// Header is the fixed 24-byte plaintext header, all integers big
// endian. It has no version field: the major version is bound into the key.
type Header struct {
	// Type is the packet type.
	Type Type
	// Role is the sender's role. Seal requires it to equal the codec's role.
	Role Role
	// LowTTL marks a packet sent with a reduced TTL (diagnostic).
	LowTTL bool
	// Retx marks a retransmission of the same logical request (diagnostic).
	Retx bool
	// FA is WANT_EXTRA on probe and EXTRA_SENT on probe_ack; zero elsewhere.
	FA bool
	// FB is WANT_ALT on probe and ALT_SENT on probe_ack; zero elsewhere.
	FB bool
	// FC is QUOTA_EXHAUSTED on probe_ack; zero elsewhere.
	FC bool
	// Round is the sender's current round (0 during probing).
	Round uint8
	// Sock is the sending socket id, family<<7 | index; replies echo it.
	Sock uint8
	// Cand is the candidate id (stage<<12 | index) or NoCand.
	Cand uint16
	// Aux is the observer id (low byte) on probe traffic and the nomination
	// epoch on nominate/accept/ready/handover_ack; zero elsewhere.
	Aux uint16
	// Seq is the sender's per-session counter, starting at 1; it doubles as
	// the transaction id and feeds the receiver's SeqWindow. Never zero.
	Seq uint32
	// TS is the sender's clock in milliseconds (Codec.Now).
	TS uint32
	// EchoSeq is the Seq of the packet being answered, else zero.
	EchoSeq uint32
	// EchoTS is the TS of the packet being answered, else zero.
	EchoTS uint32
}

// flags packs the role and flag bits. The caller has validated Role.
func (h *Header) flags() byte {
	f := byte(h.Role) & flagRole
	if h.LowTTL {
		f |= flagLowTTL
	}
	if h.Retx {
		f |= flagRetx
	}
	if h.FA {
		f |= flagFA
	}
	if h.FB {
		f |= flagFB
	}
	if h.FC {
		f |= flagFC
	}
	return f
}

// put writes the header into b[:HeaderSize].
func (h *Header) put(b []byte) {
	_ = b[HeaderSize-1]
	b[0] = byte(h.Type)
	b[1] = h.flags()
	b[2] = h.Round
	b[3] = h.Sock
	binary.BigEndian.PutUint16(b[4:], h.Cand)
	binary.BigEndian.PutUint16(b[6:], h.Aux)
	binary.BigEndian.PutUint32(b[8:], h.Seq)
	binary.BigEndian.PutUint32(b[12:], h.TS)
	binary.BigEndian.PutUint32(b[16:], h.EchoSeq)
	binary.BigEndian.PutUint32(b[20:], h.EchoTS)
}

// parseHeader decodes b[:HeaderSize] into h and returns the type's rule. It
// fails on an unknown type and on flags the type does not admit (reserved
// bit, sender role, FA/FB/FC); h is unspecified on failure.
func parseHeader(b []byte, h *Header) (rule, bool) {
	_ = b[HeaderSize-1]
	r, ok := ruleOf(Type(b[0]))
	f := b[1]
	if !ok || !r.admits(f) {
		return rule{}, false
	}
	*h = Header{
		Type:    Type(b[0]),
		Role:    Role(f & flagRole),
		LowTTL:  f&flagLowTTL != 0,
		Retx:    f&flagRetx != 0,
		FA:      f&flagFA != 0,
		FB:      f&flagFB != 0,
		FC:      f&flagFC != 0,
		Round:   b[2],
		Sock:    b[3],
		Cand:    binary.BigEndian.Uint16(b[4:]),
		Aux:     binary.BigEndian.Uint16(b[6:]),
		Seq:     binary.BigEndian.Uint32(b[8:]),
		TS:      binary.BigEndian.Uint32(b[12:]),
		EchoSeq: binary.BigEndian.Uint32(b[16:]),
		EchoTS:  binary.BigEndian.Uint32(b[20:]),
	}
	return r, true
}

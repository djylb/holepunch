package probe

import (
	"encoding/binary"

	"github.com/djylb/holepunch/stun"
)

// STUN Binding (RFC 8489) is the optional sub-probe, through package stun:
// a Binding Request, and a Success with (XOR-)MAPPED-ADDRESS. No
// OTHER-ADDRESS, no CHANGE-REQUEST.

// IsSTUN is the read pump's demultiplexer of a socket shared with holepunch
// packets (RFC 7983): it reports whether pkt belongs to the STUN path, by
// its first bytes alone — first byte 0–3 and the magic cookie at offset 4.
// holepunch packets start with a byte in [0x04, 0x0F], so the two never
// overlap, and stun parses the rest. It deliberately differs from
// stun.IsMessage, which validates a whole message: it reads no length field,
// so a malformed datagram in the STUN range still goes to the STUN parser,
// which drops it, rather than to the holepunch decoder; and it takes only
// the first bytes 0–3 that RFC 7983 gives STUN, where IsMessage accepts any
// with the two top bits clear.
func IsSTUN(pkt []byte) bool {
	return len(pkt) >= stun.HeaderSize && pkt[0] < 4 && binary.BigEndian.Uint32(pkt[4:8]) == stun.MagicCookie
}

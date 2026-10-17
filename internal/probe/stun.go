package probe

import (
	"encoding/binary"

	"github.com/djylb/holepunch/stun"
)

// STUN Binding (RFC 8489) is the optional sub-probe, through package stun:
// a Binding Request, and a Success with (XOR-)MAPPED-ADDRESS. No
// OTHER-ADDRESS, no CHANGE-REQUEST.

// IsSTUN reports whether pkt is in the STUN range of a socket shared with
// holepunch packets (RFC 7983): first byte 0–3 and the magic cookie at
// offset 4. holepunch packets start with a byte in [0x04, 0x0F], so a read
// pump tells the two apart from the first bytes alone; stun parses the rest.
func IsSTUN(pkt []byte) bool {
	return len(pkt) >= stun.HeaderSize && pkt[0] < 4 && binary.BigEndian.Uint32(pkt[4:8]) == stun.MagicCookie
}

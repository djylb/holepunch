package udpwire

import (
	"encoding/binary"
	"hash/crc32"
	"slices"
)

// The flow opener. Some
// networks drop a UDP flow's datagrams after the fifth unless one of the
// first five is a STUN message, which is what WebRTC and game traffic sends
// first. So the first datagram a socket sends to each remote endpoint is a
// standard STUN Binding Request that carries the sealed packet:
//
//	 0        2        4              8                     20
//	+--------+--------+--------------+---------------------+
//	| 0x0001 |  len   |  0x2112A442  | transaction id |  header
//	+--------+--------+--------------+---------------------+
//	| 0x0026 |   n    | sealed packet (n bytes) | 0 × p    |  PADDING
//	+--------+--------+-------------------------+----------+
//	| 0x8028 |   4    | CRC-32 ⊕ 0x5354554E     |             FINGERPRINT
//	+--------+--------+-------------------------+
//
// len counts every attribute (n + p + 12), p ∈ [0, 3] pads n to a multiple
// of four with zeros, as RFC 8489, section 14 requires, and the CRC-32 covers the
// message up to FINGERPRINT. The transaction id
// is fresh CSPRNG output per opener. Every fixed byte — the message type,
// the cookie, the two attribute types and the FINGERPRINT length — is fixed
// by the STUN standard and found in every STUN message of its kind on the
// Internet, so none of them is a mark of this library:
//
//   - PADDING (RFC 5780, section 7.6) is the one standard attribute defined to
//     carry free-form bytes in a Binding Request, so the sealed packet travels
//     as a legitimate attribute value instead of an invented type; its length
//     is the sealed packet's, which is already drawn per packet.
//   - FINGERPRINT (RFC 8489, section 14.7) ends every ICE connectivity check
//     (RFC 8445, section 7.2.2), so WebRTC Binding Requests carry it as their last
//     attribute; a classifier that tells STUN from other traffic on a shared
//     port by it finds a valid one.
//
// The receiver tells the two forms apart by the first byte (RFC 7983): 0–3
// is STUN, a sealed holepunch packet starts in [B0Min, B0Max].

// STUN constants of the opener (RFC 8489, section 5; RFC 5780, section 7.6).
const (
	stunHeaderSize     = 20
	stunMagic          = 0x2112A442
	stunBindingRequest = 0x0001
	attrHeaderSize     = 4
	attrPadding        = 0x0026
	attrFingerprint    = 0x8028
	fingerprintSize    = 4
	fingerprintXOR     = 0x5354554E
	stunMaxFirstByte   = 3 // RFC 7983: a first byte in [0, 3] is STUN
)

// Opener sizes.
const (
	// wrapOverhead is what the opener adds to a sealed packet besides its
	// zero to three alignment bytes: the STUN header, the PADDING attribute
	// header and the FINGERPRINT attribute (32 bytes).
	wrapOverhead = stunHeaderSize + attrHeaderSize + attrHeaderSize + fingerprintSize
	// maxWrapOverhead is the most an opener adds (35 bytes): wrapOverhead and
	// three alignment bytes.
	maxWrapOverhead = wrapOverhead + 3
	// MaxWrapped is the longest opener (1104 bytes): the longest envelope P
	// packet wrapped. It stays below the IPv6 minimum MTU minus headers.
	MaxWrapped = maxProbePacket + maxWrapOverhead

	minWrapped = MinPeerPacket + wrapOverhead
)

// Wrapped reports whether pkt is in the STUN range of RFC 7983 — first byte
// 0 to 3 — and so may be an opener, which Unwrap decides. A sealed packet
// never is.
func Wrapped(pkt []byte) bool { return len(pkt) > 0 && pkt[0] <= stunMaxFirstByte }

// Wrap appends the opener form of the sealed packet pkt to dst and returns
// the extended slice; it allocates only when dst lacks capacity. The
// transaction id comes from the codec's CSPRNG. pkt must be a packet Seal
// produced (so at most 1069 bytes); dst must not overlap it.
func (c *Codec) Wrap(dst, pkt []byte) []byte {
	n := len(pkt)
	pad := (4 - n%4) % 4
	size := wrapOverhead + n + pad
	dst = slices.Grow(dst, size)
	out := dst[len(dst) : len(dst)+size]
	binary.BigEndian.PutUint16(out[0:], stunBindingRequest)
	binary.BigEndian.PutUint16(out[2:], uint16(size-stunHeaderSize))
	binary.BigEndian.PutUint32(out[4:], stunMagic)
	c.mu.Lock()
	_, _ = c.nonces.Read(out[8:stunHeaderSize]) // ChaCha8.Read always fills p and returns nil
	c.mu.Unlock()
	binary.BigEndian.PutUint16(out[stunHeaderSize:], attrPadding)
	binary.BigEndian.PutUint16(out[stunHeaderSize+2:], uint16(n))
	copy(out[stunHeaderSize+attrHeaderSize:], pkt)
	tail := out[stunHeaderSize+attrHeaderSize+n:]
	clear(tail[:pad])
	fp := tail[pad:]
	binary.BigEndian.PutUint16(fp[0:], attrFingerprint)
	binary.BigEndian.PutUint16(fp[2:], fingerprintSize)
	binary.BigEndian.PutUint32(fp[4:], crc32.ChecksumIEEE(out[:size-attrHeaderSize-fingerprintSize])^fingerprintXOR)
	return dst[:len(dst)+size]
}

// Unwrap returns the sealed packet inside an opener, a subslice of pkt. The
// opener must be exactly the form Wrap produces — a Binding Request with the
// magic cookie, a length that covers the datagram, PADDING then a valid
// FINGERPRINT and nothing else — and the packet inside must start with a
// sealed packet's first byte: ErrShort below the shortest opener, ErrForeign
// otherwise, in particular for any other STUN message. It costs one CRC-32
// and does not allocate; the result is unauthenticated until Open or
// OpenProbe succeeds.
func Unwrap(pkt []byte) ([]byte, DecodeError) {
	switch {
	case len(pkt) == 0 || !Wrapped(pkt):
		return nil, ErrForeign
	case len(pkt) < minWrapped:
		return nil, ErrShort
	case len(pkt) > MaxWrapped:
		return nil, ErrForeign
	}
	size := len(pkt)
	n := int(binary.BigEndian.Uint16(pkt[stunHeaderSize+2:]))
	pad := (4 - n%4) % 4
	fp := pkt[size-attrHeaderSize-fingerprintSize:]
	inner := pkt[stunHeaderSize+attrHeaderSize : min(stunHeaderSize+attrHeaderSize+n, size)]
	switch {
	case binary.BigEndian.Uint16(pkt[0:]) != stunBindingRequest,
		int(binary.BigEndian.Uint16(pkt[2:])) != size-stunHeaderSize,
		binary.BigEndian.Uint32(pkt[4:]) != stunMagic,
		binary.BigEndian.Uint16(pkt[stunHeaderSize:]) != attrPadding,
		wrapOverhead+n+pad != size,
		binary.BigEndian.Uint16(fp[0:]) != attrFingerprint,
		binary.BigEndian.Uint16(fp[2:]) != fingerprintSize,
		binary.BigEndian.Uint32(fp[4:]) != crc32.ChecksumIEEE(pkt[:size-attrHeaderSize-fingerprintSize])^fingerprintXOR,
		inner[0] < B0Min || inner[0] > B0Max:
		return nil, ErrForeign
	}
	return inner, OK
}

package udpwire

import (
	"crypto/subtle"
	"unsafe"
)

// Precheck runs the checks that precede any cryptography:
// ErrShort below minLen, ErrForeign above the envelope maximum or with a first
// byte outside [B0Min, B0Max]. minLen selects the envelope: MinPeerPacket for
// envelope S (at most 1053 bytes) and MinProbePacket for envelope P (at most
// 1069 bytes); any value of at least MinProbePacket uses the envelope P
// maximum and any smaller one the envelope S maximum. An empty packet is
// ErrShort whatever minLen is.
func Precheck(pkt []byte, minLen int) DecodeError {
	maxLen := maxPeerPacket
	if minLen >= MinProbePacket {
		maxLen = maxProbePacket
	}
	switch {
	case len(pkt) == 0 || len(pkt) < minLen:
		return ErrShort
	case len(pkt) > maxLen || pkt[0] < B0Min || pkt[0] > B0Max:
		return ErrForeign
	}
	return OK
}

// UnmaskRoute recovers the route of an envelope P packet so natprobe can find
// the session before decrypting anything. It costs one SHA-256 and returns
// ErrShort or ErrForeign as Precheck(pkt, MinProbePacket) would. The result
// is unauthenticated until OpenProbe succeeds.
func UnmaskRoute(pkt []byte) ([RouteSize]byte, DecodeError) {
	var route [RouteSize]byte
	if e := Precheck(pkt, MinProbePacket); e != OK {
		return route, e
	}
	mask := routeMask(pkt[1:PeerOuterSize])
	subtle.XORBytes(route[:], pkt[PeerOuterSize:ProbeOuterSize], mask[:RouteSize])
	return route, OK
}

// Open authenticates, decrypts and parses an envelope S packet into h and t
// It does not check the sender role (CheckRole)
// or replay (SeqWindow). h and t are zeroed first and hold the packet's
// fields only when the result is OK; either may be nil when the caller only
// needs the classification.
//
// The plaintext goes to scratch when scratch has the capacity for it
// (MaxPlaintext, or len(pkt), always suffices) and does not overlap pkt; pkt
// is then left unchanged. Otherwise Open decrypts in place and overwrites pkt
// — with zeros if authentication fails. Open does not allocate.
func (c *Codec) Open(pkt, scratch []byte, h *Header, t *TLVs) DecodeError {
	return c.open(pkt, scratch, h, t, false)
}

// OpenProbe is Open for envelope P, used by natprobe after UnmaskRoute found
// this codec. The masked route is outside the AAD, so OpenProbe unmasks it
// again and returns ErrRoute unless it equals the codec's route; without that
// check a modified mroute could still be accepted. Buffers are handled as by
// Open.
func (c *Codec) OpenProbe(pkt, scratch []byte, h *Header, t *TLVs) DecodeError {
	return c.open(pkt, scratch, h, t, true)
}

// open implements Open (envelope S) and OpenProbe (envelope P).
func (c *Codec) open(pkt, scratch []byte, h *Header, t *TLVs, probe bool) DecodeError {
	var hb Header
	var tb TLVs
	if h == nil {
		h = &hb
	}
	if t == nil {
		t = &tb
	}
	*h, *t = Header{}, TLVs{}
	outer, minLen := PeerOuterSize, MinPeerPacket
	if probe {
		outer, minLen = ProbeOuterSize, MinProbePacket
	}
	if e := Precheck(pkt, minLen); e != OK {
		return e
	}
	if probe && !c.ownsRoute(pkt) {
		return ErrRoute
	}
	plain, ok := c.decrypt(pkt, outer, scratch)
	if !ok {
		return ErrAuth
	}
	return parse(plain, probe, h, t)
}

// ownsRoute reports whether the masked route of an envelope P packet unmasks
// to this codec's route.
func (c *Codec) ownsRoute(pkt []byte) bool {
	mask := routeMask(pkt[1:PeerOuterSize])
	var diff byte
	for i, m := range pkt[PeerOuterSize:ProbeOuterSize] {
		diff |= m ^ mask[i] ^ c.route[i]
	}
	return diff == 0
}

// decrypt opens pkt[outer:] (ciphertext and tag) with the nonce at pkt[1:13]
// and AAD b0 ‖ route. pkt has passed Precheck for its envelope.
func (c *Codec) decrypt(pkt []byte, outer int, scratch []byte) ([]byte, bool) {
	ct := pkt[outer:]
	n := len(ct) - TagSize
	// GCM panics on a destination that partially overlaps its input, so an
	// overlapping scratch falls back to exact in-place decryption, which is
	// always allowed.
	dst := ct[:0]
	if cap(scratch) >= n && !overlaps(scratch[:n], pkt) {
		dst = scratch[:0]
	}
	plain, err := c.aead.Open(dst, pkt[1:PeerOuterSize], ct, c.aad[pkt[0]-B0Min][:])
	return plain, err == nil
}

// overlaps reports whether a and b share memory. It compares addresses, as
// crypto/internal/alias does, because no safe operation can tell whether two
// slices alias.
func overlaps(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	pa := uintptr(unsafe.Pointer(unsafe.SliceData(a)))
	pb := uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	return pa < pb+uintptr(len(b)) && pb < pa+uintptr(len(a))
}

// parse decodes an authenticated plaintext (at least HeaderSize bytes). Any
// structural fault is ErrPayload, including a probe in envelope S or a
// non-probe in envelope P (only a key holder can produce either).
func parse(plain []byte, probe bool, h *Header, t *TLVs) DecodeError {
	r, ok := parseHeader(plain[:HeaderSize], h)
	if !ok || (h.Type == TProbe) != probe || !parseTLVs(plain[HeaderSize:], r.tlvs, t) {
		*h, *t = Header{}, TLVs{}
		return ErrPayload
	}
	return OK
}

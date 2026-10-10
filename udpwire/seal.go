package udpwire

import (
	"crypto/subtle"
	"slices"
)

// Seal appends the packet described by h and t to dst and returns the
// extended slice; it allocates only when dst lacks capacity. TProbe is sealed
// in envelope P, every other type in envelope S. b0 and, when plainLen is 0,
// the plaintext length come from the codec's pacer stream; the nonce comes
// from its CSPRNG.
//
// h.Role must be the codec's role and a role allowed to send h.Type, the
// flags must be ones the type admits, and h.Seq must be non-zero (clients use
// NextSeq; natprobe counts per session and role). t supplies the TLVs h.Type
// carries and must leave every other field zero; t may be nil for types that
// carry nothing mandatory.
//
// plainLen fixes the plaintext length; it must lie in [content, MaxPlaintext]
// where content is the header plus the encoded TLVs. With plainLen 0, probes
// draw from [96, 144] ([176, 224] when FA or FB is set) and client-to-client
// types from the session PadPolicy, raised to content if shorter; reply types
// (probe_ack, probe_extra, probe_alt) need an explicit length, normally from
// ReplyLengths.
//
// On error dst is returned unchanged.
func (c *Codec) Seal(dst []byte, h *Header, t *TLVs, plainLen int) ([]byte, error) {
	if h == nil {
		return dst, errNilHeader
	}
	if t == nil {
		t = &TLVs{}
	}
	r, err := c.check(h, t)
	if err != nil {
		return dst, err
	}
	content := HeaderSize + t.size(r.tlvs)
	switch {
	case plainLen < 0 || plainLen > MaxPlaintext || (plainLen > 0 && plainLen < content):
		return dst, errBadLength
	case plainLen == 0 && r.length == lengthExplicit:
		return dst, errNoLength
	}

	var nonce [NonceSize]byte
	c.mu.Lock()
	b0 := B0Min + byte(c.pacer.UintN(b0Count))
	n := plainLen
	if n == 0 {
		n = max(c.drawLength(r, h), content)
	}
	_, _ = c.nonces.Read(nonce[:]) // ChaCha8.Read always fills p and returns nil
	c.mu.Unlock()
	return c.sealWith(dst, h, t, r, b0, &nonce, n), nil
}

// check validates h and t against the type's rule and this codec.
func (c *Codec) check(h *Header, t *TLVs) (rule, error) {
	r, ok := ruleOf(h.Type)
	switch {
	case !ok:
		return r, errBadType
	case h.Role != c.role:
		return r, errRoleMismatch
	case !r.senders.has(h.Role):
		return r, errNotSender
	case !r.admits(h.flags()):
		return r, errBadFlags
	case h.Seq == 0:
		return r, errZeroSeq
	case !t.valid(r.tlvs):
		return r, errBadTLVs
	}
	return r, nil
}

// drawLength draws a plaintext length for a type without an explicit one.
// The caller holds c.mu.
func (c *Codec) drawLength(r rule, h *Header) int {
	if r.length == lengthSession {
		return uniform(c.pacer, int(c.pad.Min), int(c.pad.Max))
	}
	if h.FA || h.FB {
		return uniform(c.pacer, probeWantMin, probeWantMax)
	}
	return uniform(c.pacer, probeMin, probeMax)
}

// sealWith encodes and encrypts a validated packet with the given b0, nonce
// and plaintext length n (content ≤ n ≤ MaxPlaintext). The plaintext is built
// in place in the output and encrypted there, so the only copy is the
// caller's buffer.
func (c *Codec) sealWith(dst []byte, h *Header, t *TLVs, r rule, b0 byte, nonce *[NonceSize]byte, n int) []byte {
	outer := PeerOuterSize
	if h.Type == TProbe {
		outer = ProbeOuterSize
	}
	size := outer + n + TagSize
	dst = slices.Grow(dst, size)
	pkt := dst[len(dst) : len(dst)+size]

	pkt[0] = b0
	copy(pkt[1:PeerOuterSize], nonce[:])
	if outer == ProbeOuterSize {
		mask := routeMask(nonce[:])
		subtle.XORBytes(pkt[PeerOuterSize:ProbeOuterSize], c.route[:], mask[:RouteSize])
	}
	plain := pkt[outer : outer+n]
	h.put(plain)
	used := HeaderSize + t.put(plain[HeaderSize:], r.tlvs)
	// Zero padding: its first byte doubles as the PAD terminator, and inside
	// the AEAD it is indistinguishable from content.
	clear(plain[used:])
	c.aead.Seal(plain[:0], pkt[1:PeerOuterSize], plain, c.aad[b0-B0Min][:])
	return dst[:len(dst)+size]
}

package udpwire

import "time"

// First-byte range.
const (
	// B0Min is the smallest value of a packet's first byte. Each packet draws
	// its first byte uniformly from [B0Min, B0Max]; bits 7 and 6 are clear, so
	// QUIC stacks classify the datagram as non-QUIC and drop it, and the range
	// avoids STUN (0–3) and DTLS under RFC 7983 / RFC 9443
	// demultiplexing. The byte carries no version information.
	B0Min = 0x04
	// B0Max is the largest value of a packet's first byte; see B0Min.
	B0Max = 0x0F
)

// Field sizes.
const (
	// RouteSize is the length of a session route id. The route is the HKDF
	// salt and part of the AAD; it appears on the wire only masked, in probes.
	RouteSize = 16
	// NonceSize is the length of the per-packet AES-GCM nonce.
	NonceSize = 12
	// TagSize is the length of the AES-GCM authentication tag.
	TagSize = 16
	// HeaderSize is the length of the fixed plaintext header.
	HeaderSize = 24
)

// Outer (cleartext) prefix sizes.
const (
	// PeerOuterSize is the cleartext prefix of envelope S: b0 and the nonce.
	PeerOuterSize = 1 + NonceSize
	// ProbeOuterSize is the cleartext prefix of envelope P: b0, the nonce and
	// the masked route.
	ProbeOuterSize = PeerOuterSize + RouteSize
)

// Packet and plaintext length limits.
const (
	// MinPeerPacket is the shortest envelope S datagram (53 bytes): a bare
	// header with no TLVs and no padding.
	MinPeerPacket = PeerOuterSize + HeaderSize + TagSize
	// MinProbePacket is the shortest envelope P datagram (69 bytes).
	MinProbePacket = ProbeOuterSize + HeaderSize + TagSize
	// MaxPlaintext is the largest plaintext (header, TLVs and padding). It
	// keeps every datagram (≤ 1069 bytes) below the IPv6 minimum MTU minus
	// headers, so no path fragments it.
	MaxPlaintext = 1024
)

// Minimum reply plaintexts, the content natprobe replies must carry.
const (
	// MinAckPlaintext is the smallest probe_ack plaintext: header, OBSERVED,
	// EXTRA_PORT and COOKIE (54 bytes, 83 on the wire).
	MinAckPlaintext = HeaderSize + tlvHeaderSize + observedSize + tlvHeaderSize + extraPortSize + tlvHeaderSize + cookieSize
	// MinExtraPlaintext is the smallest probe_extra or probe_alt plaintext:
	// header and OBSERVED (44 bytes, 73 on the wire).
	MinExtraPlaintext = HeaderSize + tlvHeaderSize + observedSize
)

// NoCand is the Header.Cand value of packets that name no candidate (probe
// traffic and hairpin).
const NoCand = 0xFFFF

// Candidate id limits: Header.Cand is stage<<12 | index, the stage in the
// top four bits; stage 15 with index maxCandIndex is NoCand.
const (
	maxCandStage = 14
	maxCandIndex = 0x0FFF
)

// CandID is the candidate id of the index-th target of stage stage. An
// index beyond maxCandIndex or a stage beyond maxCandStage has no id of its
// own — it would collide with another target's, or with NoCand — so ok is
// false and the target is not sent.
func CandID(stage, index int) (id uint16, ok bool) {
	if stage < 0 || stage > maxCandStage || index < 0 || index > maxCandIndex {
		return NoCand, false
	}
	return uint16(stage<<12 | index), true
}

// DefaultResidualWindow is the DropResidual window used when the caller passes
// a non-positive one. It comfortably exceeds the handover timeout (2 s) plus
// reordering, the only period in which handshake retransmissions can arrive.
const DefaultResidualWindow = 10 * time.Second

const (
	b0Count = B0Max - B0Min + 1

	maxPeerPacket  = PeerOuterSize + MaxPlaintext + TagSize  // 1053
	maxProbePacket = ProbeOuterSize + MaxPlaintext + TagSize // 1069

	// replyOverhead is the envelope S cost on top of the plaintext.
	replyOverhead = PeerOuterSize + TagSize
	minAckWire    = MinAckPlaintext + replyOverhead   // 83
	minExtraWire  = MinExtraPlaintext + replyOverhead // 73
	minPairWire   = minAckWire + minExtraWire         // 156
)

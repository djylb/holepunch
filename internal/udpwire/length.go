package udpwire

import "math/rand/v2"

// PadPolicy is a session's plaintext length interval for client-to-client
// packets (punch_start.wire.payload_min/payload_max). Each such packet
// draws its plaintext length uniformly from [Min, Max], raised to its content
// length when that is larger, so different sessions have different length
// distributions.
type PadPolicy struct {
	// Min is the smallest plaintext length.
	Min uint16
	// Max is the largest plaintext length.
	Max uint16
}

// Session interval generation and the client-side protocol clamp.
const (
	padMinLow   = 48
	padMinHigh  = 160
	padSpanLow  = 64
	padSpanHigh = 256
)

// Probe plaintext intervals. A probe that wants an extra or alt reply
// is longer, so that both replies fit within its own size.
const (
	probeMin     = 96
	probeMax     = 144
	probeWantMin = 176
	probeWantMax = 224
)

// NewPadPolicy draws a session's interval as the coordinator puts it in
// punch_start.wire: Min uniform in [48, 160] and Max − Min uniform in
// [64, 256]. A nil r uses the math/rand/v2 global source.
func NewPadPolicy(r *rand.Rand) PadPolicy {
	lo := uniform(r, padMinLow, padMinHigh)
	return PadPolicy{Min: uint16(lo), Max: uint16(lo + uniform(r, padSpanLow, padSpanHigh))}
}

// clamp applies the client's protocol-level bounds, Min in [48, 1024] and
// Max in [Min, 1024]. The coordinator only ever sends tighter values; the
// clamp keeps a faulty one from producing unsendable packets. The zero value
// is refused instead: it means the interval was never filled in, and clamping
// it would give the whole session one constant length, which would make its
// packets recognisable.
func (p PadPolicy) clamp() (PadPolicy, error) {
	if p == (PadPolicy{}) {
		return p, errNoPad
	}
	lo := min(max(p.Min, padMinLow), MaxPlaintext)
	return PadPolicy{Min: lo, Max: min(max(p.Max, lo), MaxPlaintext)}, nil
}

// ReplyLengths returns the plaintext lengths of natprobe's replies to a probe
// whose datagram is reqWire bytes long.
// second reports that the probe asked for an extra or alt reply and the quota
// allows one; wrapped that the probe came as an opener, so that every reply
// goes out as one too and costs up to 35 bytes more.
// Lengths are in [minimum legal, request] so that reply bytes never exceed
// request bytes; with w the per-reply opener cost (0 or 35):
//
//   - reqWire − w < 83, or reqWire above the longest valid probe (1069, or
//     MaxWrapped for an opener): no reply, (0, 0);
//   - ack only: ack wire length uniform in [83, min(reqWire − w, 1053)];
//   - two replies, when second and reqWire − 2w ≥ 156: total T uniform in
//     [156, reqWire − 2w], ack uniform in [83, T − 73], second = T − ack.
//
// A zero secondPlain means only the ack is sent, so the ack must not claim
// EXTRA_SENT or ALT_SENT. A nil r uses the math/rand/v2 global source.
func ReplyLengths(reqWire int, second, wrapped bool, r *rand.Rand) (ackPlain, secondPlain int) {
	maxReq, w := maxProbePacket, 0
	if wrapped {
		maxReq, w = MaxWrapped, maxWrapOverhead
	}
	if reqWire-w < minAckWire || reqWire > maxReq {
		return 0, 0
	}
	if !second || reqWire-2*w < minPairWire {
		return uniform(r, minAckWire, min(reqWire-w, maxPeerPacket)) - replyOverhead, 0
	}
	total := uniform(r, minPairWire, reqWire-2*w)
	ack := uniform(r, minAckWire, total-minExtraWire)
	return ack - replyOverhead, total - ack - replyOverhead
}

// uniform returns an integer uniformly distributed in [lo, hi] (lo ≤ hi).
func uniform(r *rand.Rand, lo, hi int) int {
	if r == nil {
		return lo + rand.IntN(hi-lo+1)
	}
	return lo + r.IntN(hi-lo+1)
}

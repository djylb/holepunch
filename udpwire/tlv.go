package udpwire

import (
	"encoding/binary"
	"net/netip"
)

// TLVs holds the optional plaintext fields that follow the header.
// Each packet type carries a fixed subset: Seal rejects a TLVs that sets any
// other field, and Open fills only that subset and leaves the rest zero.
type TLVs struct {
	// Observed is the request source address the replier saw (OBSERVED).
	// Carried and mandatory on probe_ack, probe_extra, probe_alt and success;
	// it must have a non-zero port and a specified address. On the wire it is
	// 16 bytes of IPv6 (IPv4 as v4-mapped) plus a port, so Open returns IPv4
	// unmapped and without a zone.
	Observed netip.AddrPort
	// ExtraPort is the source port of the extra reply natprobe sent for this
	// probe, 0 if none (EXTRA_PORT; always present on probe_ack).
	ExtraPort uint16
	// Cookie is the return-reachability cookie of the observation slot, 0 if
	// none (COOKIE; always present on probe_ack).
	Cookie uint32
	// Sandwich marks a probe natprobe hands to the coordinator (SANDWICH,
	// probe): Round is the punch round and Phase is 0 before or 1 after
	// the round's first punch (the sandwich), 2 or 3 for the first or
	// second probe of an anchor refresh. Set
	// reports presence.
	Sandwich struct {
		Round, Phase uint8
		Set          bool
	}
	// RxCount is how many authenticated packets the sender has received from
	// the receiver so far (RX_COUNT; success, accept, handover_ack). HasRx
	// reports presence.
	RxCount uint32
	// HasRx reports whether RxCount is present.
	HasRx bool
	// Slot is the extra-path slot of a nomination and of its accept
	// (PATH_SLOT; nominate, accept): 1 to maxPathSlot for an extra path; 0,
	// sent as no TLV, for the primary path.
	Slot uint8
	// Paths is the extra-path field (PATHS; accept, ready), 0 sent as no
	// TLV. On the primary path's accept it is how many extra paths the
	// responder takes; on ready the extra slots the initiator commits, bit
	// k for slot k. The receiver interprets it by the packet type.
	Paths uint8
}

// TLV codes, lengths and the per-type carry sets.
const (
	tlvPad       = 0x00 // terminates parsing; zero padding follows
	tlvObserved  = 0x01
	tlvExtraPort = 0x02
	tlvCookie    = 0x03
	tlvSandwich  = 0x04
	tlvRxCount   = 0x05
	tlvPathSlot  = 0x06
	tlvPaths     = 0x07

	tlvHeaderSize = 2 // type, length
	observedSize  = 16 + 2
	extraPortSize = 2
	cookieSize    = 4
	sandwichSize  = 2
	rxCountSize   = 4
	pathSlotSize  = 1
	pathsSize     = 1

	maxProbePhase = 3 // largest valid Sandwich.Phase: the second refresh probe
	// maxPathSlot is the largest extra-path slot: a session hands over at
	// most eight paths, the primary and seven extra ones, whose slots fit
	// the bits 1–7 of PATHS on ready.
	maxPathSlot = 7
)

// tlvSet is a bit set indexed by TLV code.
type tlvSet uint8

const (
	carriesObserved  tlvSet = 1 << tlvObserved
	carriesExtraPort tlvSet = 1 << tlvExtraPort
	carriesCookie    tlvSet = 1 << tlvCookie
	carriesSandwich  tlvSet = 1 << tlvSandwich
	carriesRxCount   tlvSet = 1 << tlvRxCount
	carriesPathSlot  tlvSet = 1 << tlvPathSlot
	carriesPaths     tlvSet = 1 << tlvPaths
)

func (s tlvSet) has(code byte) bool { return code < 8 && s&(1<<code) != 0 }

// mandatory returns the TLVs of s that Seal always emits and Open therefore
// requires: OBSERVED, EXTRA_PORT and COOKIE. SANDWICH, RX_COUNT, PATH_SLOT
// and PATHS are optional.
func (s tlvSet) mandatory() tlvSet { return s & (carriesObserved | carriesExtraPort | carriesCookie) }

// validObserved reports whether ap may be sent as OBSERVED: a real source
// address always has a specified IP and a non-zero port.
func validObserved(ap netip.AddrPort) bool {
	return ap.IsValid() && ap.Port() != 0 && !ap.Addr().Unmap().IsUnspecified()
}

// valid reports whether t can be sealed for a packet with carry set s: each
// carried TLV is well formed, and every other field — a TLV the type does not
// carry, or the value of an absent SANDWICH/RX_COUNT — is zero, so a caller
// never believes it sent something Seal would have dropped. PATH_SLOT and
// PATHS are absent at zero, so only a slot past maxPathSlot is malformed.
func (t *TLVs) valid(s tlvSet) bool {
	rest := *t
	if s.has(tlvObserved) {
		if !validObserved(t.Observed) {
			return false
		}
		rest.Observed = netip.AddrPort{}
	}
	if s.has(tlvExtraPort) {
		rest.ExtraPort = 0
	}
	if s.has(tlvCookie) {
		rest.Cookie = 0
	}
	if s.has(tlvSandwich) && t.Sandwich.Set {
		if t.Sandwich.Phase > maxProbePhase {
			return false
		}
		rest.Sandwich.Round, rest.Sandwich.Phase, rest.Sandwich.Set = 0, 0, false
	}
	if s.has(tlvRxCount) && t.HasRx {
		rest.RxCount, rest.HasRx = 0, false
	}
	if s.has(tlvPathSlot) {
		if t.Slot > maxPathSlot {
			return false
		}
		rest.Slot = 0
	}
	if s.has(tlvPaths) {
		rest.Paths = 0
	}
	return rest == TLVs{}
}

// size returns the encoded length of the TLVs in carry set s. OBSERVED,
// EXTRA_PORT and COOKIE are always emitted when carried (MinAckPlaintext
// counts them); SANDWICH, RX_COUNT, PATH_SLOT and PATHS only when present.
func (t *TLVs) size(s tlvSet) int {
	n := 0
	if s.has(tlvObserved) {
		n += tlvHeaderSize + observedSize
	}
	if s.has(tlvExtraPort) {
		n += tlvHeaderSize + extraPortSize
	}
	if s.has(tlvCookie) {
		n += tlvHeaderSize + cookieSize
	}
	if s.has(tlvSandwich) && t.Sandwich.Set {
		n += tlvHeaderSize + sandwichSize
	}
	if s.has(tlvRxCount) && t.HasRx {
		n += tlvHeaderSize + rxCountSize
	}
	if s.has(tlvPathSlot) && t.Slot != 0 {
		n += tlvHeaderSize + pathSlotSize
	}
	if s.has(tlvPaths) && t.Paths != 0 {
		n += tlvHeaderSize + pathsSize
	}
	return n
}

// put encodes the TLVs in carry set s into b, in ascending code order, and
// returns the number of bytes written (t.size(s)).
func (t *TLVs) put(b []byte, s tlvSet) int {
	n := 0
	if s.has(tlvObserved) {
		v := tlvAt(b[n:], tlvObserved, observedSize)
		a := t.Observed.Addr().As16()
		copy(v, a[:])
		binary.BigEndian.PutUint16(v[16:], t.Observed.Port())
		n += tlvHeaderSize + observedSize
	}
	if s.has(tlvExtraPort) {
		binary.BigEndian.PutUint16(tlvAt(b[n:], tlvExtraPort, extraPortSize), t.ExtraPort)
		n += tlvHeaderSize + extraPortSize
	}
	if s.has(tlvCookie) {
		binary.BigEndian.PutUint32(tlvAt(b[n:], tlvCookie, cookieSize), t.Cookie)
		n += tlvHeaderSize + cookieSize
	}
	if s.has(tlvSandwich) && t.Sandwich.Set {
		v := tlvAt(b[n:], tlvSandwich, sandwichSize)
		v[0], v[1] = t.Sandwich.Round, t.Sandwich.Phase
		n += tlvHeaderSize + sandwichSize
	}
	if s.has(tlvRxCount) && t.HasRx {
		binary.BigEndian.PutUint32(tlvAt(b[n:], tlvRxCount, rxCountSize), t.RxCount)
		n += tlvHeaderSize + rxCountSize
	}
	if s.has(tlvPathSlot) && t.Slot != 0 {
		tlvAt(b[n:], tlvPathSlot, pathSlotSize)[0] = t.Slot
		n += tlvHeaderSize + pathSlotSize
	}
	if s.has(tlvPaths) && t.Paths != 0 {
		tlvAt(b[n:], tlvPaths, pathsSize)[0] = t.Paths
		n += tlvHeaderSize + pathsSize
	}
	return n
}

// tlvAt writes a TLV header at b[0:2] and returns the value slot.
func tlvAt(b []byte, code byte, size int) []byte {
	b[0], b[1] = code, byte(size)
	return b[tlvHeaderSize : tlvHeaderSize+size]
}

// parseTLVs decodes the TLV region b of a packet with carry set s into t
// (which the caller has zeroed). Parsing stops at a PAD byte or at the end;
// whatever follows PAD is padding and is not inspected (it is
// authenticated already). Codes outside s — unknown, experimental, or
// known but not carried by this type — are skipped, and a repeated code keeps
// its first occurrence. A TLV that overruns b, a carried TLV of the wrong
// length or with an invalid value, and a missing mandatory TLV all fail, so
// Open accepts exactly the TLV sets Seal can produce.
func parseTLVs(b []byte, s tlvSet, t *TLVs) bool {
	var seen tlvSet
	for len(b) > 0 && b[0] != tlvPad {
		if len(b) < tlvHeaderSize || len(b) < tlvHeaderSize+int(b[1]) {
			return false
		}
		code, v := b[0], b[tlvHeaderSize:tlvHeaderSize+int(b[1])]
		b = b[tlvHeaderSize+len(v):]
		if !s.has(code) || seen.has(code) {
			continue
		}
		seen |= 1 << code
		if !t.decode(code, v) {
			return false
		}
	}
	return seen&s.mandatory() == s.mandatory()
}

// decode stores the value v of a carried TLV.
func (t *TLVs) decode(code byte, v []byte) bool {
	switch code {
	case tlvObserved:
		if len(v) != observedSize {
			return false
		}
		addr := netip.AddrFrom16([16]byte(v[:16])).Unmap()
		t.Observed = netip.AddrPortFrom(addr, binary.BigEndian.Uint16(v[16:]))
		return validObserved(t.Observed)
	case tlvExtraPort:
		if len(v) != extraPortSize {
			return false
		}
		t.ExtraPort = binary.BigEndian.Uint16(v)
	case tlvCookie:
		if len(v) != cookieSize {
			return false
		}
		t.Cookie = binary.BigEndian.Uint32(v)
	case tlvSandwich:
		if len(v) != sandwichSize || v[1] > maxProbePhase {
			return false
		}
		t.Sandwich.Round, t.Sandwich.Phase, t.Sandwich.Set = v[0], v[1], true
	case tlvRxCount:
		if len(v) != rxCountSize {
			return false
		}
		t.RxCount, t.HasRx = binary.BigEndian.Uint32(v), true
	case tlvPathSlot:
		// Zero is the primary path, which is sent without the TLV.
		if len(v) != pathSlotSize || v[0] == 0 || v[0] > maxPathSlot {
			return false
		}
		t.Slot = v[0]
	case tlvPaths:
		if len(v) != pathsSize || v[0] == 0 {
			return false
		}
		t.Paths = v[0]
	}
	return true
}

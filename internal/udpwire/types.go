package udpwire

// Type is the packet type, the first plaintext byte. Codes are
// contiguous from 1; 0 and 12–255 are invalid.
type Type uint8

// Packet types. TProbe is the only type sealed in envelope P.
const (
	// TProbe is a client's probe to a natprobe observer (also the waiting
	// keepalive and the sandwich probe). Flags: FA = WANT_EXTRA, FB = WANT_ALT.
	TProbe Type = iota + 1
	// TProbeAck is the observer's reply to a probe. Flags: FA = EXTRA_SENT,
	// FB = ALT_SENT, FC = QUOTA_EXHAUSTED.
	TProbeAck
	// TProbeExtra is the reply from natprobe's extra pool (same IP, other port).
	TProbeExtra
	// TProbeAlt is the reply from natprobe's second IP.
	TProbeAlt
	// THairpin is a client's packet to its own public mapping.
	THairpin
	// TPunch is a hole-punching packet between clients.
	TPunch
	// TSuccess answers an authenticated punch.
	TSuccess
	// TNominate is the initiator's nomination of a candidate pair: the
	// primary path's, or with PATH_SLOT an extra path's.
	TNominate
	// TAccept is the responder's acceptance of a nomination; on an extra
	// path's it echoes PATH_SLOT, on the primary path's PATHS is the
	// responder's room for extra paths.
	TAccept
	// TReady is the initiator's confirmation of the primary path's
	// acceptance; PATHS lists the extra paths it commits.
	TReady
	// THandoverAck is the responder's acknowledgement of ready.
	THandoverAck
)

// Role is a sender role, carried in the low two flag bits. 0 is invalid.
type Role uint8

// Roles.
const (
	// RoleInitiator is the client that nominates.
	RoleInitiator Role = iota + 1
	// RoleResponder is the client that accepts.
	RoleResponder
	// RoleServer is natprobe.
	RoleServer
)

// Flag byte layout.
const (
	flagRole     = 0x03
	flagLowTTL   = 1 << 2
	flagRetx     = 1 << 3
	flagFA       = 1 << 4
	flagFB       = 1 << 5
	flagFC       = 1 << 6
	flagReserved = 1 << 7
)

// roleSet is a bit set indexed by Role.
type roleSet uint8

const (
	fromInitiator roleSet = 1 << RoleInitiator
	fromResponder roleSet = 1 << RoleResponder
	fromServer    roleSet = 1 << RoleServer
	fromClient            = fromInitiator | fromResponder
)

func (s roleSet) has(r Role) bool { return r <= RoleServer && s&(1<<r) != 0 }

func roleBit(r Role) roleSet { return 1 << r }

// peerOf returns the other client role.
func peerOf(r Role) Role {
	if r == RoleInitiator {
		return RoleResponder
	}
	return RoleInitiator
}

// lengthRule says where a packet's plaintext length comes from when Seal is
// not given one.
type lengthRule uint8

const (
	// lengthSession draws from the session PadPolicy.
	lengthSession lengthRule = iota
	// lengthProbe draws from the global probe interval, which grows when the
	// probe asks for a second reply so the requester pays for it.
	lengthProbe
	// lengthExplicit means the caller must choose: natprobe sizes replies
	// with ReplyLengths.
	lengthExplicit
)

// rule is the static per-type contract that Seal enforces and Open checks.
type rule struct {
	senders roleSet
	flags   uint8  // permitted FA/FB/FC bits
	tlvs    tlvSet // TLVs the type carries; see tlvSet.mandatory
	length  lengthRule
}

// ruleOf returns the rule of t. It is a switch rather than a table so that no
// package-level state exists to be aliased or mutated.
func ruleOf(t Type) (rule, bool) {
	switch t {
	case TProbe:
		return rule{senders: fromClient, flags: flagFA | flagFB, tlvs: carriesSandwich, length: lengthProbe}, true
	case TProbeAck:
		return rule{senders: fromServer, flags: flagFA | flagFB | flagFC, tlvs: carriesObserved | carriesExtraPort | carriesCookie, length: lengthExplicit}, true
	case TProbeExtra, TProbeAlt:
		return rule{senders: fromServer, tlvs: carriesObserved, length: lengthExplicit}, true
	case THairpin, TPunch:
		return rule{senders: fromClient, length: lengthSession}, true
	case TSuccess:
		return rule{senders: fromClient, tlvs: carriesObserved | carriesRxCount, length: lengthSession}, true
	case TNominate:
		return rule{senders: fromInitiator, tlvs: carriesPathSlot, length: lengthSession}, true
	case TReady:
		return rule{senders: fromInitiator, tlvs: carriesPaths, length: lengthSession}, true
	case TAccept:
		return rule{senders: fromResponder, tlvs: carriesRxCount | carriesPathSlot | carriesPaths, length: lengthSession}, true
	case THandoverAck:
		return rule{senders: fromResponder, tlvs: carriesRxCount, length: lengthSession}, true
	}
	return rule{}, false
}

// admits reports whether flag byte f is valid for the rule: reserved bit
// clear, a sender role the type allows, only the type's own FA/FB/FC bits,
// and never FA together with FB (a probe asks for one second reply at most,
// so an ack reports at most one).
func (r rule) admits(f byte) bool {
	return f&flagReserved == 0 &&
		r.senders.has(Role(f&flagRole)) &&
		f&(flagFA|flagFB|flagFC)&^r.flags == 0 &&
		f&(flagFA|flagFB) != flagFA|flagFB
}

package protocol

import (
	"fmt"
	"net/netip"
)

// Enumerations. String-kind enums (Role, Family, Phase, BudgetClass,
// BirthdayTier and the value types of model.go) are lowercase strings on the
// wire by construction; uint8-kind enums (Mapping, Filtering, PortAlloc, Conf,
// Tri, ControlSecurity, ReasonClass) implement encoding.TextMarshaler and
// encoding.TextUnmarshaler with lowercase names.
// UnmarshalText of a uint8-kind enum rejects unknown names; string-kind enums
// decode any string and are checked by Validate, because some of them are open
// (an unknown Reason in punch_abort maps to aborted_by_*, an unknown Feature
// or assist kind is ignored).

// ---- roles and families ----

// Role is a session role. RoleServer only appears in Abort.By and Assist.From.
type Role string

// Role values.
const (
	RoleInitiator Role = "initiator"
	RoleResponder Role = "responder"
	RoleServer    Role = "server"
)

// Peer returns the other punching role (initiator ↔ responder) and "" for
// anything else.
func (r Role) Peer() Role {
	switch r {
	case RoleInitiator:
		return RoleResponder
	case RoleResponder:
		return RoleInitiator
	}
	return ""
}

// IsPunch reports whether r is initiator or responder.
func (r Role) IsPunch() bool { return r == RoleInitiator || r == RoleResponder }

// Valid reports whether r is one of the three roles.
func (r Role) Valid() bool { return r.IsPunch() || r == RoleServer }

// Code is the role code in the UDP payload header:
// 1 initiator, 2 responder, 3 server, 0 otherwise. The spray seed's info string
// uses it too.
func (r Role) Code() uint8 {
	switch r {
	case RoleInitiator:
		return 1
	case RoleResponder:
		return 2
	case RoleServer:
		return 3
	}
	return 0
}

// Family is an address family.
type Family string

// Family values.
const (
	FamilyUDP4 Family = "udp4"
	FamilyUDP6 Family = "udp6"
)

// Valid reports whether f is udp4 or udp6.
func (f Family) Valid() bool { return f == FamilyUDP4 || f == FamilyUDP6 }

// Matches reports whether a belongs to f: an IPv4 address for udp4, an IPv6
// address that is not IPv4-mapped for udp6. Plans and assists only carry
// addresses of the family they are about.
func (f Family) Matches(a netip.Addr) bool {
	switch f {
	case FamilyUDP4:
		return a.Is4()
	case FamilyUDP6:
		return a.Is6() && !a.Is4In6()
	}
	return false
}

// FamilyOf is the family of a, or "" for an invalid or IPv4-mapped address.
func FamilyOf(a netip.Addr) Family {
	switch {
	case a.Is4():
		return FamilyUDP4
	case a.Is6() && !a.Is4In6():
		return FamilyUDP6
	}
	return ""
}

// ---- client phase (holepunch.Phase; the only values of punch_result.phase) ----

// Phase is the client session phase. It is the
// value of punch_result.phase and of the client API's phase.
type Phase string

// Phase values.
const (
	PhaseCreated     Phase = "created"     // AttachSession called
	PhaseProbing     Phase = "probing"     // punch_start accepted
	PhaseReported    Phase = "reported"    // probe_report written
	PhasePlanned     Phase = "planned"     // summary accepted, sockets pre-bound
	PhaseReady       Phase = "ready"       // punch_ready written
	PhasePunching    Phase = "punching"    // a go's delay elapsed; also between rounds
	PhaseNegotiating Phase = "negotiating" // first success or nomination
	PhaseConfirmed   Phase = "confirmed"   // local Confirm, round_result{confirmed} sent
	PhaseHandover    Phase = "handover"    // waiting for / sending handover_ack
	PhaseDone        Phase = "done"        // handed over; terminal
	PhaseFailed      Phase = "failed"      // terminal
)

// Valid reports whether p is one of the eleven phases.
func (p Phase) Valid() bool {
	switch p {
	case PhaseCreated, PhaseProbing, PhaseReported, PhasePlanned, PhaseReady, PhasePunching,
		PhaseNegotiating, PhaseConfirmed, PhaseHandover, PhaseDone, PhaseFailed:
		return true
	}
	return false
}

// Terminal reports whether p is done or failed.
func (p Phase) Terminal() bool { return p == PhaseDone || p == PhaseFailed }

// ---- control-stream security ----

// ControlSecurity says how the caller vouches for the control stream's
// confidentiality and integrity. Wire text: unknown | declared |
// insecure_for_testing.
type ControlSecurity uint8

// ControlSecurity values.
const (
	// ControlSecurityUnknown is the default: the stream is accepted only if
	// the conn has ConnectionState() with HandshakeComplete (TLS); otherwise
	// it is rejected with invalid_argument (detail insecure_control).
	ControlSecurityUnknown ControlSecurity = iota
	// ControlSecurityDeclared means the caller declares the outer layer
	// encrypted and authenticated (such as an encrypted bridge).
	ControlSecurityDeclared
	// ControlSecurityInsecureForTesting is for tests and loopback only; it is
	// marked in Diagnostics, every progress meta (insecure=1) and Warn.
	ControlSecurityInsecureForTesting
)

// The wire names of the uint8-kind enums, indexed by value. They are
// functions returning arrays rather than package variables so that no shared
// table can be modified (lintcheck noglobalstate).
func controlSecurityNames() [3]string {
	return [3]string{"unknown", "declared", "insecure_for_testing"}
}

// String returns the wire name of s.
//
//goland:noinspection GoMixedReceiverTypes
func (s ControlSecurity) String() string {
	n := controlSecurityNames()
	return enumString(n[:], uint8(s))
}

// MarshalText encodes s as its wire name; an out-of-range value is an error.
//
//goland:noinspection GoMixedReceiverTypes
func (s ControlSecurity) MarshalText() ([]byte, error) {
	n := controlSecurityNames()
	return enumMarshal("control security", n[:], uint8(s))
}

// UnmarshalText accepts exactly the wire names.
//
//goland:noinspection GoMixedReceiverTypes
func (s *ControlSecurity) UnmarshalText(b []byte) error {
	n := controlSecurityNames()
	return enumParse(s, "control security", n[:], b)
}

// ---- NAT description ----

// Mapping is the NAT mapping behaviour: unknown | eim | adm | apdm.
type Mapping uint8

// Mapping values.
const (
	MapUnknown Mapping = iota
	MapEIM             // endpoint-independent
	MapADM             // address-dependent
	MapAPDM            // address-and-port-dependent
)

// Filtering is the NAT filtering behaviour: unknown | eif | adf | pdf |
// not_pdf (EIF and ADF cannot be told apart with a single server IP).
type Filtering uint8

// Filtering values.
const (
	FiltUnknown Filtering = iota
	FiltEIF
	FiltADF
	FiltPDF
	FiltNotPDF
)

// PortAlloc is the external port allocation: unknown | preserving |
// sequential | pool | random | preserve_fresh.
type PortAlloc uint8

// PortAlloc values.
const (
	AllocUnknown PortAlloc = iota
	AllocPreserving
	AllocSequential
	AllocPool
	AllocRandom
	// AllocPreserveFresh is an endpoint-dependent allocator whose fresh
	// socket keeps its local port for its first mapping, while the later
	// mappings of the same socket get other ports: the first mapping of a
	// socket bound at a chosen port is known
	// in advance.
	AllocPreserveFresh
)

// Conf is a confidence level, ordered: none < low < medium < high.
type Conf uint8

// Conf values.
const (
	ConfNone Conf = iota
	ConfLow
	ConfMedium
	ConfHigh
)

// Tri is a three-valued boolean: unknown | false | true.
type Tri uint8

// Tri values.
const (
	TriUnknown Tri = iota
	TriFalse
	TriTrue
)

func mappingNames() [4]string   { return [4]string{"unknown", "eim", "adm", "apdm"} }
func filteringNames() [5]string { return [5]string{"unknown", "eif", "adf", "pdf", "not_pdf"} }
func portAllocNames() [6]string {
	return [6]string{"unknown", "preserving", "sequential", "pool", "random", "preserve_fresh"}
}
func confNames() [4]string { return [4]string{"none", "low", "medium", "high"} }
func triNames() [3]string  { return [3]string{"unknown", "false", "true"} }

// String returns the wire name of m.
//
//goland:noinspection GoMixedReceiverTypes
func (m Mapping) String() string { n := mappingNames(); return enumString(n[:], uint8(m)) }

// Valid reports whether m is a defined value.
//
//goland:noinspection GoMixedReceiverTypes
func (m Mapping) Valid() bool { return int(m) < len(mappingNames()) }

// MarshalText encodes m as its wire name; an out-of-range value is an error.
//
//goland:noinspection GoMixedReceiverTypes
func (m Mapping) MarshalText() ([]byte, error) {
	n := mappingNames()
	return enumMarshal("mapping", n[:], uint8(m))
}

// UnmarshalText accepts exactly the wire names.
//
//goland:noinspection GoMixedReceiverTypes
func (m *Mapping) UnmarshalText(b []byte) error {
	n := mappingNames()
	return enumParse(m, "mapping", n[:], b)
}

// String returns the wire name of f.
//
//goland:noinspection GoMixedReceiverTypes
func (f Filtering) String() string { n := filteringNames(); return enumString(n[:], uint8(f)) }

// Valid reports whether f is a defined value.
//
//goland:noinspection GoMixedReceiverTypes
func (f Filtering) Valid() bool { return int(f) < len(filteringNames()) }

// MarshalText encodes f as its wire name; an out-of-range value is an error.
//
//goland:noinspection GoMixedReceiverTypes
func (f Filtering) MarshalText() ([]byte, error) {
	n := filteringNames()
	return enumMarshal("filtering", n[:], uint8(f))
}

// UnmarshalText accepts exactly the wire names.
//
//goland:noinspection GoMixedReceiverTypes
func (f *Filtering) UnmarshalText(b []byte) error {
	n := filteringNames()
	return enumParse(f, "filtering", n[:], b)
}

// String returns the wire name of a.
//
//goland:noinspection GoMixedReceiverTypes
func (a PortAlloc) String() string { n := portAllocNames(); return enumString(n[:], uint8(a)) }

// Valid reports whether a is a defined value.
//
//goland:noinspection GoMixedReceiverTypes
func (a PortAlloc) Valid() bool { return int(a) < len(portAllocNames()) }

// MarshalText encodes a as its wire name; an out-of-range value is an error.
//
//goland:noinspection GoMixedReceiverTypes
func (a PortAlloc) MarshalText() ([]byte, error) {
	n := portAllocNames()
	return enumMarshal("port allocation", n[:], uint8(a))
}

// UnmarshalText accepts exactly the wire names.
//
//goland:noinspection GoMixedReceiverTypes
func (a *PortAlloc) UnmarshalText(b []byte) error {
	n := portAllocNames()
	return enumParse(a, "port allocation", n[:], b)
}

// String returns the wire name of c.
//
//goland:noinspection GoMixedReceiverTypes
func (c Conf) String() string { n := confNames(); return enumString(n[:], uint8(c)) }

// Valid reports whether c is a defined value.
//
//goland:noinspection GoMixedReceiverTypes
func (c Conf) Valid() bool { return int(c) < len(confNames()) }

// MarshalText encodes c as its wire name; an out-of-range value is an error.
//
//goland:noinspection GoMixedReceiverTypes
func (c Conf) MarshalText() ([]byte, error) {
	n := confNames()
	return enumMarshal("confidence", n[:], uint8(c))
}

// UnmarshalText accepts exactly the wire names.
//
//goland:noinspection GoMixedReceiverTypes
func (c *Conf) UnmarshalText(b []byte) error {
	n := confNames()
	return enumParse(c, "confidence", n[:], b)
}

// String returns the wire name of t.
//
//goland:noinspection GoMixedReceiverTypes
func (t Tri) String() string { n := triNames(); return enumString(n[:], uint8(t)) }

// Valid reports whether t is a defined value.
//
//goland:noinspection GoMixedReceiverTypes
func (t Tri) Valid() bool { return int(t) < len(triNames()) }

// MarshalText encodes t as its wire name; an out-of-range value is an error.
//
//goland:noinspection GoMixedReceiverTypes
func (t Tri) MarshalText() ([]byte, error) {
	n := triNames()
	return enumMarshal("tri-state", n[:], uint8(t))
}

// UnmarshalText accepts exactly the wire names.
//
//goland:noinspection GoMixedReceiverTypes
func (t *Tri) UnmarshalText(b []byte) error {
	n := triNames()
	return enumParse(t, "tri-state", n[:], b)
}

// ---- budgets ----

// BudgetClass is a per-round budget ceiling: light | balanced | heavy |
// extreme | background. Ordered by Rank.
type BudgetClass string

// BudgetClass values.
const (
	BudgetLight    BudgetClass = "light"
	BudgetBalanced BudgetClass = "balanced"
	BudgetHeavy    BudgetClass = "heavy"
	BudgetExtreme  BudgetClass = "extreme"
	// BudgetBackground is the slow birthday of a Background session: many
	// sockets opened slowly, a long window and a low rate — wide in time,
	// gentle per second. It ranks with heavy and runs only in a Background
	// session.
	BudgetBackground BudgetClass = "background"
)

// SessionMode says whether anyone waits for a session: interactive |
// background. The empty value is interactive.
type SessionMode string

// Session modes.
const (
	// ModeInteractive means the caller waits for the session; the ladder
	// fails fast. The default.
	ModeInteractive SessionMode = "interactive"
	// ModeBackground means a relay already serves the caller and nobody
	// waits; a PDF × RND pair may run the slow birthday (BudgetBackground).
	ModeBackground SessionMode = "background"
)

// Valid reports whether m is empty or one of the modes.
func (m SessionMode) Valid() bool { return m == "" || m == ModeInteractive || m == ModeBackground }

// Advice is what a failed session suggests for the next attempt: "" (retry as
// before), background_viable or relay_only.
type Advice string

// Advice values.
const (
	// AdviceBackgroundViable means the pair connects slowly: serve the
	// caller over the relay and punch again in ModeBackground.
	AdviceBackgroundViable Advice = "background_viable"
	// AdviceRelayOnly means no mode is expected to connect the pair; keep
	// the relay.
	AdviceRelayOnly Advice = "relay_only"
)

// Valid reports whether a is empty or one of the advice values.
func (a Advice) Valid() bool { return a == "" || a == AdviceBackgroundViable || a == AdviceRelayOnly }

// BirthdayTier is the birthday-spray scale: off | conservative | balanced |
// aggressive. Ordered by Rank. The empty value means "unset" in a Policy.
type BirthdayTier string

// BirthdayTier values.
const (
	BirthdayOff          BirthdayTier = "off"
	BirthdayConservative BirthdayTier = "conservative"
	BirthdayBalanced     BirthdayTier = "balanced"
	BirthdayAggressive   BirthdayTier = "aggressive"
)

// ---- helpers ----

func enumString(names []string, v uint8) string {
	if int(v) < len(names) {
		return names[v]
	}
	return fmt.Sprintf("invalid(%d)", v)
}

func enumMarshal(what string, names []string, v uint8) ([]byte, error) {
	if int(v) < len(names) {
		return []byte(names[v]), nil
	}
	return nil, fmt.Errorf("protocol: invalid %s value %d", what, v)
}

func enumParse[T ~uint8](dst *T, what string, names []string, b []byte) error {
	for i, n := range names {
		if string(b) == n {
			*dst = T(i)
			return nil
		}
	}
	return fmt.Errorf("protocol: unknown %s %q", what, b)
}

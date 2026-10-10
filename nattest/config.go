package nattest

import (
	"fmt"
	"net/netip"
	"time"
)

// Mapping is the mapping behaviour of a NAT (RFC 4787, section 4.1): which outbound
// packets of one internal endpoint share an external endpoint.
type Mapping uint8

const (
	// EIM is endpoint-independent mapping, keyed by (internal IP, internal port).
	EIM Mapping = iota
	// ADM is address-dependent mapping, keyed by (internal endpoint, destination IP).
	ADM
	// APDM is address-and-port-dependent mapping, keyed by (internal endpoint,
	// destination IP, destination port).
	APDM
	// Identity translates nothing: the hosts own addresses of the parent realm
	// and the device is a stateful firewall that filters by Filtering.
	Identity
)

// String returns the abbreviation used in RFC 4787 and in dumps.
func (m Mapping) String() string {
	switch m {
	case EIM:
		return "EIM"
	case ADM:
		return "ADM"
	case APDM:
		return "APDM"
	case Identity:
		return "Identity"
	}
	return fmt.Sprintf("Mapping(%d)", uint8(m))
}

// Filtering is the inbound filtering behaviour of a NAT or firewall (RFC 4787,
// section 5). Permissions belong to a mapping: an inbound packet is judged
// against the destinations its target mapping has sent to, as a connection
// tracking table does.
type Filtering uint8

const (
	// EIF is endpoint-independent filtering: any source may reach an existing
	// mapping.
	EIF Filtering = iota
	// ADF is address-dependent filtering: only IPs the mapping has sent to.
	ADF
	// APDF is address-and-port-dependent filtering: only the (IP, port) pairs
	// the mapping has sent to.
	APDF
	// Open accepts every inbound packet, even without a prior outbound one. It
	// is meant for Identity, NoNAT and NPTv6; on a translating NAT, where an
	// inbound packet needs a mapping anyway, it behaves as EIF.
	Open
)

// String returns the abbreviation used in RFC 4787 and in dumps.
func (f Filtering) String() string {
	switch f {
	case EIF:
		return "EIF"
	case ADF:
		return "ADF"
	case APDF:
		return "APDF"
	case Open:
		return "Open"
	}
	return fmt.Sprintf("Filtering(%d)", uint8(f))
}

// PortAlloc is the strategy a NAT uses to pick the external port of a new
// mapping. It is one of the constants below or a [Pool].
//
// The low 16 bits hold the strategy; a Pool also carries its bounds in bits
// 16–47, which keeps PortAlloc a comparable value that fits in a constant.
type PortAlloc uint64

const (
	// Preserve uses the internal port when it is free and inside PortRange,
	// and otherwise the next port of the NAT-wide Sequential cursor.
	Preserve PortAlloc = iota
	// Sequential allocates the previous port plus PortStep, wrapping inside
	// PortRange and skipping busy ports. The cursor is kept per external IP
	// and starts at a seeded random position.
	Sequential
	// Random picks a seeded, uniformly random free port inside PortRange.
	Random
	// PreserveThenSequential uses the internal port when it is free, and
	// otherwise walks from the internal port in steps of PortStep.
	PreserveThenSequential
	// PreserveThenRandom uses the internal port when it is free, and
	// otherwise a seeded random free port. Under APDM a fresh socket's
	// first mapping keeps its port and its later ones are random (PRESRND).
	PreserveThenRandom

	allocPool // strategy part of Pool(lo, hi)
)

// Pool allocates uniformly at random inside the port block [lo, hi], the way
// a CGNAT assigns each subscriber a block of ports (RFC 7422). The bounds may
// be given in either order; port 0 is never allocated.
func Pool(lo, hi uint16) PortAlloc {
	if lo > hi {
		lo, hi = hi, lo
	}
	return allocPool | PortAlloc(lo)<<16 | PortAlloc(hi)<<32
}

func (a PortAlloc) kind() PortAlloc { return a & 0xffff }

func (a PortAlloc) bounds() (lo, hi uint16) { return uint16(a >> 16), uint16(a >> 32) }

// String returns the strategy name, with the bounds for a Pool.
func (a PortAlloc) String() string {
	switch a.kind() {
	case Preserve:
		return "Preserve"
	case Sequential:
		return "Sequential"
	case Random:
		return "Random"
	case PreserveThenSequential:
		return "PreserveThenSequential"
	case PreserveThenRandom:
		return "PreserveThenRandom"
	case allocPool:
		lo, hi := a.bounds()
		return fmt.Sprintf("Pool(%d,%d)", lo, hi)
	}
	return fmt.Sprintf("PortAlloc(%d)", uint64(a))
}

// ExitPolicy selects the external address of a new mapping when a NAT has
// more than one (a router with several uplinks or a CGNAT address pool).
type ExitPolicy uint8

const (
	// SingleExit always uses the first external address.
	SingleExit ExitPolicy = iota
	// PerSourcePort hashes the internal endpoint: one socket keeps its exit,
	// different sockets spread over the exits (the multi_exit evidence of a
	// probe).
	PerSourcePort
	// PerDestIP hashes the destination IP: the exit is stable per destination
	// IP and differs across IPs. The exit becomes part of the mapping key, so
	// an EIM mapping is split per exit.
	PerDestIP
	// RoundRobin uses the next address for every new mapping.
	RoundRobin
)

// String returns the policy name.
func (e ExitPolicy) String() string {
	switch e {
	case SingleExit:
		return "SingleExit"
	case PerSourcePort:
		return "PerSourcePort"
	case PerDestIP:
		return "PerDestIP"
	case RoundRobin:
		return "RoundRobin"
	}
	return fmt.Sprintf("ExitPolicy(%d)", uint8(e))
}

// IPv6Mode is how a NAT device handles IPv6.
type IPv6Mode uint8

const (
	// NoNAT gives the hosts public /64 addresses; the device is a stateful
	// firewall that filters by IPv6Config.Firewall.
	NoNAT IPv6Mode = iota
	// NPTv6 translates the prefix only (RFC 6296): the interface identifier
	// and the port are unchanged and IPv6Config.Firewall filters. It is
	// available on NATs attached to the core.
	NPTv6
	// NAT66 applies the IPv4 rules of the NATConfig (Mapping, Filtering,
	// PortAlloc) to IPv6, with a separate mapping table.
	NAT66
)

// String returns the mode name.
func (m IPv6Mode) String() string {
	switch m {
	case NoNAT:
		return "NoNAT"
	case NPTv6:
		return "NPTv6"
	case NAT66:
		return "NAT66"
	}
	return fmt.Sprintf("IPv6Mode(%d)", uint8(m))
}

// IPv6Config enables IPv6 behind a NAT device.
type IPv6Config struct {
	Mode IPv6Mode
	// Firewall filters inbound packets in the NoNAT and NPTv6 modes; NAT66
	// uses NATConfig.Filtering.
	Firewall Filtering
}

// ScanDefense makes a NAT react to scans like an intrusion detection system:
// once a threshold is exceeded the offending IP is banned for BanFor, in both
// directions. A zero threshold takes the default (300 ports, run 64, 500
// packets); a negative one disables that check. Zero
// durations take the defaults Window = 10 s and BanFor = 60 s.
type ScanDefense struct {
	// DistinctDstPorts bans an internal source IP that sends to more than this
	// many distinct ports of one destination IP within Window. It counts per
	// source IP, not per socket, which is stricter and closer to an IDS.
	DistinctDstPorts int
	// MaxConsecutiveRun bans an internal source IP whose destination ports
	// towards one IP form a run of more than this many consecutive ports,
	// ascending or descending. A repeated port neither extends nor breaks a
	// run; a pause of Window does.
	MaxConsecutiveRun int
	// UnsolicitedInbound bans a remote IP that sends more than this many
	// filtered inbound packets to the NAT within Window, the way a scanned
	// network blocks the scanner.
	UnsolicitedInbound int
	Window             time.Duration
	BanFor             time.Duration
}

// NoTimeout as NATConfig.MappingTimeout makes mappings never expire.
const NoTimeout time.Duration = -1

// NATConfig configures a NAT device. The zero value is a full cone NAT:
// endpoint-independent mapping and filtering with port preservation, IPv4 only.
type NATConfig struct {
	// Name labels the NAT in dumps; the default is "nat<N>" and duplicates
	// get a "#k" suffix.
	Name string

	Mapping   Mapping
	Filtering Filtering
	PortAlloc PortAlloc
	// PortStep is the step of Sequential and PreserveThenSequential; it may be
	// negative. The default is 1; 2 models a NAT that keeps the port parity.
	PortStep int
	// PortRange bounds the external ports; the default is [1024, 65535].
	// Calibration tests shrink it, for example to 1024 ports.
	PortRange [2]uint16
	// PortNoisePPS is the rate of a Poisson process of other subscribers
	// behind the same NAT that consume external ports: it advances the
	// Sequential cursor and occupies ports for MappingTimeout, which is what
	// makes port prediction miss in practice. The default is 0 (quiet).
	PortNoisePPS float64

	// MappingTimeout expires a mapping that has not sent for this long. The
	// default is 30 s; NoTimeout disables expiry.
	MappingTimeout time.Duration
	// RefreshOnInbound lets inbound packets refresh a mapping too. RFC 4787
	// REQ-6 only requires outbound refresh, which is the default.
	RefreshOnInbound bool

	// Hairpin loops packets sent to the NAT's own external endpoints back
	// into the LAN, with the sender's external endpoint as source.
	Hairpin bool
	// ExternalIPs are the external addresses of the translated families. When
	// empty, each translated family gets one automatic address; with more
	// than one address, ExitPolicy picks per mapping.
	ExternalIPs []netip.Addr
	ExitPolicy  ExitPolicy
	// MaxMappings bounds the mapping table; the least recently used mapping
	// is evicted when it is full. The default is 4096.
	MaxMappings int

	// ScanDefense enables scan detection; nil disables it.
	ScanDefense *ScanDefense
	// Uplink impairs the link between the NAT and its parent realm, in both
	// directions.
	Uplink LinkConfig
	// IPv6 enables IPv6 behind the NAT; nil means IPv4 only.
	IPv6 *IPv6Config

	// LANPrefix is the IPv4 LAN of a translating NAT. The default is
	// 10.N.0.0/16; [CGNAT] sets 100.64.0.0/10 on the carrier NAT so that the
	// home NAT's external address lies in the shared address space.
	LANPrefix netip.Prefix

	// Routes send chosen destinations through translations of their own,
	// as a router does that policy-routes them through a proxy or a
	// second uplink behind the same address:
	// a socket's mappings toward a route's destinations are apart from
	// its mappings on every other path, on the same external IPs, and the
	// route's own mapping, filtering and port allocation apply to them.
	// The first route whose Dst holds a destination takes it; the device's
	// own fields translate every other one. A rendezvous server on a route
	// of its own observes mappings the peer never sees — the
	// path-dependent mapping.
	Routes []Route
	// Classifier models an outbound protocol classifier on the device's
	// uplink; nil has none.
	Classifier *Classifier
}

// Route is one destination-dependent path through a NAT device
// (NATConfig.Routes). A packet leaves on the path of its destination, a
// reply included; an inbound packet is judged by the filtering of the path
// its mapping belongs to.
type Route struct {
	// Dst are the destinations the route takes.
	Dst       []netip.Prefix
	PortAlloc PortAlloc
	// Mapping is EIM, ADM or APDM; Identity counts as EIM.
	Mapping   Mapping
	Filtering Filtering
	// Proxy makes the route a proxy that relays each destination over an
	// upstream socket of its own: an inbound packet it admits opens no flow
	// for the reply, which leaves through the mapping toward its
	// destination — a new one if there is none (no conntrack flow is opened).
	Proxy bool
}

// Classifier models the outbound protocol classifier of some carrier
// networks: it inspects the first Window datagrams
// of each flow leaving the device — translated source endpoint ×
// destination endpoint — and drops every later datagram of a flow none of
// whose first Window datagrams it allowed. An allowed flow passes for good,
// until it has been idle for MappingTimeout. The classifier sits beyond
// the translation, so a dropped datagram still created or refreshed its
// mapping; hairpinned packets stay inside and are not inspected.
type Classifier struct {
	// Window is how many datagrams of a flow the classifier inspects; 0
	// means 5.
	Window int
	// Allow reports whether a datagram lets its flow through; nil allows
	// STUN messages ([IsSTUN]). It is called under the device's lock and
	// must not block.
	Allow func(payload []byte) bool
}

// defaultClassifierWindow is the inspected prefix of a flow measured on a
// real network.
const defaultClassifierWindow = 5

// Defaults of NATConfig and ScanDefense.
const (
	defaultMappingTimeout = 30 * time.Second
	defaultMaxMappings    = 4096
	defaultPortLo         = 1024
	defaultPortHi         = 65535

	defaultScanPorts       = 300
	defaultScanRun         = 64
	defaultScanUnsolicited = 500
	defaultScanWindow      = 10 * time.Second
	defaultScanBan         = 60 * time.Second
)

// normalized returns c with defaults applied and private copies of the
// referenced values, so that the caller may reuse its config.
func (c NATConfig) normalized() NATConfig {
	if c.PortStep == 0 {
		c.PortStep = 1
	}
	if c.PortRange == [2]uint16{} {
		c.PortRange = [2]uint16{defaultPortLo, defaultPortHi}
	}
	if c.PortRange[0] > c.PortRange[1] {
		c.PortRange[0], c.PortRange[1] = c.PortRange[1], c.PortRange[0]
	}
	c.PortRange[0] = max(c.PortRange[0], 1)
	switch {
	case c.MappingTimeout == 0:
		c.MappingTimeout = defaultMappingTimeout
	case c.MappingTimeout < 0:
		c.MappingTimeout = NoTimeout
	}
	if c.MaxMappings <= 0 {
		c.MaxMappings = defaultMaxMappings
	}
	c.PortAlloc = normalizedAlloc(c.PortAlloc)
	c.ExternalIPs = append([]netip.Addr(nil), c.ExternalIPs...)
	if c.ScanDefense != nil {
		sd := c.ScanDefense.normalized()
		c.ScanDefense = &sd
	}
	if c.IPv6 != nil {
		v := *c.IPv6
		c.IPv6 = &v
	}
	c.Routes = append([]Route(nil), c.Routes...)
	for i := range c.Routes {
		r := &c.Routes[i]
		r.Dst = append([]netip.Prefix(nil), r.Dst...)
		if r.Mapping == Identity {
			r.Mapping = EIM
		}
		r.PortAlloc = normalizedAlloc(r.PortAlloc)
	}
	if c.Classifier != nil {
		k := *c.Classifier
		if k.Window <= 0 {
			k.Window = defaultClassifierWindow
		}
		if k.Allow == nil {
			k.Allow = IsSTUN
		}
		c.Classifier = &k
	}
	return c
}

// normalizedAlloc keeps port 0 out of a Pool and maps an unknown strategy
// to Preserve.
func normalizedAlloc(a PortAlloc) PortAlloc {
	switch {
	case a.kind() == allocPool:
		lo, hi := a.bounds()
		return Pool(max(lo, 1), max(hi, 1))
	case a.kind() > PreserveThenRandom:
		return Preserve
	}
	return a
}

func (s ScanDefense) normalized() ScanDefense {
	s.DistinctDstPorts = threshold(s.DistinctDstPorts, defaultScanPorts)
	s.MaxConsecutiveRun = threshold(s.MaxConsecutiveRun, defaultScanRun)
	s.UnsolicitedInbound = threshold(s.UnsolicitedInbound, defaultScanUnsolicited)
	if s.Window <= 0 {
		s.Window = defaultScanWindow
	}
	if s.BanFor <= 0 {
		s.BanFor = defaultScanBan
	}
	return s
}

// threshold maps the ScanDefense convention (0 = default, < 0 = off) to the
// internal one (0 = off).
func threshold(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

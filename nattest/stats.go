package nattest

import (
	"net/netip"
	"sync/atomic"
	"time"
)

// dropReason says why a packet did not reach its destination.
type dropReason uint8

const (
	dropNone dropReason = iota
	dropLoss
	dropRate
	dropTTL
	dropMTU
	dropBan
	dropBlackhole
	dropNoHairpin
	dropNoPort
	dropNoRoute
	dropFiltered
	dropNoSocket
	dropInboxFull
	dropClosed
	dropClassified
	numDropReasons
)

// dropNames are the drop reasons in dumps.
var dropNames = [numDropReasons]string{
	"", "loss", "rate", "ttl", "mtu", "ban", "blackhole", "no_hairpin", "port_exhausted",
	"no_route", "filtered", "no_socket", "inbox_full", "closed", "classified",
}

func (r dropReason) String() string { return dropNames[r] }

// dropCounters counts drops by reason; links add to them without the owner's
// lock, hence the atomics.
type dropCounters [numDropReasons]atomic.Uint64

func (d *dropCounters) add(r dropReason) { d[r].Add(1) }

func (d *dropCounters) addN(r dropReason, k uint64) { d[r].Add(k) }

func (d *dropCounters) snapshot() DropStats {
	return DropStats{
		Loss:          d[dropLoss].Load(),
		Rate:          d[dropRate].Load(),
		TTL:           d[dropTTL].Load(),
		MTU:           d[dropMTU].Load(),
		Ban:           d[dropBan].Load(),
		Blackhole:     d[dropBlackhole].Load(),
		NoHairpin:     d[dropNoHairpin].Load(),
		PortExhausted: d[dropNoPort].Load(),
		NoRoute:       d[dropNoRoute].Load(),
		Closed:        d[dropClosed].Load(),
		Classified:    d[dropClassified].Load(),
	}
}

// DropStats counts the packets a NAT device, or the core in [NetStats],
// dropped, by reason. Inbound packets rejected by filtering are not drops of
// this kind; they are counted in NATStats.FilteredInbound.
type DropStats struct {
	Loss          uint64 `json:"loss,omitempty"`
	Rate          uint64 `json:"rate,omitempty"`
	TTL           uint64 `json:"ttl,omitempty"`
	MTU           uint64 `json:"mtu,omitempty"`
	Ban           uint64 `json:"ban,omitempty"`
	Blackhole     uint64 `json:"blackhole,omitempty"`
	NoHairpin     uint64 `json:"no_hairpin,omitempty"`     // sent to the NAT's own external address with Hairpin off
	PortExhausted uint64 `json:"port_exhausted,omitempty"` // no free external port in the range or pool
	NoRoute       uint64 `json:"no_route,omitempty"`       // destination address owned by nobody
	Closed        uint64 `json:"closed,omitempty"`         // in flight when the network was closed
	Classified    uint64 `json:"classified,omitempty"`     // cut by the uplink's protocol classifier (Classifier)
}

// plus returns the per-reason sums of d and o.
func (d DropStats) plus(o DropStats) DropStats {
	d.Loss += o.Loss
	d.Rate += o.Rate
	d.TTL += o.TTL
	d.MTU += o.MTU
	d.Ban += o.Ban
	d.Blackhole += o.Blackhole
	d.NoHairpin += o.NoHairpin
	d.PortExhausted += o.PortExhausted
	d.NoRoute += o.NoRoute
	d.Closed += o.Closed
	d.Classified += o.Classified
	return d
}

// Total returns the sum over all reasons.
func (d DropStats) Total() uint64 {
	return d.Loss + d.Rate + d.TTL + d.MTU + d.Ban + d.Blackhole + d.NoHairpin + d.PortExhausted + d.NoRoute + d.Closed + d.Classified
}

// HostStats is a snapshot of what a host sent and received over UDP. A packet
// is counted when the application's WriteTo accepts it, before any NAT or
// link sees it, whoever wrote it: snapshot the statistics before the
// application starts its own traffic on a handed-over socket.
type HostStats struct {
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`

	PeakPPS100ms int `json:"peak_pps_100ms"` // most packets sent within any sliding 100 ms
	PeakPPS1s    int `json:"peak_pps_1s"`    // most packets sent within any sliding second

	// DistinctDstPortsPerIP10s is the maximum, over destination IPs and over
	// time, of the distinct destination ports used towards one IP within a
	// sliding 10 s window.
	DistinctDstPortsPerIP10s int `json:"distinct_dst_ports_per_ip_10s"`
	// MaxConsecutiveRun is the longest run of consecutive destination ports,
	// ascending or descending, in the send sequence towards one IP. A repeat
	// neither extends nor breaks a run; a 10 s pause does.
	MaxConsecutiveRun int `json:"max_consecutive_run"`

	FirstSendAt time.Time                `json:"first_send_at,omitzero"`
	FirstSendTo map[netip.Addr]time.Time `json:"first_send_to,omitempty"` // first packet per destination IP

	SocketsOpened    uint64            `json:"sockets_opened"`
	SocketsClosed    uint64            `json:"sockets_closed"`
	SocketsByPurpose map[string]uint64 `json:"sockets_by_purpose,omitempty"` // sockets opened per purpose

	// WritesAfterHandover counts the calls made on a socket after
	// Host.MarkHandover, except those made through the conn MarkHandover
	// returned: every method but LocalAddr counts.
	WritesAfterHandover uint64 `json:"writes_after_handover"`
	InjectedWriteErrors uint64 `json:"injected_write_errors"`
	InjectedBindErrors  uint64 `json:"injected_bind_errors"`

	DroppedNoSocket  uint64 `json:"dropped_no_socket"`  // arrived for a port nobody is bound to
	DroppedInboxFull uint64 `json:"dropped_inbox_full"` // socket receive queue full

	// FirstByteHistogram and LenHistogram sum the packet shapes of all
	// sockets (see SocketStats); the first bytes are those of the packets
	// that are no STUN message.
	FirstByteHistogram [256]uint64    `json:"first_byte_histogram"`
	LenHistogram       map[int]uint64 `json:"len_histogram,omitempty"`

	// Sockets lists the host's sockets in the order they were opened: all
	// open ones and the most recently closed ones (up to 1024).
	Sockets []SocketStats `json:"sockets,omitempty"`
}

// SocketStats describes one socket and the shape of the packets sent through
// it. A socket belongs to one session of the library, so its shape is a
// per-session view: the first-byte histogram and ConstantOffsets show whether
// any byte position is constant within the session, and
// LenHistogram shows the session's length interval, which must differ from
// one session to the next. STUN messages ([IsSTUN]) are counted apart:
// their header bytes are the standard's, so the first bytes and the
// constant offsets cover the other packets only, and the flow counts show
// where the STUN messages went — first on each flow, as the library's
// openers, or later.
type SocketStats struct {
	Local   netip.AddrPort `json:"local"`
	Purpose string         `json:"purpose"`
	Closed  bool           `json:"closed,omitempty"`
	// Handover is set by Host.MarkHandover.
	Handover bool `json:"handover,omitempty"`
	// HopLimit is the last value set with SetHopLimit; 0 is the default.
	HopLimit int `json:"hop_limit"`

	PacketsSent        uint64         `json:"packets_sent"`
	BytesSent          uint64         `json:"bytes_sent"`
	FirstByteHistogram [256]uint64    `json:"first_byte_histogram"`
	LenHistogram       map[int]uint64 `json:"len_histogram,omitempty"`
	// ConstantOffsets lists the payload offsets at which every packet sent
	// so far carried the same byte, among the offsets present in every packet
	// and below 2048. It is nil until the second packet. Random bytes agree
	// at a given offset across k packets with probability 256^-(k-1), so an
	// assertion should require enough packets, for example 8.
	ConstantOffsets []int `json:"constant_offsets,omitempty"`
	// STUNPackets counts the packets that are STUN messages.
	STUNPackets uint64 `json:"stun_packets,omitempty"`
	// Flows counts the destinations the socket sent to.
	Flows int `json:"flows,omitempty"`
	// PlainFirst counts the flows whose first packet was no STUN message.
	PlainFirst int `json:"plain_first,omitempty"`
	// STUNAfterPlain counts the STUN messages sent on a flow that had
	// already carried a packet that is no STUN message.
	STUNAfterPlain uint64 `json:"stun_after_plain,omitempty"`
}

// NATStats is a snapshot of one NAT device's counters.
type NATStats struct {
	MappingsCreated uint64 `json:"mappings_created"`
	MappingsExpired uint64 `json:"mappings_expired"` // timed out, ExpireAll or Rebind
	MappingsEvicted uint64 `json:"mappings_evicted"` // least recently used, at MaxMappings
	MappingsActive  int    `json:"mappings_active"`

	PacketsOut uint64 `json:"packets_out"` // translated outbound, hairpin included
	PacketsIn  uint64 `json:"packets_in"`  // accepted inbound, hairpin included

	FilteredInbound  uint64 `json:"filtered_inbound"` // inbound without mapping or rejected by filtering
	HairpinDelivered uint64 `json:"hairpin_delivered"`
	ScanBans         uint64 `json:"scan_bans"`

	NoiseAllocs uint64 `json:"noise_allocs"` // ports taken by simulated other subscribers
	NoiseActive int    `json:"noise_active"` // of those, still held

	Dropped DropStats `json:"dropped"`
}

// NetStats aggregates the whole network.
type NetStats struct {
	PacketsSent      uint64 `json:"packets_sent"`
	PacketsDelivered uint64 `json:"packets_delivered"`

	FilteredInbound  uint64    `json:"filtered_inbound"`
	DroppedNoSocket  uint64    `json:"dropped_no_socket"`
	DroppedInboxFull uint64    `json:"dropped_inbox_full"`
	Dropped          DropStats `json:"dropped"` // the core and every NAT

	EventsScheduled uint64 `json:"events_scheduled"` // hops and pipe chunks that waited for a delay
	EventsPending   int    `json:"events_pending"`
}

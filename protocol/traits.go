package protocol

import "net/netip"

// Traits describes one family's NAT as orthogonal fields with confidences. It
// is produced by the classifier (internal/nat.Classify), carried in
// probe_report (client provisional) and probe_summary (server authoritative),
// and consumed by the planner through the predicates below.
type Traits struct {
	Family         Family    `json:"family,omitempty"` // omitted where the container names the family
	NoNAT          Tri       `json:"no_nat,omitempty"` // observed == local (IP and port)
	Mapping        Mapping   `json:"mapping,omitempty"`
	MappingConf    Conf      `json:"mapping_conf,omitempty"`
	Filtering      Filtering `json:"filtering,omitempty"`
	FilteringConf  Conf      `json:"filtering_conf,omitempty"`
	PortAlloc      PortAlloc `json:"port_alloc,omitempty"`
	PortAllocConf  Conf      `json:"port_alloc_conf,omitempty"`
	PortStep       int16     `json:"port_step,omitempty"`      // sequential: signed step
	PortVelocity   float32   `json:"port_velocity,omitempty"`  // other hosts' allocation rate, ports/s
	PortNoisy      bool      `json:"port_noisy,omitempty"`     // sequential: other hosts allocated between this side's probes, however short the baseline
	PortAnchor     uint16    `json:"port_anchor,omitempty"`    // last external port by creation order
	PortAnchorMs   int64     `json:"port_anchor_ms,omitempty"` // creation time on the server's monotonic axis
	PortRangeLo    uint16    `json:"port_lo,omitempty"`        // pool: estimated port block
	PortRangeHi    uint16    `json:"port_hi,omitempty"`
	FirstPreserved bool      `json:"first_preserved,omitempty"` // APDM but the first mapping kept the local port
	MultiExit      bool      `json:"multi_exit,omitempty"`      // one socket seen with >= 2 public IPs
	MultiHomed     bool      `json:"multi_homed,omitempty"`     // sockets leave through different public IPs
	Drifted        bool      `json:"drifted,omitempty"`
	Hairpin        Tri       `json:"hairpin,omitempty"`
	CGNAT          Tri       `json:"cgnat,omitempty"`
	CrossIP        bool      `json:"cross_ip,omitempty"` // checked against a source with another IP
	// PathDependent: a third party's STUN server saw the primary socket at
	// another port of the verified public IP than natprobe did, so the mapping
	// depends on the path and an endpoint-independent conclusion is not to be
	// trusted; planning treats the side as endpoint dependent. It never raises
	// a confidence.
	PathDependent bool           `json:"path_dependent,omitempty"`
	PublicIP      netip.Addr     `json:"public_ip,omitzero"`
	Observed      netip.AddrPort `json:"observed,omitzero"` // primary socket as seen by observer 0
	Samples       uint8          `json:"samples,omitempty"` // server observers with a valid sample
	Provisional   bool           `json:"provisional,omitempty"`
}

// TraitsUpdate is a punch-time correction of this side's traits
// (punch_result.traits; the only input of the server's traits memory).
// Nil fields are unchanged.
type TraitsUpdate struct {
	Family        Family       `json:"family"`
	Mapping       *Mapping     `json:"mapping,omitempty"`
	MappingConf   *Conf        `json:"mapping_conf,omitempty"`
	Filtering     *Filtering   `json:"filtering,omitempty"`
	FilteringConf *Conf        `json:"filtering_conf,omitempty"`
	PortStep      *int16       `json:"port_step,omitempty"`
	PortVelocity  *float32     `json:"port_velocity,omitempty"`
	Hairpin       *Tri         `json:"hairpin,omitempty"`
	Source        TraitsSource `json:"source"`
}

// TraitsSource says which evidence produced a TraitsUpdate.
type TraitsSource string

// Traits update sources.
const (
	TraitsSourcePeer    TraitsSource = "peer"
	TraitsSourceAlt     TraitsSource = "alt"
	TraitsSourceSTUN    TraitsSource = "stun"
	TraitsSourceHairpin TraitsSource = "hairpin"
)

// ObservedUsable reports whether Observed is a usable candidate on its own.
func (t Traits) ObservedUsable() bool {
	return t.NoNAT == TriTrue || (t.Mapping == MapEIM && t.MappingConf >= ConfMedium)
}

// NeedsSimultaneous reports whether the peer's packets must arrive after this
// side sent (port-dependent or unknown filtering).
func (t Traits) NeedsSimultaneous() bool {
	return t.Filtering == FiltPDF || t.Filtering == FiltUnknown
}

// AcceptsAfterIPContact reports whether packets from an IP this side has
// contacted get in whatever their source port.
func (t Traits) AcceptsAfterIPContact() bool {
	return t.Filtering == FiltEIF || t.Filtering == FiltADF || t.Filtering == FiltNotPDF
}

// EndpointDependent reports whether the external port depends on the
// destination.
func (t Traits) EndpointDependent() bool {
	return t.Mapping == MapADM || t.Mapping == MapAPDM || t.MultiExit
}

// Predictable reports whether the next external port of an
// endpoint-dependent mapping can be predicted — sequential, or a pool, with
// medium confidence or better. ADM counts as well as APDM.
func (t Traits) Predictable() bool {
	return (t.Mapping == MapAPDM || t.Mapping == MapADM) && t.PortAllocConf >= ConfMedium &&
		(t.PortAlloc == AllocSequential || t.PortAlloc == AllocPool)
}

// Uncertain reports whether the mapping conclusion is weak.
func (t Traits) Uncertain() bool { return t.MappingConf <= ConfLow }

// NeedsPeerPortPrediction reports whether this side must aim at predicted
// peer ports: the peer's port depends on the destination and this side
// filters by port.
func NeedsPeerPortPrediction(self, peer Traits) bool {
	return peer.EndpointDependent() && self.NeedsSimultaneous()
}

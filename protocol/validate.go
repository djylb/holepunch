package protocol

import (
	"fmt"
	"net/netip"

	"github.com/djylb/holepunch/controlwire"
)

// Structural limits checked by Validate. Lists over
// these limits are a protocol violation. Limits the receiver clamps instead
// are in normalize.go, and maps over their key limit are truncated
// there.
const (
	maxSessionID       = 64
	maxFeatures        = 16
	maxFeatureName     = 32
	maxName            = 64 // names, ids, codes, map keys
	maxImpl            = 64
	maxCapsFamilies    = 2
	maxPortMapMethods  = 3
	maxObservers       = 16
	maxReportFamilies  = 2
	maxReportSockets   = 6
	maxReportRows      = 16
	maxReportFilters   = 24
	maxReportSTUNRows  = 8
	maxLocalAddrs      = 16
	maxOverlayAddrs    = 2
	maxTransportMode   = 16
	maxTransportData   = 8 << 10
	maxViewFamilies    = 2
	maxEndpoints       = 12
	maxSharedFamilies  = 2
	maxLadder          = 16
	maxSides           = 2
	maxRound           = 8
	maxDetail          = 256
	maxProgressDetail  = 128
	maxMetaValue       = 64
	maxMetaTotal       = 1 << 10
	maxSeenFrom        = 4
	maxOutcomes        = 2
	maxTraitsUpdates   = 2
	maxWarn            = 8
	maxLowTTLHops      = 8
	maxPingSeq         = 8
	maxPortWindowWidth = 63
)

// ---- messages ----

// Validate implements Message.
func (m PunchStart) Validate() error {
	if err := checkSessionID(m.SessionID); err != nil {
		return err
	}
	if !m.Role.IsPunch() {
		return violation("role", "%q is not initiator or responder", m.Role)
	}
	if m.Token.IsZero() {
		return violation("token", "missing")
	}
	if m.Wire.RouteID.IsZero() {
		return violation("wire.route_id", "missing")
	}
	if err := m.Control.validate("control"); err != nil {
		return err
	}
	if err := m.Probe.validate("probe"); err != nil {
		return err
	}
	if !m.Mode.Valid() {
		return violation("mode", "unknown session mode %q", m.Mode)
	}
	if m.Policy != nil {
		return m.Policy.validate("policy")
	}
	return nil
}

// Validate implements Message.
func (m Ping) Validate() error { return checkPingSeq(m.Seq) }

// Validate implements Message. A pong answers a ping, so its seq is in the
// ping range too; the server ignores pongs whose seq it did not send.
func (m Pong) Validate() error { return checkPingSeq(m.Seq) }

func checkPingSeq(seq uint8) error {
	if seq < 1 || seq > maxPingSeq {
		return violation("seq", "%d not in [1, %d]", seq, maxPingSeq)
	}
	return nil
}

// Validate implements Message.
func (m ProbeReport) Validate() error {
	if err := checkOrigin(m.SessionID, m.Role); err != nil {
		return err
	}
	if err := m.Control.validate("control"); err != nil {
		return err
	}
	if err := m.Caps.validate("caps"); err != nil {
		return err
	}
	if n := len(m.Families); n < 1 || n > maxReportFamilies {
		return violation("families", "%d families, want 1..%d", n, maxReportFamilies)
	}
	for i, f := range m.Families {
		p := fmt.Sprintf("families[%d]", i)
		if err := f.validate(p); err != nil {
			return err
		}
		if err := checkDistinctFamily(p, f.Family, m.Families[:i], func(g FamilyReport) Family { return g.Family }); err != nil {
			return err
		}
	}
	if !m.Mode.Valid() {
		return violation("mode", "unknown session mode %q", m.Mode)
	}
	return checkTransport("transport", m.Transport.Mode, m.Transport.Data)
}

// Validate implements Message.
func (m ProbeSummary) Validate() error {
	if err := checkSessionID(m.SessionID); err != nil {
		return err
	}
	if err := m.Self.validate("self"); err != nil {
		return err
	}
	if err := m.Peer.validate("peer"); err != nil {
		return err
	}
	if err := m.Pair.validate("pair"); err != nil {
		return err
	}
	if err := checkTransport("transport", m.Transport.Mode, m.Transport.PeerData); err != nil {
		return err
	}
	return m.Plan.validate("plan")
}

// Validate implements Message.
func (m PunchReady) Validate() error {
	if err := checkOrigin(m.SessionID, m.Role); err != nil {
		return err
	}
	if n := len(m.Families); n < 1 || n > maxSides {
		return violation("families", "%d families, want 1..%d", n, maxSides)
	}
	for i, f := range m.Families {
		p := fmt.Sprintf("families[%d]", i)
		if !f.Family.Valid() {
			return violation(p+".family", "invalid family %q", f.Family)
		}
		if err := checkDistinctFamily(p, f.Family, m.Families[:i], func(g FamilyReady) Family { return g.Family }); err != nil {
			return err
		}
		if f.Sockets < 1 {
			return violation(p+".sockets", "no socket bound")
		}
		if f.PortMap != nil {
			if err := f.PortMap.validate(p+".port_map", f.Family); err != nil {
				return err
			}
		}
	}
	return nil
}

// Validate implements Message.
func (m PunchGo) Validate() error {
	if err := checkSessionID(m.SessionID); err != nil {
		return err
	}
	if err := checkRound("round", m.Round); err != nil {
		return err
	}
	if m.WindowMs == 0 {
		return violation("window_ms", "missing")
	}
	// Round 1's plan is probe_summary.plan.round1, the one the client bound
	// its sockets for before punch_ready; every later round's plan travels in
	// its go. A round-1 go carries one only as an
	// anchor update after an anchor refresh, which the client checks
	// against the summary's (RoundPlan.CheckAnchorUpdate).
	switch {
	case m.Round == 1 && m.Plan == nil:
		return nil
	case m.Plan == nil:
		return violation("plan", "required for round %d", m.Round)
	}
	if err := m.Plan.validate("plan"); err != nil {
		return err
	}
	if m.Plan.Round != m.Round {
		return violation("plan.round", "%d != round %d", m.Plan.Round, m.Round)
	}
	if m.Plan.WindowMs != m.WindowMs {
		// The same detail as a round-1 go that differs from the summary's
		// plan: a go's window must be its plan's.
		return violation("window", "%d != plan.window_ms %d", m.WindowMs, m.Plan.WindowMs)
	}
	return nil
}

// Validate implements Message.
func (m Progress) Validate() error {
	if err := checkOrigin(m.SessionID, m.Role); err != nil {
		return err
	}
	if !isName(m.Stage, maxName) {
		return violation("stage", "%q is not a stage name", m.Stage)
	}
	switch m.Status {
	case "", StatusOK, StatusFail, StatusInfo:
	default:
		return violation("status", "unknown status %q", m.Status)
	}
	if m.Round > maxRound {
		return violation("round", "%d > %d", m.Round, maxRound)
	}
	if len(m.Detail) > maxProgressDetail {
		return violation("detail", "%d bytes > %d", len(m.Detail), maxProgressDetail)
	}
	for k := range m.Counters {
		if !isName(k, maxName) {
			return violation("counters", "%q is not a counter name", k)
		}
	}
	return checkMeta("meta", m.Meta, maxProgressMap)
}

// Validate implements Message. An empty or unknown code is valid: the client
// maps it with AbortReason.
func (m Abort) Validate() error {
	if err := checkSessionID(m.SessionID); err != nil {
		return err
	}
	if !m.By.Valid() {
		return violation("by", "unknown role %q", m.By)
	}
	if m.Code != "" && !isName(string(m.Code), maxName) {
		return violation("code", "%q is not a code", m.Code)
	}
	if len(m.Detail) > maxDetail {
		return violation("detail", "%d bytes > %d", len(m.Detail), maxDetail)
	}
	return nil
}

// Validate implements Message.
func (m RoundResult) Validate() error {
	if err := checkOrigin(m.SessionID, m.Role); err != nil {
		return err
	}
	if err := checkRound("round", m.Round); err != nil {
		return err
	}
	switch m.Status {
	case RoundWindowEnd, RoundBudgetExhausted, RoundConfirmed, RoundFatal:
	default:
		return violation("status", "unknown status %q", m.Status)
	}
	if m.Status == RoundFatal && m.Code == "" {
		return violation("code", "required for status fatal")
	}
	if m.Code != "" && !m.Code.Known() {
		return violation("code", "unknown reason %q", m.Code)
	}
	if len(m.Families) > maxOutcomes {
		return violation("families", "%d > %d", len(m.Families), maxOutcomes)
	}
	for i, f := range m.Families {
		p := fmt.Sprintf("families[%d]", i)
		if !f.Family.Valid() {
			return violation(p+".family", "invalid family %q", f.Family)
		}
		if err := checkDistinctFamily(p, f.Family, m.Families[:i], func(g FamilyOutcome) Family { return g.Family }); err != nil {
			return err
		}
		if len(f.SeenFrom) > maxSeenFrom {
			return violation(p+".seen_from", "%d > %d", len(f.SeenFrom), maxSeenFrom)
		}
		for j, a := range f.SeenFrom {
			if err := checkEndpoint(fmt.Sprintf("%s.seen_from[%d]", p, j), a, f.Family); err != nil {
				return err
			}
		}
		if r := f.Remap; r != nil {
			if err := checkEndpoint(p+".remap.a", r.Observed, f.Family); err != nil {
				return err
			}
			if r.Cookie == 0 {
				return violation(p+".remap.c", "a remap echoes a nonzero cookie")
			}
		}
	}
	if m.Status == RoundConfirmed && m.Path == nil {
		return violation("path", "required for status confirmed")
	}
	if m.Path != nil {
		return m.Path.validate("path", false)
	}
	return nil
}

// Validate implements Message.
func (m PunchResult) Validate() error {
	if err := checkOrigin(m.SessionID, m.Role); err != nil {
		return err
	}
	if !m.Phase.Valid() {
		return violation("phase", "unknown phase %q", m.Phase)
	}
	switch {
	case m.OK && m.Path == nil:
		return violation("path", "required when ok")
	case !m.OK && m.Code == "":
		return violation("code", "required when not ok")
	case m.Code != "" && !m.Code.Known():
		return violation("code", "unknown reason %q", m.Code)
	}
	if m.Path != nil {
		if err := m.Path.validate("path", m.OK); err != nil {
			return err
		}
	}
	switch {
	case len(m.ExtraPaths) > 0 && !m.OK:
		return violation("extra_paths", "only when ok")
	case len(m.ExtraPaths) > MaxPaths-1:
		return violation("extra_paths", "%d > %d", len(m.ExtraPaths), MaxPaths-1)
	}
	for i, p := range m.ExtraPaths {
		if err := p.validate(fmt.Sprintf("extra_paths[%d]", i), true); err != nil {
			return err
		}
	}
	if len(m.Detail) > maxDetail {
		return violation("detail", "%d bytes > %d", len(m.Detail), maxDetail)
	}
	for k := range m.Stats.Drops {
		if !isName(k, maxName) {
			return violation("stats.drops", "%q is not a drop name", k)
		}
	}
	if len(m.Traits) > maxTraitsUpdates {
		return violation("traits", "%d > %d", len(m.Traits), maxTraitsUpdates)
	}
	for i, u := range m.Traits {
		p := fmt.Sprintf("traits[%d]", i)
		if err := u.validate(p); err != nil {
			return err
		}
		if err := checkDistinctFamily(p, u.Family, m.Traits[:i], func(g TraitsUpdate) Family { return g.Family }); err != nil {
			return err
		}
	}
	if len(m.Warn) > maxWarn {
		return violation("warn", "%d > %d", len(m.Warn), maxWarn)
	}
	for i, w := range m.Warn {
		if !isName(w, maxName) {
			return violation(fmt.Sprintf("warn[%d]", i), "%q is not a warning name", w)
		}
	}
	return nil
}

// ---- origin ----

// CheckOrigin verifies a received message against its link: every message
// except ping/pong must carry the link's session_id (else protocol_violation,
// detail session_mismatch), and a client-to-server message must carry the
// link's role (detail role_mismatch). A client passes role "": server messages
// carry no sender role. m may be a message value or pointer.
func CheckOrigin(m Message, sessionID string, role Role) error {
	o, ok := m.(interface{ origin() (string, Role, bool) })
	if !ok {
		return nil // ping and pong are link-level
	}
	sid, sender, fromClient := o.origin()
	if sid != sessionID {
		return &ValidationError{Reason: ReasonProtocolViolation, Detail: "session_mismatch",
			Msg: fmt.Sprintf("session %q on link %q", sid, sessionID)}
	}
	if role != "" && fromClient && sender != role {
		return &ValidationError{Reason: ReasonProtocolViolation, Detail: "role_mismatch",
			Msg: fmt.Sprintf("role %q on a %s link", sender, role)}
	}
	return nil
}

func (m PunchStart) origin() (string, Role, bool)   { return m.SessionID, "", false }
func (m ProbeSummary) origin() (string, Role, bool) { return m.SessionID, "", false }
func (m PunchGo) origin() (string, Role, bool)      { return m.SessionID, "", false }
func (m Abort) origin() (string, Role, bool)        { return m.SessionID, "", false }
func (m ProbeReport) origin() (string, Role, bool)  { return m.SessionID, m.Role, true }
func (m PunchReady) origin() (string, Role, bool)   { return m.SessionID, m.Role, true }
func (m Progress) origin() (string, Role, bool)     { return m.SessionID, m.Role, true }
func (m RoundResult) origin() (string, Role, bool)  { return m.SessionID, m.Role, true }
func (m PunchResult) origin() (string, Role, bool)  { return m.SessionID, m.Role, true }

// An assist is checked as a client message on a server link: a client's
// assist must carry the link's role. A client passes role "", which skips
// the check for the server's forwarded assists.
func (m Assist) origin() (string, Role, bool) { return m.SessionID, m.Role, true }

// ---- sub-structures ----

func (c ControlSpec) validate(path string) error {
	if c.Version != controlwire.Version {
		return &ValidationError{Reason: ReasonControlVersionMismatch, Detail: path + ".version",
			Msg: fmt.Sprintf("%d != frame major %d", c.Version, controlwire.Version)}
	}
	if len(c.Features) > maxFeatures {
		return violation(path+".features", "%d > %d", len(c.Features), maxFeatures)
	}
	for i, f := range c.Features {
		if !f.Valid() {
			return violation(fmt.Sprintf("%s.features[%d]", path, i), "bad feature name %q", f)
		}
	}
	return nil
}

func (c ClientCaps) validate(path string) error {
	if len(c.Impl) > maxImpl {
		return violation(path+".impl", "%d bytes > %d", len(c.Impl), maxImpl)
	}
	if len(c.Families) > maxCapsFamilies {
		return violation(path+".families", "%d > %d", len(c.Families), maxCapsFamilies)
	}
	for i, f := range c.Families {
		p := fmt.Sprintf("%s.families[%d]", path, i)
		if !f.Family.Valid() {
			return violation(p+".family", "invalid family %q", f.Family)
		}
		if err := checkDistinctFamily(p, f.Family, c.Families[:i], func(g FamilyCaps) Family { return g.Family }); err != nil {
			return err
		}
	}
	if len(c.PortMap) > maxPortMapMethods {
		return violation(path+".port_map", "%d > %d", len(c.PortMap), maxPortMapMethods)
	}
	for i, m := range c.PortMap {
		if !m.Valid() {
			return violation(fmt.Sprintf("%s.port_map[%d]", path, i), "unknown method %q", m)
		}
	}
	return nil
}

// validate accepts an empty observer list: the client reports it as
// no_probe_endpoint, not as a malformed message.
func (p ProbeSpec) validate(path string) error {
	if p.V != ProbeSpecVersion {
		return &ValidationError{Reason: ReasonControlVersionMismatch, Detail: "probe_v",
			Msg: fmt.Sprintf("probe spec v%d, want v%d", p.V, ProbeSpecVersion)}
	}
	if len(p.Observers) > maxObservers {
		return violation(path+".observers", "%d > %d", len(p.Observers), maxObservers)
	}
	for i, o := range p.Observers {
		q := fmt.Sprintf("%s.observers[%d]", path, i)
		if err := checkEndpoint(q+".addr", o.Addr, ""); err != nil {
			return err
		}
		for _, prev := range p.Observers[:i] {
			if prev.ID == o.ID {
				return violation(q+".id", "duplicate observer id %d", o.ID)
			}
		}
	}
	if len(p.STUN) > MaxProbeSTUN {
		return violation(path+".stun", "%d > %d", len(p.STUN), MaxProbeSTUN)
	}
	for i, s := range p.STUN {
		if err := checkEndpoint(fmt.Sprintf("%s.stun[%d]", path, i), s, ""); err != nil {
			return err
		}
	}
	return nil
}

func (p Policy) validate(path string) error {
	if err := p.Budget.validate(path + ".budget"); err != nil {
		return err
	}
	if len(p.LowTTLHops) > maxLowTTLHops {
		return violation(path+".low_ttl_hops", "%d > %d", len(p.LowTTLHops), maxLowTTLHops)
	}
	return nil
}

func (b Budget) validate(path string) error {
	if b.Birthday != "" && !b.Birthday.Valid() {
		return violation(path+".birthday", "unknown tier %q", b.Birthday)
	}
	return nil
}

func (f FamilyReport) validate(path string) error {
	if !f.Family.Valid() {
		return violation(path+".family", "invalid family %q", f.Family)
	}
	if f.Failure != "" && !f.Failure.Known() {
		return violation(path+".failure", "unknown reason %q", f.Failure)
	}
	if len(f.Sockets) > maxReportSockets {
		return violation(path+".sockets", "%d > %d", len(f.Sockets), maxReportSockets)
	}
	for i, s := range f.Sockets {
		q := fmt.Sprintf("%s.sockets[%d]", path, i)
		switch s.Kind {
		case SocketPrimary, SocketSecond, SocketSibling:
		default:
			return violation(q+".kind", "unknown socket kind %q", s.Kind)
		}
		if err := checkEndpoint(q+".local", s.Local, f.Family); err != nil {
			return err
		}
		if len(s.Rows) > maxReportRows {
			return violation(q+".rows", "%d > %d", len(s.Rows), maxReportRows)
		}
		for j, r := range s.Rows {
			if err := checkOptionalEndpoint(fmt.Sprintf("%s.rows[%d].a", q, j), r.Observed, f.Family); err != nil {
				return err
			}
		}
	}
	if len(f.Filters) > maxReportFilters {
		return violation(path+".filters", "%d > %d", len(f.Filters), maxReportFilters)
	}
	if len(f.STUN) > maxReportSTUNRows {
		return violation(path+".stun", "%d > %d", len(f.STUN), maxReportSTUNRows)
	}
	for j, r := range f.STUN {
		if err := checkOptionalEndpoint(fmt.Sprintf("%s.stun[%d].a", path, j), r.Observed, f.Family); err != nil {
			return err
		}
	}
	if f.PortMap != nil {
		if err := f.PortMap.validate(path+".port_map", f.Family); err != nil {
			return err
		}
	}
	if len(f.LocalAddrs) > maxLocalAddrs {
		return violation(path+".local_addrs", "%d > %d", len(f.LocalAddrs), maxLocalAddrs)
	}
	for i, a := range f.LocalAddrs {
		if !f.Family.Matches(a) {
			return violation(fmt.Sprintf("%s.local_addrs[%d]", path, i), "%v is not a %s address", a, f.Family)
		}
	}
	if len(f.Overlay) > maxOverlayAddrs {
		return violation(path+".overlay", "%d > %d", len(f.Overlay), maxOverlayAddrs)
	}
	for i, a := range f.Overlay {
		if !f.Family.Matches(a) {
			return violation(fmt.Sprintf("%s.overlay[%d]", path, i), "%v is not a %s address", a, f.Family)
		}
	}
	return f.Traits.validate(path+".traits", f.Family)
}

func (r PortMapReport) validate(path string, fam Family) error {
	if !r.Method.Valid() {
		return violation(path+".method", "unknown method %q", r.Method)
	}
	if err := checkOptionalEndpoint(path+".external", r.External, fam); err != nil {
		return err
	}
	return checkOptionalEndpoint(path+".internal", r.Internal, fam)
}

// validate checks traits carried inside a family-scoped container: the family
// field, when present, must be that family.
func (t Traits) validate(path string, fam Family) error {
	switch {
	case t.Family != "" && t.Family != fam:
		return violation(path+".family", "%q inside a %s container", t.Family, fam)
	case !t.NoNAT.Valid() || !t.Hairpin.Valid() || !t.CGNAT.Valid():
		return violation(path, "invalid tri-state")
	case !t.Mapping.Valid() || !t.Filtering.Valid() || !t.PortAlloc.Valid():
		return violation(path, "invalid behaviour value")
	case !t.MappingConf.Valid() || !t.FilteringConf.Valid() || !t.PortAllocConf.Valid():
		return violation(path, "invalid confidence")
	case !finite(t.PortVelocity):
		return violation(path+".port_velocity", "not finite")
	case t.PortRangeHi != 0 && t.PortRangeLo > t.PortRangeHi:
		return violation(path+".port_lo", "%d > port_hi %d", t.PortRangeLo, t.PortRangeHi)
	case t.PublicIP.IsValid() && !fam.Matches(t.PublicIP):
		return violation(path+".public_ip", "%v is not a %s address", t.PublicIP, fam)
	}
	return checkOptionalEndpoint(path+".observed", t.Observed, fam)
}

func (u TraitsUpdate) validate(path string) error {
	if !u.Family.Valid() {
		return violation(path+".family", "invalid family %q", u.Family)
	}
	switch u.Source {
	case TraitsSourcePeer, TraitsSourceAlt, TraitsSourceSTUN, TraitsSourceHairpin:
	default:
		return violation(path+".source", "unknown source %q", u.Source)
	}
	if (u.Mapping != nil && !u.Mapping.Valid()) || (u.Filtering != nil && !u.Filtering.Valid()) ||
		(u.MappingConf != nil && !u.MappingConf.Valid()) || (u.FilteringConf != nil && !u.FilteringConf.Valid()) ||
		(u.Hairpin != nil && !u.Hairpin.Valid()) {
		return violation(path, "invalid enumeration value")
	}
	if u.PortVelocity != nil && !finite(*u.PortVelocity) {
		return violation(path+".port_velocity", "not finite")
	}
	return nil
}

func (v PeerView) validate(path string) error {
	if len(v.Families) > maxViewFamilies {
		return violation(path+".families", "%d > %d", len(v.Families), maxViewFamilies)
	}
	for i, f := range v.Families {
		q := fmt.Sprintf("%s.families[%d]", path, i)
		if !f.Family.Valid() {
			return violation(q+".family", "invalid family %q", f.Family)
		}
		if err := checkDistinctFamily(q, f.Family, v.Families[:i], func(g FamilyView) Family { return g.Family }); err != nil {
			return err
		}
		if err := f.Traits.validate(q+".traits", f.Family); err != nil {
			return err
		}
		if len(f.Endpoints) > maxEndpoints {
			return violation(q+".endpoints", "%d > %d", len(f.Endpoints), maxEndpoints)
		}
		for j, e := range f.Endpoints {
			r := fmt.Sprintf("%s.endpoints[%d]", q, j)
			if err := checkEndpoint(r+".addr", e.Addr, f.Family); err != nil {
				return err
			}
			switch e.Source {
			case EndpointServer, EndpointSecond, EndpointSibling, EndpointSTUN, EndpointPortmap, EndpointLAN, EndpointOverlay, EndpointLocalPort:
			default:
				return violation(r+".src", "unknown source %q", e.Source)
			}
		}
	}
	return nil
}

func (p PairFacts) validate(path string) error {
	if len(p.SharedFamilies) > maxSharedFamilies {
		return violation(path+".shared_families", "%d > %d", len(p.SharedFamilies), maxSharedFamilies)
	}
	for i, f := range p.SharedFamilies {
		q := fmt.Sprintf("%s.shared_families[%d]", path, i)
		if !f.Valid() {
			return violation(q, "invalid family %q", f)
		}
		for _, g := range p.SharedFamilies[:i] {
			if g == f {
				return violation(q, "duplicate %s", f)
			}
		}
	}
	for _, m := range []map[Family]bool{p.SamePublicIP, p.LikelySameLAN, p.SharedOverlay, p.Unverified} {
		for f := range m {
			if !f.Valid() {
				return violation(path, "invalid family key %q", f)
			}
		}
	}
	for r := range p.ProbeRTTMs {
		if !r.IsPunch() {
			return violation(path+".probe_rtt_ms", "invalid role key %q", r)
		}
	}
	for r := range p.ClockOffsetMs {
		if !r.IsPunch() {
			return violation(path+".clock_offset_ms", "invalid role key %q", r)
		}
	}
	return nil
}

func (p PlanSpec) validate(path string) error {
	if err := checkID(path+".id", p.ID); err != nil {
		return err
	}
	if p.RoundsMax < 1 {
		return violation(path+".rounds_max", "must be >= 1")
	}
	if p.PairClass != "" && !isName(p.PairClass, maxName) {
		return violation(path+".pair_class", "%q is not a name", p.PairClass)
	}
	if len(p.Ladder) > maxLadder {
		return violation(path+".ladder", "%d > %d", len(p.Ladder), maxLadder)
	}
	for i, l := range p.Ladder {
		if !isName(l, maxName) {
			return violation(fmt.Sprintf("%s.ladder[%d]", path, i), "%q is not a variant name", l)
		}
	}
	if err := p.Budget.validate(path + ".budget"); err != nil {
		return err
	}
	if err := p.Round1.validate(path + ".round1"); err != nil {
		return err
	}
	if p.Round1.Round != 1 {
		return violation(path+".round1.round", "%d, want 1", p.Round1.Round)
	}
	if !p.Mode.Valid() {
		return violation(path+".mode", "unknown session mode %q", p.Mode)
	}
	if !p.Advice.Valid() {
		return violation(path+".advice", "unknown advice %q", p.Advice)
	}
	return nil
}

func (r RoundPlan) validate(path string) error {
	if err := checkRound(path+".round", r.Round); err != nil {
		return err
	}
	if !isName(r.Variant, maxName) {
		return violation(path+".variant", "%q is not a variant name", r.Variant)
	}
	if !r.Budget.Valid() {
		return violation(path+".budget", "unknown budget class %q", r.Budget)
	}
	if r.WindowMs == 0 {
		return violation(path+".window_ms", "missing")
	}
	if n := len(r.Sides); n < 1 || n > maxSides {
		return violation(path+".sides", "%d sides, want 1..%d", n, maxSides)
	}
	for i, s := range r.Sides {
		q := fmt.Sprintf("%s.sides[%d]", path, i)
		if err := s.validate(q); err != nil {
			return err
		}
		if err := checkDistinctFamily(q, s.Family, r.Sides[:i], func(g FamilySide) Family { return g.Family }); err != nil {
			return err
		}
	}
	return nil
}

func (s FamilySide) validate(path string) error {
	if !s.Family.Valid() {
		return violation(path+".family", "invalid family %q", s.Family)
	}
	switch s.Role {
	case SideSender, SideReceiver, SideBoth, SideReplyOnly:
	default:
		return violation(path+".role", "unknown role %q", s.Role)
	}
	if s.Sockets < 1 {
		return violation(path+".sockets", "must be >= 1")
	}
	if len(s.Stages) < 1 {
		return violation(path+".stages", "no stage")
	}
	var fresh, freshPeer int
	for i, st := range s.Stages {
		if err := st.validate(fmt.Sprintf("%s.stages[%d]", path, i), s.Family); err != nil {
			return err
		}
		switch st.Kind {
		case StageFresh:
			fresh++
		case StageFreshPeer:
			freshPeer++
		}
	}
	// Both stages draw their ports from the round's pair seed alone, so a
	// side has at most one of each (StageFresh).
	if fresh > 1 || freshPeer > 1 {
		return violation(path+".stages", "more than one fresh or fresh_peer stage")
	}
	return nil
}

// validate checks a stage of a fam side: the fields its kind needs, and that
// every address is of that family.
func (s Stage) validate(path string, fam Family) error {
	switch s.Kind {
	case StageDirect:
		if len(s.Targets) == 0 {
			return violation(path+".targets", "required for direct")
		}
	case StagePredict:
		switch {
		case s.Anchor == 0:
			return violation(path+".anchor", "required for predict")
		case s.Span == 0:
			return violation(path+".span", "required for predict")
		case len(s.Steps) == 0:
			return violation(path+".steps", "required for predict")
		}
	case StageRandom:
		if s.Count == 0 {
			return violation(path+".count", "required for random")
		}
	case StageFresh:
		switch {
		case s.Count == 0:
			return violation(path+".count", "required for fresh")
		case len(s.Targets) == 0 == !s.IP.IsValid():
			return violation(path+".targets", "fresh needs either targets or ip")
		}
	case StageFreshPeer:
		switch {
		case s.Count == 0:
			return violation(path+".count", "required for fresh_peer")
		case len(s.Targets) > 0:
			return violation(path+".targets", "not allowed for fresh_peer")
		}
	case StageReplyOnly:
	default:
		return violation(path+".kind", "unknown stage kind %q", s.Kind)
	}
	if s.Kind == StagePredict || s.Kind == StageRandom || s.Kind == StageFreshPeer || s.Kind == StageFresh && s.IP.IsValid() {
		if !fam.Matches(s.IP) {
			return violation(path+".ip", "%v is not a %s address", s.IP, fam)
		}
	}
	for i, t := range s.Targets {
		if err := checkEndpoint(fmt.Sprintf("%s.targets[%d]", path, i), t, fam); err != nil {
			return err
		}
	}
	if s.Hi != 0 && s.Lo > s.Hi {
		return violation(path+".lo", "%d > hi %d", s.Lo, s.Hi)
	}
	if s.Pair && s.Kind != StagePredict {
		return violation(path+".pair", "only a predict stage is paired")
	}
	return nil
}

func (p PathInfo) validate(path string, needConfirmedBy bool) error {
	if !p.Family.Valid() {
		return violation(path+".family", "invalid family %q", p.Family)
	}
	if err := checkEndpoint(path+".local", p.Local, p.Family); err != nil {
		return err
	}
	if err := checkEndpoint(path+".remote", p.Remote, p.Family); err != nil {
		return err
	}
	if err := checkRound(path+".round", p.Round); err != nil {
		return err
	}
	switch p.CandKind {
	case CandDirect, CandPredicted, CandRandom, CandBirthday, CandPeerReflexive, CandLAN, CandTargets, CandOverlay:
	default:
		return violation(path+".cand_kind", "unknown candidate kind %q", p.CandKind)
	}
	if !p.Kind.Valid() {
		return violation(path+".kind", "unknown path kind %q", p.Kind)
	}
	switch p.ConfirmedBy {
	case ConfirmedByAck, ConfirmedByUpperLayer, ConfirmedByQuiet, ConfirmedByReady:
	case "":
		if needConfirmedBy {
			return violation(path+".confirmed_by", "required")
		}
	default:
		return violation(path+".confirmed_by", "unknown evidence %q", p.ConfirmedBy)
	}
	return nil
}

// ---- helpers ----

func checkSessionID(s string) error { return checkID("session_id", s) }

// checkID accepts 1..64 bytes of [A-Za-z0-9_-] (session ids, plan ids).
func checkID(path, s string) error {
	if len(s) < 1 || len(s) > maxSessionID {
		return violation(path, "%d bytes, want 1..%d", len(s), maxSessionID)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' || c == '-') {
			return violation(path, "byte %q outside [A-Za-z0-9_-]", c)
		}
	}
	return nil
}

func checkOrigin(sessionID string, role Role) error {
	if err := checkSessionID(sessionID); err != nil {
		return err
	}
	if !role.IsPunch() {
		return violation("role", "%q is not initiator or responder", role)
	}
	return nil
}

func checkRound(path string, r uint8) error {
	if r < 1 || r > maxRound {
		return violation(path, "%d not in [1, %d]", r, maxRound)
	}
	return nil
}

func checkTransport(path, mode, data string) error {
	if len(mode) > maxTransportMode {
		return violation(path+".mode", "%d bytes > %d", len(mode), maxTransportMode)
	}
	if len(data) > maxTransportData {
		return violation(path, "data of %d bytes > %d", len(data), maxTransportData)
	}
	return nil
}

// checkMeta checks caller pass-through metadata: keys of
// 1..64 bytes, values of at most 64 bytes, at most 1 KiB in all. Keys beyond
// maxKeys are not an error; Normalize truncates them, and only the kept keys
// count towards the total.
func checkMeta(path string, meta map[string]string, maxKeys int) error {
	for k, v := range meta {
		if len(k) == 0 || len(k) > maxName {
			return violation(path, "key of %d bytes", len(k))
		}
		if len(v) > maxMetaValue {
			return violation(path+"."+k, "value of %d bytes > %d", len(v), maxMetaValue)
		}
	}
	total := 0
	for _, k := range keptKeys(meta, maxKeys) {
		total += len(k) + len(meta[k])
	}
	if total > maxMetaTotal {
		return violation(path, "%d bytes in all > %d", total, maxMetaTotal)
	}
	return nil
}

// checkEndpoint requires a usable unicast ip:port of family fam ("" = any).
func checkEndpoint(path string, a netip.AddrPort, fam Family) error {
	ip := a.Addr()
	switch {
	case !a.IsValid() || a.Port() == 0 || ip.IsUnspecified() || ip.IsMulticast():
		return violation(path, "%v is not a usable ip:port", a)
	case fam == "" && FamilyOf(ip) == "":
		return violation(path, "%v is an IPv4-mapped address", a)
	case fam != "" && !fam.Matches(ip):
		return violation(path, "%v is not a %s address", a, fam)
	}
	return nil
}

func checkOptionalEndpoint(path string, a netip.AddrPort, fam Family) error {
	if a == (netip.AddrPort{}) {
		return nil
	}
	return checkEndpoint(path, a, fam)
}

// checkDistinctFamily rejects a family that already appears in earlier.
func checkDistinctFamily[T any](path string, fam Family, earlier []T, familyOf func(T) Family) error {
	for _, e := range earlier {
		if familyOf(e) == fam {
			return violation(path+".family", "duplicate %s", fam)
		}
	}
	return nil
}

// isName reports whether s matches [a-z][a-z0-9_]{0,max-1}.
func isName(s string, max int) bool {
	if len(s) < 1 || len(s) > max || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func finite(f float32) bool { return f-f == 0 }

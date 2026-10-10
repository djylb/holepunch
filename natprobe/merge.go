package natprobe

import (
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
)

// MergeDiag counts what the merge did not take at face value.
type MergeDiag struct {
	Unverified        int // client rows claiming an answer the server never recorded (dropped)
	CookieMissing     int // server-recorded rows whose cookie was not echoed correctly (not verified)
	Conflicts         int // the client's ack value ≠ the server's record (SNAT proxy, wrong advertised address)
	RejectedEndpoints int // self-reported STUN and port-mapping addresses that failed the constraints
	// STUNConflicts counts admitted STUN values that contradict natprobe's
	// own records (nat.ObsTable.STUNConflicts): STUN is a hint, recorded
	// but never classified against natprobe.
	STUNConflicts int
	MemoryPanics  int // TraitsMemory.Apply panicked; its advice was ignored
}

// Merge computes the server's authoritative view of role from the role's
// probe_report:
//   - natprobe's records replace the client's values, and client rows the
//     server never saw are dropped — except that a row the client reports
//     unanswered keeps its place in the send order, without a value;
//   - only rows whose cookie was echoed become verified endpoints;
//   - records the client did not report (ack lost) are classified anyway;
//   - the filtering uses the server's sent counts and the client's seen
//     counts, the latter capped by the former;
//   - self-reported STUN and port-mapping addresses must pass the endpoint
//     constraints; an admitted STUN value is a hint that can neither raise
//     natprobe's conclusions above Medium nor overturn them; one that
//     contradicts them is counted (MergeDiag.STUNConflicts), and one
//     at another port of natprobe's single mapping marks the traits
//     PathDependent;
//   - the overlay addresses the client reported become overlay endpoints at
//     its primary socket's port;
//   - the traits memory may refine the result (mem nil: no memory), and the
//     traits are final (Provisional false).
//
// Only key.ClientKey is used; the family and the public IP of each family
// complete the key. The report must come from role of this session
// (protocol.CheckOrigin), else Merge returns that validation error. Merge
// is safe for concurrent use and never panics.
func (h *Handle) Merge(role protocol.Role, rep protocol.ProbeReport, mem TraitsMemory, key TraitsKey) (view protocol.PeerView, diag MergeDiag, err error) {
	if h == nil || h.e == nil {
		return view, diag, errors.New("natprobe: nil handle")
	}
	if !role.IsPunch() {
		return view, diag, &protocol.ValidationError{Reason: protocol.ReasonInvalidArgument, Detail: "role", Msg: "merge role must be initiator or responder"}
	}
	if perr := life.Safe("natprobe/merge", func() { view, diag, err = h.merge(role, rep, mem, key) }); perr != nil {
		return protocol.PeerView{}, MergeDiag{}, perr
	}
	return view, diag, err
}

func (h *Handle) merge(role protocol.Role, rep protocol.ProbeReport, mem TraitsMemory, key TraitsKey) (protocol.PeerView, MergeDiag, error) {
	var diag MergeDiag
	view := protocol.PeerView{Families: []protocol.FamilyView{}}
	if err := protocol.CheckOrigin(rep, h.e.id, role); err != nil {
		return view, diag, err
	}
	obs := h.Observations(role)
	var seen []protocol.Family
	for _, fr := range rep.Families {
		if !fr.Family.Valid() || slices.Contains(seen, fr.Family) {
			continue
		}
		seen = append(seen, fr.Family)
		view.Families = append(view.Families, h.mergeFamily(fr, obs, mem, key, &diag))
	}
	return view, diag, nil
}

// slotKey names an observation slot of one role.
type slotKey struct{ sock, obs uint8 }

// familyMerge is the state of merging one reported family.
type familyMerge struct {
	h         *Handle
	f         protocol.Family
	t         *nat.ObsTable
	srv       []ServerObservation // the role's slots of this family
	socks     []nat.SocketMeta
	alt       map[uint8]bool   // observers of the alt group, as the slots show them
	answered  map[slotKey]bool // slots the client got an ack for
	conflicts int              // client ack values that contradict the server's records
	diag      *MergeDiag
}

func (h *Handle) mergeFamily(fr protocol.FamilyReport, obs []ServerObservation, mem TraitsMemory, key TraitsKey, diag *MergeDiag) protocol.FamilyView {
	m := &familyMerge{h: h, f: fr.Family, alt: map[uint8]bool{}, answered: map[slotKey]bool{}, diag: diag}
	var observers []nat.Observer
	for _, s := range obs {
		if nat.SocketFamily(s.Socket) != m.f {
			continue
		}
		m.srv = append(m.srv, s)
		m.alt[s.Observer] = m.alt[s.Observer] || s.Alt
		if !slices.ContainsFunc(observers, func(o nat.Observer) bool { return o.ID == s.Observer }) {
			scope := nat.ScopeGlobal
			if s.LAN {
				scope = nat.ScopePrivate
			}
			observers = append(observers, nat.Observer{ID: s.Observer, Group: s.Observer / portsPerGroup, Alt: s.Alt, Scope: scope})
		}
	}
	for _, sr := range fr.Sockets {
		m.socks = append(m.socks, nat.SocketMeta{ID: sr.ID, Kind: sr.Kind, Local: sr.Local})
	}
	m.t = nat.NewTable(m.f, m.socks, observers)
	m.socks = m.t.Sockets() // the sockets the table accepted
	m.mergeRows(fr)
	m.mergeFilters(fr)
	m.mergeSelfReported(fr)
	m.t.NoteOverlay(fr.Overlay)

	tr := m.t.Classify()
	diag.STUNConflicts += m.t.STUNConflicts()
	tr.PortAnchorMs = m.anchorMs(tr)
	if mem != nil && tr.Samples > 0 {
		k := TraitsKey{ClientKey: key.ClientKey, Family: m.f, PublicIP: tr.PublicIP}
		cur := tr
		if life.Safe("natprobe/memory", func() { cur = mem.Apply(k, cur) }) != nil {
			diag.MemoryPanics++
		} else {
			tr = cur
			tr.Family = m.f
		}
	}
	tr.Provisional = false
	if m.conflicts > 0 && tr.MappingConf > protocol.ConfLow {
		// The client saw other values than the server recorded: mostly a
		// deployment error (an SNAT proxy, a wrong advertised address).
		tr.MappingConf--
	}
	return protocol.FamilyView{Family: m.f, Traits: tr, Endpoints: m.t.Endpoints()}
}

// mergeRows records every slot the server has: the reported ones with the
// client's first seq, send time, RTT and cookie verdict, the unreported ones
// for classification only. A client value that matches neither the slot's first
// nor its latest value is a conflict, which lowers the mapping confidence by
// one level. A row the client reports unanswered and the server has no slot for
// is a probe lost on its way: it carries no value, but it made its mapping when
// it left, so it is kept as an unanswered point in the client's send order,
// which the port allocation counts.
func (m *familyMerge) mergeRows(fr protocol.FamilyReport) {
	covered := map[slotKey]bool{}
	conflicts := 0
	for _, sr := range fr.Sockets {
		if nat.SocketFamily(sr.ID) != m.f {
			continue
		}
		for _, row := range sr.Rows {
			k := slotKey{sr.ID, row.Observer}
			claimed := row.Observed.IsValid() || row.RTTMs != 0 || row.Cookie != 0
			s, ok := m.find(k)
			if !ok {
				if claimed {
					m.diag.Unverified++
				} else if row.FirstSeq != 0 {
					m.noteUnanswered(sr.ID, row)
				}
				continue
			}
			if covered[k] {
				continue
			}
			covered[k], m.answered[k] = true, claimed
			verified := row.Cookie != 0 && row.Cookie == s.Cookie
			if !verified {
				m.diag.CookieMissing++
			}
			seq := row.FirstSeq
			if seq == 0 {
				seq = s.FirstSeq
			}
			m.recordSlot(s, seq, time.Duration(row.SentMs)*time.Millisecond, time.Duration(row.RTTMs)*time.Millisecond, verified)
			if a := unmapAP(row.Observed); row.Observed.IsValid() && a != s.Observed && a != s.First {
				conflicts++
			}
		}
	}
	for _, s := range m.srv {
		if !covered[slotKey{s.Socket, s.Observer}] {
			m.recordSlot(s, s.FirstSeq, -1, 0, false) // the probe arrived, the ack was lost
		}
	}
	m.conflicts += conflicts
	m.diag.Conflicts += conflicts
}

// noteUnanswered records the reported row of socket sock that no probe of
// reached the server as an unanswered point.
func (m *familyMerge) noteUnanswered(sock uint8, row protocol.RowReport) {
	src := nat.SourceServer
	if m.alt[row.Observer] {
		src = nat.SourceServerAlt
	}
	m.t.NoteSent(nat.PointKey{Socket: sock, Source: src, Observer: row.Observer}, row.FirstSeq, time.Duration(row.SentMs)*time.Millisecond)
}

func (m *familyMerge) find(k slotKey) (ServerObservation, bool) {
	for _, s := range m.srv {
		if s.Socket == k.sock && s.Observer == k.obs {
			return s, true
		}
	}
	return ServerObservation{}, false
}

// recordSlot adds a slot to the table: its first value and, when it drifted,
// its latest value, the only one the cookie can verify.
func (m *familyMerge) recordSlot(s ServerObservation, seq uint32, sent, rtt time.Duration, verified bool) {
	src := nat.SourceServer
	if s.Alt {
		src = nat.SourceServerAlt
	}
	k := nat.PointKey{Socket: s.Socket, Source: src, Observer: s.Observer}
	created := m.h.e.created
	firstAt, lastAt := s.FirstAt.Sub(created), s.LastAt.Sub(created)
	drifted := s.First != s.Observed
	m.t.RecordServer(nat.Row{Key: k, Observed: s.First, FirstSeq: seq, FirstSent: sent, FirstSeen: firstAt, LastSeen: firstAt,
		Changes: s.Changes, RTT: rtt, Cookie: s.Cookie, Verified: verified && !drifted})
	if drifted {
		m.t.RecordServer(nat.Row{Key: k, Observed: s.Observed, FirstSeq: seq, FirstSent: sent, FirstSeen: lastAt, LastSeen: lastAt,
			Changes: s.Changes, RTT: rtt, Cookie: s.Cookie, Verified: verified})
	}
}

// mergeFilters takes the sent counts from the server and the seen counts
// from the client, only for slots the client got an ack for: it cannot know
// of declarations in acks it never received.
func (m *familyMerge) mergeFilters(fr protocol.FamilyReport) {
	type seenCounts struct{ extra, alt uint8 }
	clientSeen := map[slotKey]seenCounts{}
	for _, fl := range fr.Filters {
		k := slotKey{fl.Socket, fl.Observer}
		if _, dup := clientSeen[k]; !dup {
			clientSeen[k] = seenCounts{fl.ExtraSeen, fl.AltSeen}
		}
	}
	for _, s := range m.srv {
		k := slotKey{s.Socket, s.Observer}
		if (s.ExtraSent == 0 && s.AltSent == 0) || !m.answered[k] {
			continue
		}
		c := clientSeen[k]
		m.t.AddFilter(nat.FilterEvidence{Socket: s.Socket, Observer: s.Observer,
			ExtraDeclared: s.ExtraSent, ExtraSeen: min(c.extra, s.ExtraSent), AltDeclared: s.AltSent, AltSeen: min(c.alt, s.AltSent)})
	}
}

// mergeSelfReported admits the STUN and port-mapping addresses that pass the
// anti-reflection constraints, on the primary socket.
func (m *familyMerge) mergeSelfReported(fr protocol.FamilyReport) {
	var primary nat.SocketMeta
	found := false
	for _, s := range m.socks {
		if s.Kind == protocol.SocketPrimary {
			primary, found = s, true
			break
		}
	}
	if !found {
		return
	}
	verified := m.t.VerifiedIPs()
	for _, row := range fr.STUN {
		if !row.Observed.IsValid() {
			continue
		}
		if !nat.AdmitSelfReported(nat.SourceSTUN, unmapAP(row.Observed), verified) {
			m.diag.RejectedEndpoints++
			continue
		}
		m.t.Record(nat.PointKey{Socket: primary.ID, Source: nat.SourceSTUN, Observer: row.Observer}, row.Observed, 0,
			time.Duration(row.RTTMs)*time.Millisecond, 0)
	}
	if pm := fr.PortMap; pm != nil && pm.External.IsValid() {
		if nat.AdmitSelfReported(nat.SourcePortMap, unmapAP(pm.External), verified) {
			m.t.Record(nat.PointKey{Socket: primary.ID, Source: nat.SourcePortMap}, pm.External, 0, 0, 0)
		} else {
			m.diag.RejectedEndpoints++
		}
	}
}

// anchorMs is PortAnchorMs on the server's monotonic axis: milliseconds from
// the registration to the first probe of the anchor mapping.
func (m *familyMerge) anchorMs(tr protocol.Traits) int64 {
	if tr.PortAlloc != protocol.AllocSequential || tr.PortAnchor == 0 {
		return 0
	}
	sequenced := func(id uint8) bool {
		for _, s := range m.socks {
			if s.ID == id && (s.Kind == protocol.SocketPrimary || s.Kind == protocol.SocketSecond) {
				return true
			}
		}
		return false
	}
	var best *ServerObservation
	for i := range m.srv {
		s := &m.srv[i]
		if s.First.Port() == tr.PortAnchor && sequenced(s.Socket) && (best == nil || s.FirstSeq > best.FirstSeq) {
			best = s
		}
	}
	if best == nil {
		return 0
	}
	return best.FirstAt.Sub(m.h.e.created).Milliseconds()
}

func unmapAP(a netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()) }

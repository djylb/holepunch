package nat

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Table bounds per family.
const (
	maxSockets = 6
	maxRows    = 64
	maxFilters = 24
	maxInbound = 8
)

// Source says where an observation came from.
type Source uint8

// Sources.
const (
	// SourceServer is a natprobe main-group observer (probe_ack).
	SourceServer Source = iota + 1
	// SourceServerAlt is a natprobe alt-group observer (solicited probe_ack).
	SourceServerAlt
	// SourceSTUN is an optional STUN binding, self-reported to the server.
	SourceSTUN
	// SourcePeer is the peer's peer_seen while punching.
	SourcePeer
	// SourcePortMap is a UPnP/PCP/NAT-PMP external address, self-reported.
	SourcePortMap
)

// PointKey is an observation point. The rows of one key are that
// point's value history: two different values at one point are drift,
// different values at different points are evidence of the mapping
// behaviour.
//
// A server observer is named by its id, because a server-side table knows no
// advertised addresses. A peer observation is keyed by the full endpoint our
// packet went to: an APDM mapping differs per destination port, so keying by
// the peer's IP alone would report drift for normal behaviour.
type PointKey struct {
	Socket   uint8
	Source   Source
	Observer uint8          // SourceServer, SourceServerAlt: observer id; SourceSTUN: index in ProbeSpec.STUN
	Peer     netip.AddrPort // SourcePeer: the peer endpoint our packet went to
}

// Row is one observation point × one observed value.
type Row struct {
	Key       PointKey
	Observed  netip.AddrPort // zero: the point was probed and nothing answered yet
	FirstSeq  uint32         // seq of the point's first probe: mapping creation order, comparable across sockets
	FirstSent time.Duration  // first probe of the point, relative to the probe start; < 0 unknown
	FirstSeen time.Duration  // first time this value was seen (server-side tables: since Register)
	LastSeen  time.Duration  // latest time this value was seen
	Changes   uint8          // server-side tables: value changes natprobe recorded at the point
	RTT       time.Duration  // minimum RTT (server and STUN sources); 0 unknown
	Cookie    uint32         // COOKIE of the latest answer (report field c)
	Verified  bool           // server-side tables: recorded by natprobe and its cookie echoed
}

// FilterEvidence is the filtering evidence of one (socket, observer):
// settled declarations only, that is extras or alts the server declared that
// either arrived or were waited out.
type FilterEvidence struct {
	Socket, Observer         uint8
	ExtraDeclared, ExtraSeen uint8
	AltDeclared, AltSeen     uint8
}

// inboundEvidence is a valid peer packet that reached a socket from an IP the
// socket had never sent to: the filtering is endpoint independent.
type inboundEvidence struct {
	Socket uint8
	From   netip.Addr
}

// ObsTable is the observation table of one family. The prober fills
// it while probing, the client runtime keeps adding peer evidence while
// punching, and natprobe builds one per reported family in Handle.Merge. It
// is safe for concurrent use.
type ObsTable struct {
	mu        sync.Mutex
	family    protocol.Family
	sockets   []SocketMeta
	observers []Observer
	rows      []Row
	filters   []FilterEvidence
	inbound   []inboundEvidence
	hairpin   protocol.Tri
	overlay   []netip.Addr // the host's overlay addresses (NoteOverlay)
	// reportedFallback lets a LAN-observed table admit the global
	// addresses its client reported (SetReportedFallback).
	reportedFallback bool
}

// NewTable returns an empty table of family f with the given sockets (the
// first primary socket decides the family's traits) and observers. Sockets
// and observers of another family, sockets of an unknown kind, repeated ids
// and entries beyond the bounds are dropped. An observer's Scope is taken
// from its address when left zero; one with neither is dropped.
func NewTable(f protocol.Family, sockets []SocketMeta, observers []Observer) *ObsTable {
	t := &ObsTable{family: f}
	for _, s := range sockets {
		t.addSocketLocked(s)
	}
	for _, o := range observers {
		o.Addr = unmap(o.Addr)
		if o.Scope == ScopeNone {
			o.Scope = ScopeOf(o.Addr.Addr())
		}
		otherFamily := o.Addr.IsValid() && !f.Matches(o.Addr.Addr())
		if o.Scope != ScopeNone && !otherFamily && len(t.observers) < maxObservers && t.observerLocked(o.ID) == nil {
			t.observers = append(t.observers, o)
		}
	}
	return t
}

// AddSocket adds a socket opened after the table was created (the second
// socket) and reports whether the socket is now known.
func (t *ObsTable) AddSocket(m SocketMeta) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addSocketLocked(m)
}

func (t *ObsTable) addSocketLocked(m SocketMeta) bool {
	if !validKind(m.Kind) || SocketFamily(m.ID) != t.family {
		return false
	}
	if t.socketLocked(m.ID) != nil {
		return true
	}
	if len(t.sockets) == maxSockets {
		return false
	}
	m.Local = unmap(m.Local)
	t.sockets = append(t.sockets, m)
	return true
}

// Sockets returns a copy of the known sockets.
func (t *ObsTable) Sockets() []SocketMeta {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.sockets)
}

// NoteSent records the first probe of point k, its seq and its send time
// relative to the probe start. Later sends to the point change nothing:
// the first send created the mapping.
func (t *ObsTable) NoteSent(k PointKey, seq uint32, at time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.rows {
		if t.rows[i].Key == k {
			return
		}
	}
	t.appendLocked(Row{Key: k, FirstSeq: seq, FirstSent: at, FirstSeen: -1, LastSeen: -1})
}

// Record adds an answer at point k carrying observed, received at at
// (relative to the probe start) with round-trip time rtt (0 unknown) and
// cookie (probe_ack only), and reports whether the point now holds two or
// more different values (drift). A value that is not a unicast address
// of the table's family with a port is ignored.
func (t *ObsTable) Record(k PointKey, observed netip.AddrPort, at, rtt time.Duration, cookie uint32) (drift bool) {
	observed = unmap(observed)
	if !usableIn(t.family, observed) {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	placeholder, values := -1, 0
	firstSeq, firstSent := uint32(0), time.Duration(-1)
	for i := range t.rows {
		r := &t.rows[i]
		if r.Key != k {
			continue
		}
		firstSeq, firstSent = r.FirstSeq, r.FirstSent
		if !r.Observed.IsValid() {
			placeholder = i
			continue
		}
		values++
		if r.Observed == observed {
			r.LastSeen = at
			r.RTT = minRTT(r.RTT, rtt)
			r.Cookie = cookie
			return t.otherValueLocked(k, observed)
		}
	}
	if placeholder >= 0 {
		r := &t.rows[placeholder]
		r.Observed, r.FirstSeen, r.LastSeen, r.RTT, r.Cookie = observed, at, at, rtt, cookie
		return values > 0
	}
	t.appendLocked(Row{Key: k, Observed: observed, FirstSeq: firstSeq, FirstSent: firstSent,
		FirstSeen: at, LastSeen: at, RTT: rtt, Cookie: cookie})
	return values > 0
}

func (t *ObsTable) otherValueLocked(k PointKey, v netip.AddrPort) bool {
	for _, r := range t.rows {
		if r.Key == k && r.Observed.IsValid() && r.Observed != v {
			return true
		}
	}
	return false
}

// RecordServer adds a row as natprobe's merge builds it from its own records.
// A row whose value is not a unicast address of the table's family with a
// port is ignored.
func (t *ObsTable) RecordServer(r Row) {
	r.Observed = unmap(r.Observed)
	if !usableIn(t.family, r.Observed) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.appendLocked(r)
}

// appendLocked appends r. In a full table the oldest row of a socket other
// than the primary is evicted, and r is dropped when every row belongs to
// the primary socket: the primary decides the family's traits.
func (t *ObsTable) appendLocked(r Row) {
	if len(t.rows) == maxRows {
		victim := slices.IndexFunc(t.rows, func(old Row) bool {
			s := t.socketLocked(old.Key.Socket)
			return s == nil || s.Kind != protocol.SocketPrimary
		})
		if victim < 0 {
			return
		}
		t.rows = slices.Delete(t.rows, victim, victim+1)
	}
	t.rows = append(t.rows, r)
}

// AddFilter adds filtering evidence to the entry of (f.Socket, f.Observer).
func (t *ObsTable) AddFilter(f FilterEvidence) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.filters {
		e := &t.filters[i]
		if e.Socket == f.Socket && e.Observer == f.Observer {
			e.ExtraDeclared = satAdd(e.ExtraDeclared, f.ExtraDeclared)
			e.ExtraSeen = satAdd(e.ExtraSeen, f.ExtraSeen)
			e.AltDeclared = satAdd(e.AltDeclared, f.AltDeclared)
			e.AltSeen = satAdd(e.AltSeen, f.AltSeen)
			return
		}
	}
	if len(t.filters) < maxFilters {
		t.filters = append(t.filters, f)
	}
}

// NoteUnsolicitedInbound records that socket sock received a valid peer
// packet from an IP it had never sent to.
func (t *ObsTable) NoteUnsolicitedInbound(sock uint8, from netip.Addr) {
	from = from.Unmap()
	if !from.IsValid() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := inboundEvidence{Socket: sock, From: from}
	if !slices.Contains(t.inbound, e) && len(t.inbound) < maxInbound {
		t.inbound = append(t.inbound, e)
	}
}

// SetHairpin records the result of the hairpin self-test; an
// invalid value is ignored.
func (t *ObsTable) SetHairpin(v protocol.Tri) {
	if !v.Valid() {
		return
	}
	t.mu.Lock()
	t.hairpin = v
	t.mu.Unlock()
}

func (t *ObsTable) socketLocked(id uint8) *SocketMeta {
	for i := range t.sockets {
		if t.sockets[i].ID == id {
			return &t.sockets[i]
		}
	}
	return nil
}

func (t *ObsTable) socketOfKindLocked(k protocol.SocketKind) (SocketMeta, bool) {
	for _, s := range t.sockets {
		if s.Kind == k {
			return s, true
		}
	}
	return SocketMeta{}, false
}

func (t *ObsTable) observerLocked(id uint8) *Observer {
	for i := range t.observers {
		if t.observers[i].ID == id {
			return &t.observers[i]
		}
	}
	return nil
}

func satAdd(a, b uint8) uint8 { return uint8(min(int(a)+int(b), 255)) }

// minRTT keeps the smaller known RTT; 0 means unknown.
func minRTT(a, b time.Duration) time.Duration {
	switch {
	case b <= 0:
		return a
	case a <= 0 || b < a:
		return b
	}
	return a
}

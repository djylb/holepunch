package nat

import (
	"slices"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Report bounds (protocol: rows per socket, STUN rows).
const (
	maxReportRows = 16
	maxReportSTUN = 4
)

// Snapshot returns the family's probe_report entry as far as the table knows
// it: the family; each socket with a concrete
// local address and one row per probed server observer (first value, first
// seq, first send time, minimum RTT, cookie of the latest answer); the STUN
// rows; and the extra and alt replies seen. The caller fills Failure,
// Traits, PortMap and LocalAddrs. The result stays within the protocol
// bounds (6 sockets, 16 rows each, 4 STUN rows, 24 filters).
func (t *ObsTable) Snapshot() protocol.FamilyReport {
	t.mu.Lock()
	defer t.mu.Unlock()
	fr := protocol.FamilyReport{Family: t.family, Sockets: []protocol.SocketReport{}}
	for _, s := range t.sockets {
		if !usableIn(t.family, s.Local) {
			continue
		}
		sr := protocol.SocketReport{ID: s.ID, Kind: s.Kind, Local: s.Local, Rows: []protocol.RowReport{}}
		for _, k := range t.pointKeysLocked(s.ID, SourceServer, SourceServerAlt) {
			if len(sr.Rows) == maxReportRows {
				break
			}
			sr.Rows = append(sr.Rows, t.rowReportLocked(k))
		}
		fr.Sockets = append(fr.Sockets, sr)
	}
	for _, s := range t.sockets {
		for _, k := range t.pointKeysLocked(s.ID, SourceSTUN) {
			if rr := t.rowReportLocked(k); rr.Observed.IsValid() && len(fr.STUN) < maxReportSTUN {
				fr.STUN = append(fr.STUN, rr)
			}
		}
	}
	for _, f := range t.filters {
		if f.ExtraSeen > 0 || f.AltSeen > 0 {
			fr.Filters = append(fr.Filters, protocol.FilterReport{Socket: f.Socket, Observer: f.Observer, ExtraSeen: f.ExtraSeen, AltSeen: f.AltSeen})
		}
	}
	return fr
}

// pointKeysLocked returns the distinct keys of socket sock with one of the
// sources, in order of first appearance.
func (t *ObsTable) pointKeysLocked(sock uint8, sources ...Source) []PointKey {
	var keys []PointKey
	for _, r := range t.rows {
		if r.Key.Socket != sock || !slices.Contains(sources, r.Key.Source) || slices.Contains(keys, r.Key) {
			continue
		}
		keys = append(keys, r.Key)
	}
	return keys
}

// rowReportLocked summarizes point k: first value, first seq and send time,
// minimum RTT and the cookie of the latest answer. The server echoes the
// cookie of the slot's current value, so the latest answer's cookie is the
// one that can verify it.
func (t *ObsTable) rowReportLocked(k PointKey) protocol.RowReport {
	rr := protocol.RowReport{Observer: k.Observer}
	var first, latest *Row
	for i := range t.rows {
		r := &t.rows[i]
		if r.Key != k {
			continue
		}
		rr.FirstSeq = r.FirstSeq
		if r.FirstSent >= 0 {
			rr.SentMs = uint32(min(r.FirstSent.Milliseconds(), 1<<32-1))
		}
		if !r.Observed.IsValid() {
			continue
		}
		if first == nil || r.FirstSeen < first.FirstSeen {
			first = r
		}
		if latest == nil || r.LastSeen >= latest.LastSeen {
			latest = r
		}
		if r.RTT > 0 && (rr.RTTMs == 0 || rttMs(r.RTT) < rr.RTTMs) {
			rr.RTTMs = rttMs(r.RTT)
		}
	}
	if first == nil {
		return rr
	}
	rr.Observed = first.Observed
	rr.Cookie = latest.Cookie
	if rr.RTTMs == 0 {
		rr.RTTMs = 1 // answered with an unknown RTT: 0 would read as "no ack"
	}
	return rr
}

// rttMs rounds d up to whole milliseconds within [1, 65535].
func rttMs(d time.Duration) uint16 {
	ms := (d + time.Millisecond - 1) / time.Millisecond
	return uint16(min(max(ms, 1), 65535))
}

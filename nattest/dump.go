package nattest

import (
	"encoding/json"
	"io"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// evKind is the kind of a packet event in the log.
type evKind uint8

const (
	evSend    evKind = iota + 1 // accepted by WriteTo
	evOut                       // translated outbound by a NAT
	evIn                        // accepted inbound by a NAT
	evHairpin                   // looped back by a NAT
	evDeliver                   // queued on the destination socket
	evDrop                      // dropped, with a reason
)

var evNames = [...]string{"", "send", "nat_out", "nat_in", "hairpin", "deliver", "drop"}

// logEvent is one entry of the event log; it copies what it needs from the
// packet, which is recycled.
type logEvent struct {
	t        time.Duration
	kind     evKind
	at       string // host, NAT or "core"
	src, dst netip.AddrPort
	size     int32
	ttl      int16
	b0       int16 // first payload byte, -1 if empty
	why      dropReason
}

// eventLog is a ring buffer of the most recent packet events; nil when
// disabled.
type eventLog struct {
	mu    sync.Mutex
	buf   []logEvent
	next  int
	full  bool
	total uint64
}

func newEventLog(size int) *eventLog {
	if size <= 0 {
		return nil
	}
	return &eventLog{buf: make([]logEvent, size)}
}

func (l *eventLog) add(n *Network, kind evKind, at string, p *packet, why dropReason) {
	if l == nil {
		return
	}
	e := logEvent{t: n.now(), kind: kind, at: at, src: p.src, dst: p.dst, size: int32(len(p.data)), ttl: int16(p.ttl), b0: -1, why: why}
	if len(p.data) > 0 {
		e.b0 = int16(p.data[0])
	}
	l.mu.Lock()
	l.buf[l.next] = e
	l.next++
	if l.next == len(l.buf) {
		l.next, l.full = 0, true
	}
	l.total++
	l.mu.Unlock()
}

// snapshot returns the logged events, oldest first, and how many were
// logged in total.
func (l *eventLog) snapshot() ([]logEvent, uint64) {
	if l == nil {
		return nil, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []logEvent
	if l.full {
		out = append(out, l.buf[l.next:]...)
	}
	return append(out, l.buf[:l.next]...), l.total
}

// The dump document. Its types are unexported: the format is for people
// reading a failure, and e2e embeds it as raw JSON.
type (
	dumpDoc struct {
		Seed        int64       `json:"seed"`
		Now         time.Time   `json:"now"`
		Stats       NetStats    `json:"stats"`
		NATs        []dumpNAT   `json:"nats"`
		Hosts       []dumpHost  `json:"hosts"`
		EventsTotal uint64      `json:"events_total"`
		Events      []dumpEvent `json:"events"`
	}
	dumpNAT struct {
		Name      string        `json:"name"`
		Parent    string        `json:"parent"`
		Mapping   string        `json:"mapping"`
		Filtering string        `json:"filtering"`
		PortAlloc string        `json:"port_alloc"`
		IPv6      string        `json:"ipv6,omitempty"`
		External  []netip.Addr  `json:"external,omitempty"`
		Stats     NATStats      `json:"stats"`
		Mappings  []MappingInfo `json:"mappings"`
	}
	dumpHost struct {
		Name  string       `json:"name"`
		NAT   string       `json:"nat,omitempty"`
		Addrs []netip.Addr `json:"addrs"`
		Stats HostStats    `json:"stats"`
	}
	dumpEvent struct {
		T    time.Duration  `json:"t"` // network time, ns
		Kind string         `json:"kind"`
		At   string         `json:"at"`
		Src  netip.AddrPort `json:"src"`
		Dst  netip.AddrPort `json:"dst"`
		Len  int            `json:"len"`
		TTL  int            `json:"ttl"`
		B0   int            `json:"b0"`
		Why  string         `json:"why,omitempty"`
	}
)

// Dump writes a failure dump as indented JSON: the seed, the
// network, NAT and host statistics (with every socket's packet shape), every
// live mapping with its filter state, and the most recent packet events, hop
// by hop (see [WithEventLog]). It also works after Close.
func (n *Network) Dump(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(n.dump())
}

func (n *Network) dump() dumpDoc {
	n.topo.RLock()
	hosts := slices.Clone(n.hosts)
	nats := slices.Clone(n.nats)
	n.topo.RUnlock()
	doc := dumpDoc{Seed: n.seed, Now: n.clock.Now(), Stats: n.Stats()}
	for _, nat := range nats {
		d := dumpNAT{
			Name: nat.name, Parent: "core",
			Mapping: nat.cfg.Mapping.String(), Filtering: nat.cfg.Filtering.String(), PortAlloc: nat.cfg.PortAlloc.String(),
			External: nat.ExternalIPs(), Stats: nat.Stats(), Mappings: nat.Mappings(),
		}
		if nat.parentNAT != nil {
			d.Parent = nat.parentNAT.name
		}
		if nat.cfg.IPv6 != nil {
			d.IPv6 = nat.cfg.IPv6.Mode.String()
		}
		doc.NATs = append(doc.NATs, d)
	}
	for _, h := range hosts {
		d := dumpHost{Name: h.name, Addrs: h.Addrs(), Stats: h.Stats()}
		if h.nat != nil {
			d.NAT = h.nat.name
		}
		doc.Hosts = append(doc.Hosts, d)
	}
	evs, total := n.log.snapshot()
	doc.EventsTotal = total
	doc.Events = make([]dumpEvent, len(evs))
	for i, e := range evs {
		doc.Events[i] = dumpEvent{
			T: e.t, Kind: evNames[e.kind], At: e.at, Src: e.src, Dst: e.dst,
			Len: int(e.size), TTL: int(e.ttl), B0: int(e.b0), Why: e.why.String(),
		}
	}
	return doc
}

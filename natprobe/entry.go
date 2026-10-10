package natprobe

import (
	"math"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// entry is one registered session, at most about 4 KiB with both roles'
// slots.
type entry struct {
	id        string
	route     protocol.RouteID
	tokenTag  [16]byte
	codec     *udpwire.Codec // derived once at Register
	created   time.Time      // Register: the origin of slot times and of PortAnchorMs
	expiresAt atomic.Int64   // Registry monotonic ns; the hot path compares, never deletes
	closed    atomic.Bool
	roles     [2]roleState // initiator, responder
	sandwich  sandwichQueue
}

// initialSlots is the slot capacity a role starts with: a typical probe
// (three observers and a sibling) never grows it, so the packet path does
// not allocate; an APDM client's second socket grows it once.
const initialSlots = 4

func newEntry(reg Registration, tag [16]byte, codec *udpwire.Codec, now time.Time, cfg RegistryConfig) *entry {
	e := &entry{id: reg.SessionID, route: reg.Route, tokenTag: tag, codec: codec, created: now}
	for i := range e.roles {
		e.roles[i].slots = make([]slot, 0, min(initialSlots, cfg.SlotsPerRole))
		e.roles[i].extraLeft = cfg.ExtraQuotaPerRole
		e.roles[i].altLeft = cfg.AltQuotaPerRole
	}
	return e
}

func (e *entry) alive(mono int64) bool { return !e.closed.Load() && mono < e.expiresAt.Load() }

// extendAlive moves the expiry to until unless it is already later, and
// reports whether the entry was alive at mono. An entry that expired stays
// expired: the check and the move are one compare-and-swap, so a renewal
// racing the expiry cannot revive it.
func (e *entry) extendAlive(mono, until int64) bool {
	for {
		old := e.expiresAt.Load()
		switch {
		case e.closed.Load() || mono >= old:
			return false
		case until <= old || e.expiresAt.CompareAndSwap(old, until):
			return true
		}
	}
}

// addSat returns a+b for b ≥ 0, saturated at the largest int64: a huge TTL
// must not wrap the expiry into the past.
func addSat(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// roleState is the state of one (session, role), guarded by mu.
type roleState struct {
	mu        sync.Mutex
	slots     []slot            // grown on demand from initialSlots, at most SlotsPerRole
	win       udpwire.SeqWindow // 1024-bit replay window over the client's seq
	tat       int64             // GCRA state of SessionRate
	accepted  uint16
	extraLeft uint8
	altLeft   uint8
	replySeq  uint32 // seq of natprobe's replies to this role
}

// Slot flags: observer properties kept with the slot, so that a merge needs
// no access to the Server.
const (
	slotAlt     = 1 << 0 // an observer of the alt group
	slotPrivate = 1 << 1 // an observer advertised on a private address
)

// slot is one observation slot (role, sock, observer), about 60 bytes.
type slot struct {
	sock, obs, count, changes uint8
	flags                     uint8
	extraSent, altSent        uint8
	first, last               addr18
	firstSeq                  uint32
	cookie                    uint32 // renewed whenever last changes
	firstAt, lastAt           uint32 // ms since the entry was registered
}

// addr18 is a compact address: 16-byte IP (IPv4 mapped) and port.
type addr18 struct {
	ip   [16]byte
	port uint16
}

func packAddr(a netip.AddrPort) addr18 { return addr18{ip: a.Addr().As16(), port: a.Port()} }

func (a addr18) addrPort() netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16(a.ip).Unmap(), a.port)
}

// upsert records an accepted probe from src at slot (sock, obs) and returns
// the slot, or nil when the role has no free slot: the probe is still
// answered, with cookie 0, and merges as "not seen by the server".
func (rs *roleState) upsert(sock, obs, flags uint8, src netip.AddrPort, seq, ms uint32, maxSlots int, rng *rand.Rand) *slot {
	a := packAddr(src)
	for i := range rs.slots {
		s := &rs.slots[i]
		if s.sock != sock || s.obs != obs {
			continue
		}
		s.count = satInc(s.count)
		if s.last != a {
			s.last = a
			s.changes = satInc(s.changes)
			s.cookie = newCookie(rng)
		}
		s.lastAt = ms
		return s
	}
	if len(rs.slots) >= maxSlots {
		return nil
	}
	if len(rs.slots) == cap(rs.slots) {
		grown := make([]slot, len(rs.slots), min(max(2*cap(rs.slots), initialSlots), maxSlots))
		copy(grown, rs.slots)
		rs.slots = grown
	}
	rs.slots = append(rs.slots, slot{sock: sock, obs: obs, flags: flags, count: 1, first: a, last: a,
		firstSeq: seq, cookie: newCookie(rng), firstAt: ms, lastAt: ms})
	return &rs.slots[len(rs.slots)-1]
}

// nextSeq returns the next seq of the replies to this role, never 0.
func (rs *roleState) nextSeq() uint32 {
	rs.replySeq++
	if rs.replySeq == 0 {
		rs.replySeq = 1
	}
	return rs.replySeq
}

// newCookie draws a non-zero return-path cookie; 0 means "no cookie".
func newCookie(rng *rand.Rand) uint32 {
	for {
		if c := rng.Uint32(); c != 0 {
			return c
		}
	}
}

func satInc(v uint8) uint8 {
	if v == 255 {
		return v
	}
	return v + 1
}

package candidate

import (
	"container/heap"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// A two-Manager exchange over several pairs for the extra paths:
// every action becomes a packet on its pair, delivered after the pair's
// one-way delay unless the loss draw drops it.

// mpPair is one pair as both sides see it.
type mpPair struct {
	iLoc, rAddr netip.AddrPort // initiator view
	rLoc, iAddr netip.AddrPort // responder view
	fam         protocol.Family
	path        protocol.PathKind
	kind        Kind  // the initiator's planned kind of the pair
	iSock       uint8 // the initiator's socket id, as the responder's packets name it
	rSock       uint8
	oneWay      time.Duration
}

type mpPkt struct {
	at     time.Time
	seq    int
	toInit bool
	pair   int
	a      Action
}

type mpQueue []mpPkt

func (q *mpQueue) Len() int { return len(*q) }
func (q *mpQueue) Less(i, j int) bool {
	s := *q
	if !s[i].at.Equal(s[j].at) {
		return s[i].at.Before(s[j].at)
	}
	return s[i].seq < s[j].seq
}
func (q *mpQueue) Swap(i, j int) { s := *q; s[i], s[j] = s[j], s[i] }
func (q *mpQueue) Push(x any)    { *q = append(*q, x.(mpPkt)) }
func (q *mpQueue) Pop() any {
	old := *q
	x := old[len(old)-1]
	*q = old[:len(old)-1]
	return x
}

// mpRun is the outcome of one exchange.
type mpRun struct {
	iConfirmAt, iReadyAt time.Time
	init, resp           *Manager
	iHand, rHand         *Action
	iExtras, rExtras     []Candidate
	handshakes           [2]int // handshake packets sent by each side
	extraPackets         [2]int // those of them for extra paths
	iFailed, rFailed     bool
	firstReadyPaths      uint8
	readyPathsChanged    bool
}

// mpExchange runs the handshake: both sides saw every pair carry packets
// before t0; maxPaths are the two sides' Config.MaxPaths.
func mpExchange(pairs []mpPair, maxPaths [2]int, loss float64, seed uint64) *mpRun {
	r := &mpRun{
		init: NewManager(Config{Role: protocol.RoleInitiator, MaxPaths: maxPaths[0]}),
		resp: NewManager(Config{Role: protocol.RoleResponder, MaxPaths: maxPaths[1]}),
	}
	rng := rand.New(rand.NewPCG(seed, 73))
	t0 := time.Unix(1000, 0)
	for _, p := range pairs {
		if p.kind != KindUnknown {
			r.init.Observe(t0, p.iLoc, p.rAddr, p.fam, p.kind)
			r.resp.Observe(t0, p.rLoc, p.iAddr, p.fam, p.kind)
		}
		r.init.Success(t0, p.iLoc, p.rAddr, p.fam, 2*p.oneWay)
		r.init.Describe(p.iLoc, p.rAddr, p.path, p.rSock)
		r.resp.Success(t0, p.rLoc, p.iAddr, p.fam, 2*p.oneWay)
		r.resp.Describe(p.rLoc, p.iAddr, p.path, p.iSock)
	}
	var q mpQueue
	seq := 0
	pairOf := func(toInit bool, local, remote netip.AddrPort) int {
		for i, p := range pairs {
			if toInit && p.rLoc == local && p.iAddr == remote || !toInit && p.iLoc == local && p.rAddr == remote {
				return i
			}
		}
		return -1
	}
	apply := func(fromInit bool, now time.Time, acts []Action) {
		for _, a := range acts {
			switch a.Kind {
			case SendNominate, SendAccept, SendReady, SendAck:
				side := 1
				if fromInit {
					side = 0
				}
				r.handshakes[side]++
				if a.Slot != 0 {
					r.extraPackets[side]++
				}
				if a.Kind == SendReady {
					if r.iReadyAt.IsZero() {
						r.iReadyAt, r.firstReadyPaths = now, a.Paths
					} else if a.Paths != r.firstReadyPaths {
						r.readyPathsChanged = true
					}
				}
				i := pairOf(!fromInit, a.Local, a.Remote)
				if i < 0 || rng.Float64() < loss {
					continue
				}
				seq++
				heap.Push(&q, mpPkt{at: now.Add(pairs[i].oneWay), seq: seq, toInit: !fromInit, pair: i, a: a})
			case Confirm:
				if fromInit {
					r.iConfirmAt = now
				}
			case HandOver:
				h := a
				if fromInit {
					r.iHand, r.iExtras = &h, r.init.Extras()
				} else {
					r.rHand, r.rExtras = &h, r.resp.Extras()
				}
			case Fail:
				if fromInit {
					r.iFailed = true
				} else {
					r.rFailed = true
				}
			}
		}
	}
	apply(true, t0, r.init.Tick(t0))
	apply(true, t0, r.init.Tick(t0.Add(time.Second))) // the collection window ends
	now := t0.Add(time.Second)
	for range 100000 {
		next, ok := time.Time{}, false
		if len(q) > 0 {
			next, ok = q[0].at, true
		}
		for _, m := range []*Manager{r.init, r.resp} {
			if at, armed := m.NextDeadline(); armed && (!ok || at.Before(next)) {
				next, ok = at, true
			}
		}
		if !ok || next.Sub(t0) > 30*time.Second || (r.iHand != nil || r.iFailed) && (r.rHand != nil || r.rFailed) {
			break
		}
		now = maxTime(now, next)
		for len(q) > 0 && !q[0].at.After(now) {
			pk := heap.Pop(&q).(mpPkt)
			p := pairs[pk.pair]
			a := pk.a
			if pk.toInit {
				switch {
				case a.Kind == SendAccept && a.Slot != 0:
					apply(true, now, r.init.RecvExtraAccept(now, a.Epoch, a.Slot, p.iLoc, p.rAddr))
				case a.Kind == SendAccept:
					apply(true, now, r.init.RecvAccept(now, a.Epoch, p.rAddr, a.Paths))
				case a.Kind == SendAck:
					apply(true, now, r.init.RecvHandoverAck(now, a.Epoch, p.rAddr))
				}
				continue
			}
			switch {
			case a.Kind == SendNominate && a.Slot != 0:
				apply(false, now, r.resp.RecvExtraNominate(now, a.Epoch, a.Slot, p.rLoc, p.iAddr))
			case a.Kind == SendNominate:
				apply(false, now, r.resp.RecvNominate(now, a.Epoch, p.rLoc, p.iAddr, p.fam))
			case a.Kind == SendReady:
				apply(false, now, r.resp.RecvReady(now, a.Epoch, p.iAddr, a.Paths))
			}
		}
		apply(true, now, r.init.Tick(now))
		apply(false, now, r.resp.Tick(now))
	}
	return r
}

// mirror maps the initiator's extra paths to the responder's view.
func mirror(pairs []mpPair, xs []Candidate) []netip.AddrPort {
	var out []netip.AddrPort
	for _, x := range xs {
		for _, p := range pairs {
			if p.iLoc == x.Local && p.rAddr == x.Remote {
				out = append(out, p.rLoc, p.iAddr)
			}
		}
	}
	return out
}

func views(xs []Candidate) []netip.AddrPort {
	var out []netip.AddrPort
	for _, x := range xs {
		out = append(out, x.Local, x.Remote)
	}
	return out
}

// dualStackLAN: a LAN and a public IPv4 pair through the primary sockets,
// an IPv6 pair, and a second public IPv4 pair from another initiator
// socket to the responder's primary socket.
func dualStackLAN() []mpPair {
	return []mpPair{
		{iLoc: ap("192.168.1.2:4000"), rAddr: ap("192.168.1.3:5000"), rLoc: ap("192.168.1.3:5000"), iAddr: ap("192.168.1.2:4000"),
			fam: protocol.FamilyUDP4, path: protocol.PathLAN, kind: KindLAN, iSock: 0, rSock: 0, oneWay: time.Millisecond},
		{iLoc: ap("192.168.1.2:4000"), rAddr: ap("203.0.113.1:6000"), rLoc: ap("192.168.1.3:5000"), iAddr: ap("203.0.113.1:7000"),
			fam: protocol.FamilyUDP4, path: protocol.PathPublic, kind: KindObserved, iSock: 0, rSock: 0, oneWay: 10 * time.Millisecond},
		{iLoc: ap("[2001:db8::2]:4000"), rAddr: ap("[2001:db8::3]:5000"), rLoc: ap("[2001:db8::3]:5000"), iAddr: ap("[2001:db8::2]:4000"),
			fam: protocol.FamilyUDP6, path: protocol.PathPublic, kind: KindObserved, iSock: 0x80, rSock: 0x80, oneWay: 12 * time.Millisecond},
		{iLoc: ap("192.168.1.2:4001"), rAddr: ap("203.0.113.1:6000"), rLoc: ap("192.168.1.3:5000"), iAddr: ap("203.0.113.1:7001"),
			fam: protocol.FamilyUDP4, path: protocol.PathPublic, kind: KindObserved, iSock: 5, rSock: 0, oneWay: 10 * time.Millisecond},
	}
}

// With one path the machine sends no slot and no PATHS, and a session that
// may keep more but has no pair to add sends exactly the actions of one
// path, at the same instants: the primary path's handshake is unchanged
// (MaxPaths=1 behaves as if extra paths did not exist).
func TestOnePathUnchanged(t *testing.T) {
	single := dualStackLAN()[:1]
	run := func(maxPaths int) *mpRun { return mpExchange(single, [2]int{maxPaths, maxPaths}, 0, 1) }
	one, four := run(1), run(4)
	for _, r := range []*mpRun{one, four} {
		if r.iHand == nil || r.rHand == nil || len(r.iExtras)+len(r.rExtras) != 0 || r.firstReadyPaths != 0 {
			t.Fatalf("handover %v %v extras %v %v paths %b", r.iHand, r.rHand, r.iExtras, r.rExtras, r.firstReadyPaths)
		}
	}
	if one.handshakes != four.handshakes || !one.iReadyAt.Equal(four.iReadyAt) || one.iHand.ConfirmedBy != four.iHand.ConfirmedBy {
		t.Fatalf("one path %v at %v, four allowed %v at %v", one.handshakes, one.iReadyAt, four.handshakes, four.iReadyAt)
	}
	if !one.iReadyAt.Equal(one.iConfirmAt) {
		t.Fatal("one path waited before ready")
	}

	// Action by action, with every pair present: MaxPaths=1 never names a
	// slot or a PATHS value.
	m := NewManager(Config{Role: protocol.RoleInitiator})
	base := time.Unix(1, 0)
	for _, p := range dualStackLAN() {
		m.Success(base, p.iLoc, p.rAddr, p.fam, time.Millisecond)
		m.Describe(p.iLoc, p.rAddr, p.path, p.rSock)
	}
	acts := m.Tick(base.Add(time.Second))
	acts = append(acts, m.Tick(base.Add(1010*time.Millisecond))...)
	if len(acts) != 2 || acts[0].Kind != SendNominate || acts[0].Slot != 0 || acts[1].Slot != 0 {
		t.Fatalf("one path nominated %+v", acts)
	}
	acts = m.RecvAccept(base.Add(1020*time.Millisecond), m.Epoch(), acts[0].Remote, 7)
	if count(acts, SendReady) != 1 || acts[1].Paths != 0 || m.Phase() != PhaseReadying {
		t.Fatalf("one path after a room of 7: %+v", acts)
	}
	r := NewManager(Config{Role: protocol.RoleResponder})
	r.Success(base, ap("192.168.1.3:5000"), ap("192.168.1.2:4000"), protocol.FamilyUDP4, 0)
	r.Success(base, ap("192.168.1.3:5001"), ap("192.168.1.2:4000"), protocol.FamilyUDP4, 0)
	if a := r.RecvNominate(base, 1, ap("192.168.1.3:5000"), ap("192.168.1.2:4000"), protocol.FamilyUDP4); len(a) != 1 || a[0].Paths != 0 {
		t.Fatalf("one-path accept %+v", a)
	}
	if a := r.RecvExtraNominate(base, 1, 1, ap("192.168.1.3:5001"), ap("192.168.1.2:4000")); a != nil {
		t.Fatalf("one-path responder adopted an extra path: %+v", a)
	}
}

// Two sides that may keep four paths: the most different pairs become
// extra paths — IPv6, then the public IPv4 pair through the same sockets as
// the LAN primary — while the second public IPv4 pair, through the
// responder's primary socket again, is a duplicate; both sides commit the
// same set, on the pairs' own sockets.
func TestExtraPathsChosenAndAgreed(t *testing.T) {
	pairs := dualStackLAN()
	r := mpExchange(pairs, [2]int{4, 4}, 0, 2)
	if r.iHand == nil || r.rHand == nil {
		t.Fatal("no handover")
	}
	if c, _ := r.init.Winner(); c.Kind != KindLAN || c.Remote != pairs[0].rAddr {
		t.Fatalf("primary %v, want the LAN pair (fastest, chosen as with one path)", c.Remote)
	}
	if got, want := views(r.iExtras), []netip.AddrPort{pairs[2].iLoc, pairs[2].rAddr, pairs[1].iLoc, pairs[1].rAddr}; !slices.Equal(got, want) {
		t.Fatalf("initiator extras %v, want %v", got, want)
	}
	if got, want := views(r.rExtras), mirror(pairs, r.iExtras); !slices.Equal(got, want) {
		t.Fatalf("responder extras %v, want the initiator's %v", got, want)
	}
	if r.readyPathsChanged || r.firstReadyPaths != 0b110 {
		t.Fatalf("ready PATHS %b (changed %v)", r.firstReadyPaths, r.readyPathsChanged)
	}
	if wait := r.iReadyAt.Sub(r.iConfirmAt); wait < 0 || wait > maxRTO {
		t.Fatalf("ready %v after Confirm, beyond the settle bound", wait)
	}
}

// A responder with room for one extra path announces it on the primary
// path's accept; the initiator sends ready as soon as one extra accept is
// in, without waiting out the settle bound, and both keep two paths.
func TestRoomBoundsExtras(t *testing.T) {
	pairs := dualStackLAN()
	r := mpExchange(pairs, [2]int{4, 2}, 0, 3)
	if len(r.iExtras) != 1 || len(r.rExtras) != 1 || !slices.Equal(views(r.rExtras), mirror(pairs, r.iExtras)) {
		t.Fatalf("extras %v / %v", r.iExtras, r.rExtras)
	}
	if wait := r.iReadyAt.Sub(r.iConfirmAt); wait > 2*pairs[2].oneWay {
		t.Fatalf("ready %v after Confirm with the room already used", wait)
	}
	// A responder of one path announces no room: ready at once, no extra.
	r = mpExchange(pairs, [2]int{4, 1}, 0, 4)
	if len(r.iExtras)+len(r.rExtras) != 0 || !r.iReadyAt.Equal(r.iConfirmAt) {
		t.Fatalf("extras %v / %v, ready after %v", r.iExtras, r.rExtras, r.iReadyAt.Sub(r.iConfirmAt))
	}
}

// An extra path whose accept never comes delays ready by at most one rto
// (the settle bound), and is not committed by either side.
func TestSettleBound(t *testing.T) {
	pairs := dualStackLAN()[:3]
	pairs[2].oneWay = time.Second // the IPv6 accept arrives long after the bound
	r := mpExchange(pairs, [2]int{3, 3}, 0, 5)
	if r.iHand == nil || r.rHand == nil {
		t.Fatal("no handover")
	}
	if wait := r.iReadyAt.Sub(r.iConfirmAt); wait <= 0 || wait > maxRTO {
		t.Fatalf("ready %v after Confirm, want within (0, %v]", wait, maxRTO)
	}
	for _, x := range append(r.iExtras, r.rExtras...) {
		if x.Family == protocol.FamilyUDP6 {
			t.Fatalf("the late IPv6 path was committed: %v / %v", r.iExtras, r.rExtras)
		}
	}
	if !slices.Equal(views(r.rExtras), mirror(pairs, r.iExtras)) || len(r.iExtras) != 1 {
		t.Fatalf("extras %v / %v", r.iExtras, r.rExtras)
	}
}

// The responder adopts an extra path only within the adoption of the
// primary path at the same epoch, never a duplicate, never past its room;
// a higher epoch drops what it held.
func TestResponderExtraAdoption(t *testing.T) {
	base := time.Unix(1, 0)
	pairs := dualStackLAN()
	r := NewManager(Config{Role: protocol.RoleResponder, MaxPaths: 3})
	for _, p := range pairs {
		r.Success(base, p.rLoc, p.iAddr, p.fam, 0)
		r.Describe(p.rLoc, p.iAddr, p.path, p.iSock)
	}
	if a := r.RecvExtraNominate(base, 1, 1, pairs[2].rLoc, pairs[2].iAddr); a != nil {
		t.Fatalf("adopted an extra path before the primary: %+v", a)
	}
	acts := r.RecvNominate(base, 1, pairs[0].rLoc, pairs[0].iAddr, protocol.FamilyUDP4)
	if len(acts) != 1 || acts[0].Paths != 2 {
		t.Fatalf("primary accept %+v, want the room 2", acts)
	}
	if a := r.RecvExtraNominate(base, 2, 1, pairs[2].rLoc, pairs[2].iAddr); a != nil {
		t.Fatal("adopted an extra path of another epoch")
	}
	if a := r.RecvExtraNominate(base, 1, 1, pairs[2].rLoc, pairs[2].iAddr); len(a) != 1 || a[0].Slot != 1 || a[0].Remote != pairs[2].iAddr {
		t.Fatalf("extra accept %+v", a)
	}
	if a := r.RecvExtraNominate(base, 1, 1, pairs[2].rLoc, pairs[2].iAddr); len(a) != 1 {
		t.Fatal("a repeat was not answered")
	}
	if a := r.RecvExtraNominate(base, 1, 1, pairs[1].rLoc, pairs[1].iAddr); a != nil {
		t.Fatal("another pair took an adopted slot")
	}
	// pairs[3] reaches the responder's primary socket as public, like
	// pairs[1]: one of them is a duplicate of the other.
	if a := r.RecvExtraNominate(base, 1, 2, pairs[1].rLoc, pairs[1].iAddr); len(a) != 1 {
		t.Fatal("the public pair was refused")
	}
	if a := r.RecvExtraNominate(base, 1, 3, pairs[3].rLoc, pairs[3].iAddr); a != nil {
		t.Fatal("past the room, and a duplicate")
	}
	r.RecvReady(base, 1, pairs[0].iAddr, 1<<2)
	if got := r.Extras(); len(got) != 1 || got[0].Remote != pairs[1].iAddr {
		t.Fatalf("committed %v, want slot 2 only", got)
	}
	if r.Phase() != PhaseConfirmed {
		t.Fatal("not confirmed")
	}

	// A higher epoch drops the extra paths of the old adoption.
	r = NewManager(Config{Role: protocol.RoleResponder, MaxPaths: 3})
	for _, p := range pairs {
		r.Success(base, p.rLoc, p.iAddr, p.fam, 0)
	}
	r.RecvNominate(base, 1, pairs[0].rLoc, pairs[0].iAddr, protocol.FamilyUDP4)
	r.RecvExtraNominate(base, 1, 1, pairs[2].rLoc, pairs[2].iAddr)
	r.RecvNominate(base, 2, pairs[1].rLoc, pairs[1].iAddr, protocol.FamilyUDP4)
	r.RecvReady(base, 2, pairs[1].iAddr, 1<<1)
	if got := r.Extras(); len(got) != 0 {
		t.Fatalf("committed %v from an overridden adoption", got)
	}
}

// A socket that stops reading takes its pending extra path with it; the
// initiator that waited only for it sends ready at once.
func TestReadFailedDropsExtra(t *testing.T) {
	base := time.Unix(1, 0)
	pairs := dualStackLAN()[:3]
	m := NewManager(Config{Role: protocol.RoleInitiator, MaxPaths: 3})
	for _, p := range pairs {
		m.Success(base, p.iLoc, p.rAddr, p.fam, 20*time.Millisecond)
		m.Describe(p.iLoc, p.rAddr, p.path, p.rSock)
	}
	acts := m.Tick(base.Add(time.Second))
	if count(acts, SendNominate) != 3 {
		t.Fatalf("nominations %+v", acts)
	}
	now := base.Add(time.Second + 30*time.Millisecond)
	m.RecvExtraAccept(now, m.Epoch(), 2, pairs[1].iLoc, pairs[1].rAddr)
	if acts := m.RecvAccept(now, m.Epoch(), pairs[0].rAddr, 2); count(acts, Confirm) != 1 || count(acts, SendReady) != 0 || m.Phase() != PhaseSettling {
		t.Fatalf("after the primary accept: %+v phase %v", acts, m.Phase())
	}
	acts = m.ReadFailed(now.Add(time.Millisecond), pairs[2].iLoc)
	if count(acts, SendReady) != 1 || acts[0].Paths != 1<<2 {
		t.Fatalf("after the IPv6 socket failed: %+v", acts)
	}
	if got := m.Extras(); len(got) != 1 || got[0].Remote != pairs[1].rAddr {
		t.Fatalf("committed %v", got)
	}
	// An upper-layer datagram on the committed extra path is the
	// responder's handover evidence too.
	if acts := m.RecvUpperLayer(now.Add(5*time.Millisecond), pairs[1].iLoc, pairs[1].rAddr); count(acts, HandOver) != 1 {
		t.Fatalf("upper layer on the extra path: %+v", acts)
	}
}

// Under loss both sides that hand over hold the same extra paths, every
// ready carries the same PATHS, and neither holds a duplicate.
func TestExtraPathsAgreeUnderLoss(t *testing.T) {
	pairs := dualStackLAN()
	agreed := 0
	for seed := range uint64(300) {
		r := mpExchange(pairs, [2]int{4, 3}, 0.3, seed)
		checkMultiPath(t, pairs, r)
		if r.iHand != nil && r.rHand != nil {
			agreed++
		}
	}
	if agreed < 250 {
		t.Fatalf("%d/300 exchanges handed over on both sides", agreed)
	}
}

// checkMultiPath asserts the invariants of an exchange.
func checkMultiPath(t *testing.T, pairs []mpPair, r *mpRun) {
	t.Helper()
	if r.readyPathsChanged {
		t.Fatal("a later ready changed PATHS")
	}
	for side, xs := range [2][]Candidate{r.iExtras, r.rExtras} {
		m := r.init
		if side == 1 {
			m = r.resp
		}
		var held []*Candidate
		if c, ok := m.Winner(); ok {
			held = append(held, &c)
		}
		for i := range xs {
			if duplicateOfAny(&xs[i], held) {
				t.Fatalf("side %d holds duplicate paths: %v", side, xs)
			}
			held = append(held, &xs[i])
		}
		if len(xs) > protocol.MaxPaths-1 {
			t.Fatalf("%d extra paths", len(xs))
		}
	}
	if r.iHand != nil && r.rHand != nil && r.rHand.ConfirmedBy == protocol.ConfirmedByReady &&
		!slices.Equal(views(r.rExtras), mirror(pairs, r.iExtras)) {
		t.Fatalf("initiator %v, responder %v", r.iExtras, r.rExtras)
	}
	// The primary path's resends are bounded by the rounds and the
	// handshake reserve of the caller; the extra paths' by the campaign:
	// per extra path the first burst, the resends of the primary path's
	// nominate and those of the settle wait (at most 150 ms / 40 ms), and
	// one accept per nominate.
	perCampaign := (protocol.MaxPaths - 1) * (2 + 3 + 4)
	if r.extraPackets[0] > int(r.init.Epoch())*perCampaign || r.extraPackets[1] > r.extraPackets[0] {
		t.Fatalf("extra-path packets %v in %d campaigns", r.extraPackets, r.init.Epoch())
	}
}

// FuzzMultiPath drives the exchange with fuzzer-chosen pairs, rooms, loss
// and delays: no panic, and the invariants of checkMultiPath hold.
func FuzzMultiPath(f *testing.F) {
	f.Add(uint8(4), uint8(3), uint8(30), uint64(1), []byte{1, 10, 12, 10})
	f.Add(uint8(2), uint8(8), uint8(0), uint64(2), []byte{200, 1})
	f.Add(uint8(8), uint8(8), uint8(60), uint64(3), []byte{5, 5, 5, 5, 5, 5, 5, 5, 5})
	f.Fuzz(func(t *testing.T, mi, mr, lossPct uint8, seed uint64, delays []byte) {
		all := dualStackLAN()
		var pairs []mpPair
		for i, d := range delays {
			if i >= 12 {
				break
			}
			p := all[i%len(all)]
			if i >= len(all) {
				// More pairs from further initiator sockets.
				p.iLoc = netip.AddrPortFrom(p.iLoc.Addr(), p.iLoc.Port()+uint16(10*i))
				p.iAddr = netip.AddrPortFrom(p.iAddr.Addr(), p.iAddr.Port()+uint16(10*i))
				p.iSock += uint8(i)
			}
			p.oneWay = time.Duration(d%250+1) * time.Millisecond
			pairs = append(pairs, p)
		}
		if len(pairs) == 0 {
			return
		}
		r := mpExchange(pairs, [2]int{int(mi % 10), int(mr % 10)}, float64(lossPct%80)/100, seed)
		checkMultiPath(t, pairs, r)
	})
}

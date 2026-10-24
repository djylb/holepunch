package probe

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/stun"
)

func TestMain(m *testing.M) { goroutines.VerifyTestMain(m) }

// A small discrete-event world: one client host behind a configurable NAT,
// a natprobe-like server (three ports on 198.51.100.1, an optional alt IP
// 198.51.100.2, an extra pool port), an optional STUN server. The prober's
// state machine is stepped directly (stepRun, deterministic) or runs in its
// goroutine on the fake clock (loopRun, loopHairpin), which the world
// advances only while that goroutine is idle, so that run is deterministic
// too.

var (
	srvIP    = netip.MustParseAddr("198.51.100.1")
	altIP    = netip.MustParseAddr("198.51.100.2")
	pubIP    = netip.MustParseAddr("203.0.113.5")
	stunAddr = netip.MustParseAddrPort("192.0.2.50:3478")
)

type natCfg struct {
	noNAT     bool
	mapping   protocol.Mapping // EIM, ADM, APDM
	alloc     string           // pres | seq | random
	step      int
	velocity  float64 // background allocations, ports/s (seq)
	base      int
	filtering protocol.Filtering // EIF, ADF, PDF
	hairpin   bool
	pub       netip.Addr // default pubIP
}

type event struct {
	at  time.Duration
	seq int
	fn  func()
}

type pktLog struct {
	at       time.Duration
	from, to netip.AddrPort
	out      bool
}

type sim struct {
	t     *testing.T
	mu    sync.Mutex
	fake  *clock.Fake
	start time.Time
	now   time.Duration
	evs   []event
	evSeq int
	owd   time.Duration
	rng   *rand.Rand
	loss  float64

	nat       natCfg
	seqPos    float64
	lastAlloc time.Duration
	used      map[uint16]bool
	mappings  map[string]mapping
	contacted map[netip.AddrPort][]netip.AddrPort
	socks     map[uint8]*simSock

	// server
	unreachable bool
	icmp        bool
	extraReply  bool
	altGroup    bool
	extraLeft   int
	altLeft     int
	extraPort   netip.AddrPort
	altPort     netip.AddrPort
	slotCookie  map[[2]uint8]uint32
	slotObs     map[[2]uint8]netip.AddrPort
	replySeq    uint32
	srvWin      udpwire.SeqWindow
	cliWin      udpwire.SeqWindow
	stunOn      bool
	stunWrongV6 bool          // the STUN server answers with an IPv6 address
	stunDelay   time.Duration // the STUN server's answer arrives this long after the request; 0: one RTT
	extraFirst  bool          // the extra leaves before the ack

	cli, srv  *udpwire.Codec
	spec      Spec
	p         *Prober
	log       []pktLog
	writeErr  func(sock uint8, to netip.AddrPort) error
	observers []protocol.ObserverSpec

	// Loop mode (drive): selects counts the selects of the goroutine under
	// test, awaited is the count it reaches once it consumed every stimulus
	// delivered so far, and exited reports that it returned. wakes is
	// whether it selects on the ICMP wake-up channel (Run, not Hairpin).
	loop, wakes bool
	selects     atomic.Int64
	awaited     int64
	exited      atomic.Bool
}

// selectClock is the fake clock as the prober sees it: Run and Hairpin
// read their timer's C exactly once per select, so its timers count the
// selects of the goroutine under test.
type selectClock struct {
	*clock.Fake
	selects *atomic.Int64
}

func (c selectClock) NewTimer(d time.Duration) clock.Timer {
	return selectTimer{Timer: c.Fake.NewTimer(d), selects: c.selects}
}

type selectTimer struct {
	clock.Timer
	selects *atomic.Int64
}

func (t selectTimer) C() <-chan time.Time {
	t.selects.Add(1)
	return t.Timer.C()
}

type mapping struct {
	sock uint8
	ext  netip.AddrPort
}

type simSock struct {
	sim   *sim
	id    uint8
	local netip.AddrPort
}

func (s *simSock) ID() uint8             { return s.id }
func (s *simSock) Local() netip.AddrPort { return s.local }
func (s *simSock) WriteTo(b []byte, to netip.AddrPort) error {
	return s.sim.write(s, append([]byte(nil), b...), to)
}

type simOpts struct {
	nat        natCfg
	role       udpwire.Role
	rtt        time.Duration
	loss       float64
	seed       uint64
	alt        bool
	stun       bool
	siblings   uint8
	second     bool
	extraReply bool
	ports      int
	rttHint    uint16
	timeout    time.Duration
}

func defaultOpts() simOpts {
	return simOpts{nat: natCfg{mapping: protocol.MapEIM, alloc: "pres", filtering: protocol.FiltEIF},
		role: udpwire.RoleInitiator, rtt: 40 * time.Millisecond, seed: 1, second: true, extraReply: true, ports: 3}
}

func testKeys() ([32]byte, [16]byte) {
	var token [32]byte
	var route [16]byte
	for i := range token {
		token[i] = byte(i)
	}
	for i := range route {
		route[i] = byte(0x20 + i)
	}
	return token, route
}

func newSim(t *testing.T, o simOpts) *sim {
	t.Helper()
	fake := clock.NewFake(t, time.Time{})
	token, route := testKeys()
	cli, err := udpwire.NewCodec(token, route, o.role, udpwire.PadPolicy{Min: 64, Max: 128}, fake.Now)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := udpwire.NewCodec(token, route, udpwire.RoleServer, udpwire.PadPolicy{}, fake.Now)
	if err != nil {
		t.Fatal(err)
	}
	if !o.nat.pub.IsValid() {
		o.nat.pub = pubIP
	}
	s := &sim{t: t, fake: fake, start: fake.Now(), owd: o.rtt / 2, rng: rand.New(rand.NewPCG(o.seed, 7)), loss: o.loss,
		nat: o.nat, used: map[uint16]bool{}, mappings: map[string]mapping{}, contacted: map[netip.AddrPort][]netip.AddrPort{},
		socks: map[uint8]*simSock{}, extraReply: o.extraReply, altGroup: o.alt, extraLeft: 8, altLeft: 2,
		extraPort: netip.AddrPortFrom(srvIP, 40999), altPort: netip.AddrPortFrom(altIP, 41999),
		slotCookie: map[[2]uint8]uint32{}, slotObs: map[[2]uint8]netip.AddrPort{}, stunOn: o.stun, cli: cli, srv: srv}
	if s.nat.base == 0 {
		s.nat.base = 50000
	}
	for i := range o.ports {
		s.observers = append(s.observers, protocol.ObserverSpec{ID: uint8(i), Addr: netip.AddrPortFrom(srvIP, uint16(3478+i))})
	}
	if o.alt {
		s.observers = append(s.observers, protocol.ObserverSpec{ID: 8, Addr: netip.AddrPortFrom(altIP, 3478), Group: 1, Alt: true})
	}
	ps := protocol.ProbeSpec{V: protocol.ProbeSpecVersion, Observers: s.observers, ExtraReply: o.extraReply, SecondSocket: o.second,
		Siblings: o.siblings, RTTHintMs: o.rttHint}
	if o.stun {
		ps.STUN = []netip.AddrPort{stunAddr}
	}
	primary := s.sock(nat.SocketID(protocol.FamilyUDP4, nat.IndexPrimary), "192.168.1.10:40000")
	var sibs []SocketHandle
	for i := range o.siblings {
		sibs = append(sibs, s.sock(nat.SocketID(protocol.FamilyUDP4, nat.IndexSibling+i), fmt.Sprintf("10.8.%d.2:40000", i)))
	}
	s.spec = Spec{Codec: cli, Probe: ps, Family: protocol.FamilyUDP4, Timeout: o.timeout, Clock: selectClock{Fake: fake, selects: &s.selects}}
	s.p = New(s.spec, primary, sibs, func() (SocketHandle, error) {
		return s.sock(nat.SocketID(protocol.FamilyUDP4, nat.IndexSecond), "192.168.1.10:40001"), nil
	})
	return s
}

func (s *sim) sock(id uint8, local string) *simSock {
	ss := &simSock{sim: s, id: id, local: netip.MustParseAddrPort(local)}
	s.socks[id] = ss
	return ss
}

// schedule runs fn at now+d (the caller holds mu).
func (s *sim) schedule(d time.Duration, fn func()) {
	s.evSeq++
	s.evs = append(s.evs, event{at: s.now + d, seq: s.evSeq, fn: fn})
}

func (s *sim) lost() bool { return s.loss > 0 && s.rng.Float64() < s.loss }

// extFor returns the NAT mapping of a socket toward dest.
func (s *sim) extFor(ss *simSock, dest netip.AddrPort) netip.AddrPort {
	local := ss.local
	if s.nat.noNAT {
		return local
	}
	key := local.String()
	switch s.nat.mapping {
	case protocol.MapADM:
		key += "|" + dest.Addr().String()
	case protocol.MapAPDM:
		key += "|" + dest.String()
	case protocol.MapUnknown, protocol.MapEIM:
		// One mapping per socket.
	}
	if m, ok := s.mappings[key]; ok {
		return m.ext
	}
	var port int
	switch s.nat.alloc {
	case "pres":
		port = int(local.Port())
		for s.used[uint16(port)] {
			port++
		}
	case "seq":
		step := max(abs(s.nat.step), 1)
		s.seqPos += s.nat.velocity * (s.now - s.lastAlloc).Seconds() / float64(step)
		s.lastAlloc = s.now
		s.seqPos++
		port = s.nat.base + s.nat.step*int(math.Floor(s.seqPos+1e-9))
	default:
		port = 1024 + s.rng.IntN(64000)
	}
	s.used[uint16(port)] = true
	ext := netip.AddrPortFrom(s.nat.pub, uint16(port))
	s.mappings[key] = mapping{sock: ss.id, ext: ext}
	return ext
}

func (s *sim) write(from *simSock, b []byte, to netip.AddrPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		if err := s.writeErr(from.id, to); err != nil {
			return err
		}
	}
	ext := s.extFor(from, to)
	if !slices.Contains(s.contacted[ext], to) {
		s.contacted[ext] = append(s.contacted[ext], to)
	}
	s.log = append(s.log, pktLog{at: s.now, from: ext, to: to, out: true})
	if s.lost() {
		return nil
	}
	switch {
	case to == stunAddr && s.stunOn && s.stunDelay > 0:
		s.schedule(s.stunDelay-s.owd, func() { s.stunReply(b, ext) })
	case to == stunAddr && s.stunOn:
		s.schedule(s.owd, func() { s.stunReply(b, ext) })
	case to.Addr() == srvIP || to.Addr() == altIP:
		if s.unreachable {
			if s.icmp {
				s.schedule(2*s.owd, func() { s.noteICMP(from.id) })
			}
			return nil
		}
		s.schedule(s.owd, func() { s.serve(b, ext, to) })
	case to.Addr() == s.nat.pub && s.nat.hairpin:
		s.schedule(s.owd, func() { s.toClient(b, ext, to) })
	}
	return nil
}

func (s *sim) observer(addr netip.AddrPort) (protocol.ObserverSpec, bool) {
	for _, o := range s.observers {
		if o.Addr == addr {
			return o, true
		}
	}
	return protocol.ObserverSpec{}, false
}

// serve plays natprobe for one probe (the caller holds mu).
func (s *sim) serve(pkt []byte, src, dst netip.AddrPort) {
	o, ok := s.observer(dst)
	if !ok {
		return
	}
	var h udpwire.Header
	var t udpwire.TLVs
	if de := s.srv.OpenProbe(pkt, make([]byte, len(pkt)), &h, &t); de != udpwire.OK {
		s.t.Errorf("server open: %v", de)
		return
	}
	if s.srv.CheckRole(&h) != udpwire.OK || h.Aux != uint16(o.ID) || !s.srvWin.Accept(h.Seq) {
		s.t.Errorf("server rejected probe %+v", h)
		return
	}
	slot := [2]uint8{h.Sock, o.ID}
	if s.slotObs[slot] != src || s.slotCookie[slot] == 0 {
		s.slotObs[slot] = src
		s.slotCookie[slot] = 1 + s.rng.Uint32()%(1<<31)
	}
	wantExtra := h.FA && s.extraReply && s.extraLeft > 0
	wantAlt := h.FB && s.altGroup && s.altLeft > 0 && !o.Alt
	ackLen, secLen := udpwire.ReplyLengths(len(pkt), wantExtra || wantAlt, false, s.rng)
	sendExtra, sendAlt := wantExtra && secLen > 0, wantAlt && secLen > 0
	if sendExtra {
		s.extraLeft--
	}
	if sendAlt {
		s.altLeft--
	}
	quota := (h.FA && s.extraLeft == 0) || (h.FB && s.altLeft == 0)
	s.replySeq++
	ah := udpwire.Header{Type: udpwire.TProbeAck, Role: udpwire.RoleServer, FA: sendExtra, FB: sendAlt, FC: quota, Sock: h.Sock,
		Cand: udpwire.NoCand, Aux: h.Aux, Seq: s.replySeq, TS: uint32(s.fake.Now().UnixMilli()), EchoSeq: h.Seq, EchoTS: h.TS}
	at := udpwire.TLVs{Observed: src, Cookie: s.slotCookie[slot]}
	if sendExtra {
		at.ExtraPort = s.extraPort.Port()
	}
	ack, err := s.srv.Seal(nil, &ah, &at, ackLen)
	if err != nil {
		s.t.Errorf("seal ack: %v", err)
		return
	}
	second := func() {
		if !sendExtra && !sendAlt {
			return
		}
		s.replySeq++
		typ, from := udpwire.TProbeExtra, s.extraPort
		if sendAlt {
			typ, from = udpwire.TProbeAlt, s.altPort
		}
		xh := udpwire.Header{Type: typ, Role: udpwire.RoleServer, Sock: h.Sock, Cand: udpwire.NoCand, Aux: h.Aux, Seq: s.replySeq,
			TS: ah.TS, EchoSeq: h.Seq, EchoTS: h.TS}
		x, err := s.srv.Seal(nil, &xh, &udpwire.TLVs{Observed: src}, secLen)
		if err != nil {
			s.t.Errorf("seal extra: %v", err)
			return
		}
		s.sendToClient(x, from, src)
	}
	if s.extraFirst {
		second()
		s.sendToClient(ack, dst, src)
	} else {
		s.sendToClient(ack, dst, src)
		second()
	}
}

func (s *sim) sendToClient(pkt []byte, from, to netip.AddrPort) {
	if s.lost() {
		return
	}
	s.schedule(s.owd, func() { s.toClient(pkt, from, to) })
}

// toClient passes the NAT filter and plays the read pump (the caller holds mu).
func (s *sim) toClient(pkt []byte, from, to netip.AddrPort) {
	s.log = append(s.log, pktLog{at: s.now, from: from, to: to})
	var sock *simSock
	for _, m := range s.mappings {
		if m.ext == to {
			sock = s.socks[m.sock]
		}
	}
	if s.nat.noNAT {
		for _, ss := range s.socks {
			if ss.local == to {
				sock = ss
			}
		}
	}
	if sock == nil {
		return
	}
	if from.Addr() != s.nat.pub { // hairpinned packets bypass the filter
		cs := s.contacted[to]
		switch s.nat.filtering {
		case protocol.FiltADF:
			if !slices.ContainsFunc(cs, func(a netip.AddrPort) bool { return a.Addr() == from.Addr() }) {
				return
			}
		case protocol.FiltPDF:
			if !slices.Contains(cs, from) {
				return
			}
		case protocol.FiltUnknown, protocol.FiltEIF, protocol.FiltNotPDF:
			// Every source passes.
		}
	}
	if IsSTUN(pkt) {
		if s.p.DeliverSTUN(sock.id, from, pkt, s.fake.Now()) {
			s.stimulus()
		}
		return
	}
	var h udpwire.Header
	var t udpwire.TLVs
	if de := s.cli.Open(pkt, make([]byte, len(pkt)), &h, &t); de != udpwire.OK {
		s.t.Errorf("client open: %v", de)
		return
	}
	if s.cli.CheckRole(&h) != udpwire.OK {
		return
	}
	if h.Role == udpwire.RoleServer && !s.cliWin.Accept(h.Seq) {
		return
	}
	if s.p.Deliver(sock.id, from, &h, &t, s.fake.Now()) {
		s.stimulus()
	}
}

// noteICMP plays the read pump's ICMP unreachable note on socket sock.
func (s *sim) noteICMP(sock uint8) {
	before := s.p.icmp.Load()
	s.p.NoteUnreachable(sock)
	if s.wakes && s.p.icmp.Load() != before {
		s.stimulus()
	}
}

// stimulus records that the goroutine under test has one more thing to
// consume: once it has, it selects once more.
func (s *sim) stimulus() {
	if s.loop {
		s.awaited++
	}
}

// settle waits, in real time, until the goroutine under test has consumed
// every stimulus and is back in its select, or has returned. The world
// delivers one stimulus at a time and settles after each, so each one is
// consumed by a select of its own: none is coalesced or discarded.
func (s *sim) settle() {
	if !s.loop {
		return
	}
	for start := time.Now(); s.selects.Load() < s.awaited && !s.exited.Load(); time.Sleep(20 * time.Microsecond) {
		if time.Since(start) > 30*time.Second {
			s.t.Fatalf("the goroutine under test is stuck: %d selects, %d awaited", s.selects.Load(), s.awaited)
		}
	}
}

// stunReply answers a Binding Request with the request's mapped address,
// or with an IPv6 address when stunWrongV6 is set.
func (s *sim) stunReply(req []byte, ext netip.AddrPort) {
	txid, ok := stun.ParseBindingRequest(req)
	if !ok {
		return
	}
	mapped := ext
	if s.stunWrongV6 {
		mapped = netip.MustParseAddrPort("[2001:db8::5]:40000")
	}
	s.sendToClient(stun.AppendBindingResponse(nil, txid, mapped), stunAddr, ext)
}

// nextEvent returns the earliest pending event time, or -1.
func (s *sim) nextEvent() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.evs) == 0 {
		return -1
	}
	return slices.MinFunc(s.evs, cmpEvent).at
}

func cmpEvent(a, b event) int {
	if a.at != b.at {
		if a.at < b.at {
			return -1
		}
		return 1
	}
	return a.seq - b.seq
}

// advanceTo moves time to t and runs every event due at or before it. In
// loop mode the goroutine under test consumes each stimulus — a fired
// timer, a delivered packet, an ICMP note — before the next one.
func (s *sim) advanceTo(t time.Duration) {
	for {
		s.mu.Lock()
		slices.SortStableFunc(s.evs, cmpEvent)
		if len(s.evs) == 0 || s.evs[0].at > t {
			s.now = t
			s.mu.Unlock()
			s.clockTo(t)
			return
		}
		e := s.evs[0]
		s.evs = s.evs[1:]
		s.now = e.at
		s.mu.Unlock()
		s.clockTo(e.at)
		s.mu.Lock()
		e.fn()
		s.mu.Unlock()
		s.settle()
	}
}

// clockTo advances the fake clock to t; a timer that fires is a stimulus.
func (s *sim) clockTo(t time.Duration) {
	for range s.fake.AdvanceTo(s.start.Add(t)) {
		s.stimulus()
	}
	s.settle()
}

// stepRun drives the state machine deterministically, without a goroutine,
// the way Run does: consume the inbox, step, sleep until the next wake-up or
// network event.
func (s *sim) stepRun() Result { return s.stepRunHook(nil) }

// stepRunHook is stepRun with a hook called after every advance of the
// simulated time, so that a test can drop a specific in-flight packet.
func (s *sim) stepRunHook(hook func(now time.Duration)) Result {
	p := s.p
	if !p.ran.CompareAndSwap(false, true) {
		s.t.Fatal("ran twice")
	}
	defer p.finished.Store(true)
	rs := newRunState(p)
	if p.setupErr != "" {
		return rs.finish(protocol.ReasonInternal, p.setupErr)
	}
	if len(rs.main) == 0 {
		return rs.finish(protocol.ReasonNoProbeEndpoint, "")
	}
	p.active.Store(true)
	defer p.active.Store(false)
	for range 100000 {
		for drained := false; !drained; {
			select {
			case in := <-p.inbox:
				rs.handle(in)
			default:
				drained = true
			}
		}
		now := s.now
		if r, done := rs.step(now); done {
			return r
		}
		next := rs.nextWake(now)
		e := s.nextEvent()
		if e >= 0 && e < next {
			next = e
		}
		// A network event due now (zero RTT) runs without moving time; a
		// wake-up that is already due means the machine is stuck.
		if next < now || (next == now && e != now) {
			s.t.Fatalf("time does not advance at %v", now)
		}
		s.advanceTo(next)
		if hook != nil {
			hook(s.now)
		}
	}
	s.t.Fatal("the simulation did not terminate")
	return Result{}
}

// dropFirstEventAt removes the earliest-scheduled event due at t.
func (s *sim) dropFirstEventAt(t time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	best := -1
	for i, e := range s.evs {
		if e.at == t && (best < 0 || e.seq < s.evs[best].seq) {
			best = i
		}
	}
	if best < 0 {
		return false
	}
	s.evs = slices.Delete(s.evs, best, best+1)
	return true
}

func (s *sim) sentTo(ip netip.Addr) []pktLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pktLog
	for _, l := range s.log {
		if l.out && l.to.Addr() == ip {
			out = append(out, l)
		}
	}
	return out
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

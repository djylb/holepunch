package probe

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/clock"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// SocketHandle is a probing socket as its owner, the session runtime,
// exposes it: the prober only writes.
type SocketHandle interface {
	// ID returns sock = family<<7 | index (primary 0, second 1, siblings 2–3).
	ID() uint8
	// Local returns the concrete local address (wildcards expanded).
	Local() netip.AddrPort
	// WriteTo sends one datagram through the runtime's single send gate
	// (probe class: 100 ms write deadline, ctx check, counted apart from the
	// punching budget). It must not retain b.
	WriteTo(b []byte, to netip.AddrPort) error
}

// Spec configures a Prober. The sender role is the codec's.
type Spec struct {
	Codec   *udpwire.Codec     // the session codec, shared by the families
	Probe   protocol.ProbeSpec // punch_start.probe, validated by protocol
	Family  protocol.Family    // the family this prober probes
	Timeout time.Duration      // timeouts.probe_timeout_ms; ≤ 0 means 2000 ms; clamped to [500 ms, 10 s]
	Clock   clock.Clock        // nil means the system clock
}

// Counters count what a Prober sent and received, for budget assertions and
// diagnostics.
type Counters struct {
	Primary    uint16 // probes from the primary socket to main-group observers
	TopUp      uint16 // the single WANT_EXTRA top-up to observer 0
	Second     uint16 // probes from the second socket
	Sibling    uint16 // probes from sibling sockets
	Alt        uint16 // solicited probes to the alt group
	STUN       uint16 // STUN binding requests
	SendErrors uint16 // writes to the server that failed or panicked
	STUNErrors uint16 // STUN writes that failed or panicked: the optional sub-probe never counts against the family
	Rejected   uint32 // delivered replies matching no probe (seq, socket, observer, source)
	Dropped    uint32 // replies dropped because the inbox was full
	ICMP       uint32 // ICMP unreachable notes on the primary socket
}

// Result is the outcome of Run.
type Result struct {
	Table   *nat.ObsTable        // never nil; stays live for peer_seen rows while punching
	Traits  protocol.Traits      // provisional classification
	Clock   protocol.ClockSample // minimum-RTT sample; the offset is diagnostic only
	Sent    Counters             // what was sent and received
	Failure protocol.Reason      // "", probe_timeout, udp_blocked, no_probe_endpoint, internal, or the ctx cause
	Detail  string               // send_failed, icmp_unreachable, panic:probe/<family>, ...
	// Panic is the panic Run recovered inside the prober, which failed the
	// family with internal (Detail panic:probe/<family>); nil otherwise. The
	// runtime makes it the session's Error.Err when no family survives.
	Panic *life.PanicError
}

// Prober probes one family. Create it with New, call Run once on a session
// goroutine, feed it from the read pumps with Deliver, DeliverSTUN and
// NoteUnreachable, and optionally call Hairpin after Run returned.
type Prober struct {
	spec        Spec
	clk         clock.Clock
	role        udpwire.Role
	primary     SocketHandle
	primaryID   uint8
	siblings    []sibling
	openSecond  func() (SocketHandle, error)
	table       *nat.ObsTable
	observers   []nat.Observer
	stunServers []stunServer // the family's STUN servers; read-only after New
	setupErr    string       // internal detail when New got an unusable argument

	inbox chan inbound
	wake  chan struct{}

	active   atomic.Bool // Run or Hairpin is consuming the inbox
	ran      atomic.Bool
	finished atomic.Bool
	hairpin  atomic.Bool // the hairpin self-test started; it runs once
	dropped  atomic.Uint32
	icmp     atomic.Uint32

	observed netip.AddrPort // the primary's observed address; written by Run before finished is set
}

type sibling struct {
	h  SocketHandle
	id uint8
}

// inbound is one delivered packet, copied out of the pump's buffers.
type inbound struct {
	stun   bool
	sock   uint8
	from   netip.AddrPort
	h      udpwire.Header
	t      udpwire.TLVs
	txid   [12]byte
	mapped netip.AddrPort
	at     time.Time
}

// New returns a prober for spec.Family with the given primary socket, the
// sibling sockets (at most min(spec.Probe.Siblings, 2) of this family with
// index 2 or 3 are probed) and a function that opens the second socket on
// demand (nil: never). It never fails; an unusable argument makes Run return
// Failure internal with a detail naming it.
func New(spec Spec, primary SocketHandle, siblings []SocketHandle, openSecond func() (SocketHandle, error)) *Prober {
	p := &Prober{
		spec:       spec,
		clk:        spec.Clock,
		openSecond: openSecond,
		inbox:      make(chan inbound, inboxCap),
		wake:       make(chan struct{}, 1),
	}
	if p.clk == nil {
		p.clk = clock.System{}
	}
	var socks []nat.SocketMeta
	switch role, ok := codecRole(spec.Codec); {
	case !spec.Family.Valid():
		p.setupErr = "bad_family"
	case spec.Codec == nil:
		p.setupErr = "nil_codec"
	case !ok:
		p.setupErr = "bad_codec"
	default:
		p.role = role
		m, ok := socketMeta(primary, spec.Family, protocol.SocketPrimary)
		if !ok || m.ID != nat.SocketID(spec.Family, nat.IndexPrimary) {
			p.setupErr = "bad_primary"
			break
		}
		p.primary, p.primaryID = primary, m.ID
		socks = append(socks, m)
	}
	for _, s := range siblings {
		if len(p.siblings) == int(min(spec.Probe.Siblings, maxSiblings)) {
			break
		}
		m, ok := socketMeta(s, spec.Family, protocol.SocketSibling)
		if idx := m.ID & 0x7F; ok && (idx == nat.IndexSibling || idx == nat.IndexSibling+1) {
			p.siblings = append(p.siblings, sibling{h: s, id: m.ID})
			socks = append(socks, m)
		}
	}
	p.observers = nat.Observers(spec.Family, spec.Probe.Observers)
	p.stunServers = stunServers(spec)
	p.table = nat.NewTable(spec.Family, socks, p.observers)
	return p
}

// codecRole returns the client role the session codec seals as; Seal needs it
// in every header. A server codec is refused: a prober only runs on clients.
func codecRole(c *udpwire.Codec) (udpwire.Role, bool) {
	if c == nil {
		return 0, false
	}
	switch r := c.Role(); r {
	case udpwire.RoleInitiator, udpwire.RoleResponder:
		return r, true
	default:
		return 0, false
	}
}

// socketMeta reads a handle's id and local address inside a recover
// boundary: the runtime's implementation is outside this package. Nil,
// typed-nil, panicking and other-family handles are refused.
func socketMeta(h SocketHandle, f protocol.Family, k protocol.SocketKind) (m nat.SocketMeta, ok bool) {
	if life.IsNil(h) {
		return m, false
	}
	if err := life.Safe("probe/socket", func() { m = nat.SocketMeta{ID: h.ID(), Kind: k, Local: h.Local()} }); err != nil {
		return m, false
	}
	return m, nat.SocketFamily(m.ID) == f
}

// Deliver hands the prober a probe-class reply (probe_ack, probe_extra,
// probe_alt, hairpin) that the read pump of socket sock received from from at
// time at, after Open, CheckRole and the server SeqWindow accepted it. It
// copies h and t, never blocks and reports whether the packet was queued:
// not when the type is not probe class, nothing is probing, or the inbox is
// full.
func (p *Prober) Deliver(sock uint8, from netip.AddrPort, h *udpwire.Header, t *udpwire.TLVs, at time.Time) bool {
	if p == nil || h == nil || !p.active.Load() {
		return false
	}
	switch h.Type {
	case udpwire.TProbeAck, udpwire.TProbeExtra, udpwire.TProbeAlt, udpwire.THairpin:
	default:
		return false
	}
	in := inbound{sock: sock, from: unmap(from), h: *h, at: at}
	if t != nil {
		in.t = *t
	}
	return p.enqueue(in)
}

// DeliverSTUN hands the prober a STUN message (see IsSTUN) received on
// socket sock. Only Binding Success responses from one of the family's STUN
// servers on the primary socket are queued: STUN is unauthenticated, and
// any other sender must not take the inbox from the observers' replies.
func (p *Prober) DeliverSTUN(sock uint8, from netip.AddrPort, pkt []byte, at time.Time) bool {
	if p == nil || !p.active.Load() || sock != p.primaryID {
		return false
	}
	from = unmap(from)
	if !slices.ContainsFunc(p.stunServers, func(sv stunServer) bool { return sv.addr == from }) {
		return false
	}
	txid, mapped, ok := parseSTUN(pkt)
	if !ok {
		return false
	}
	return p.enqueue(inbound{stun: true, sock: sock, from: from, txid: txid, mapped: mapped, at: at})
}

func (p *Prober) enqueue(in inbound) bool {
	select {
	case p.inbox <- in:
		return true
	default:
		p.dropped.Add(1)
		return false
	}
}

// NoteUnreachable records an ICMP unreachable read error on socket sock; the
// pump ignores the error and keeps reading. On the primary socket it is
// evidence for udp_blocked (detail icmp_unreachable).
func (p *Prober) NoteUnreachable(sock uint8) {
	if p == nil || sock != p.primaryID {
		return
	}
	p.icmp.Add(1)
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Run probes until DONE, the probe_timeout_ms hard limit, the end of ctx or
// an early udp_blocked, and returns the result. It runs once: a second call
// returns Failure internal (detail run_twice). A panic inside fails the
// family with internal (detail panic:probe/<family>, the recovered panic in
// Result.Panic) and never escapes.
func (p *Prober) Run(ctx context.Context) (res Result) {
	if p == nil {
		return Result{Failure: protocol.ReasonInternal, Detail: "nil_prober"}
	}
	if !p.ran.CompareAndSwap(false, true) {
		return Result{Table: p.table, Traits: protocol.Traits{Family: p.spec.Family}, Failure: protocol.ReasonInternal, Detail: "run_twice"}
	}
	defer p.finished.Store(true)
	if ctx == nil {
		ctx = context.Background()
	}
	where := "probe/" + string(p.spec.Family)
	err := life.Safe(where, func() { res = p.run(ctx) })
	p.active.Store(false)
	if err != nil {
		res = Result{Table: p.table, Traits: protocol.Traits{Family: p.spec.Family}, Failure: protocol.ReasonInternal, Detail: "panic:" + where}
		// Safe returns a *life.PanicError. errors.As matches that outermost
		// value before it would call an Unwrap or As method, so no caller
		// code runs here.
		var pe *life.PanicError
		if errors.As(err, &pe) {
			res.Panic = pe
		}
	}
	return res
}

func (p *Prober) run(ctx context.Context) Result {
	s := newRunState(p)
	if p.setupErr != "" {
		return s.finish(protocol.ReasonInternal, p.setupErr)
	}
	if len(s.main) == 0 {
		return s.finish(protocol.ReasonNoProbeEndpoint, "")
	}
	if ctx.Err() != nil { // nothing to send for a session that already ended
		r, d := ctxReason(ctx)
		return s.finish(r, d)
	}
	p.active.Store(true)
	timer := p.clk.NewTimer(s.deadline)
	defer timer.Stop()
	for {
		now := s.elapsed()
		if r, done := s.step(now); done {
			return r
		}
		timer.Reset(s.nextWake(now) - now)
		select {
		case <-ctx.Done():
			r, d := ctxReason(ctx)
			return s.finish(r, d)
		case in := <-p.inbox:
			s.handle(in)
		case <-p.wake:
		case <-timer.C():
		}
	}
}

// ctxReason maps the cause of the session context to a Reason: a panic
// elsewhere in the session → internal; anything else → canceled, the session
// reporting its own failure.
func ctxReason(ctx context.Context) (protocol.Reason, string) {
	var pe *life.PanicError
	if errors.As(context.Cause(ctx), &pe) {
		return protocol.ReasonInternal, "panic:" + pe.Where()
	}
	return protocol.ReasonCanceled, ""
}

func unmap(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

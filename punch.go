package holepunch

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// Session-wide waits.
const (
	// StartWait bounds the wait for punch_start.
	startWait = 15 * time.Second
	// totalSlack is the last term of the session cap T.
	totalSlack = 3 * time.Second
	// maxTotal is the hard upper bound of T; beyond it summary_wait and
	// handshake shrink in proportion.
	maxTotal = 150 * time.Second
)

// Fault-injection points of the session entry and waits.
const (
	fiAttachReadStart = "attach.read_start"
	fiWaitSummary     = "wait.summary"
	fiWaitGo          = "wait.go"
)

// Options configures Punch. The zero value is usable when the control
// connection is TLS (see ControlSecurity).
type Options struct {
	// LocalAddr is the preferred local IP of its family's primary socket;
	// the zero value binds every address.
	LocalAddr netip.Addr
	// LocalInterface is the preferred network interface of the primary
	// sockets ("" = any), looked up by name in Network.InterfaceAddrs.
	LocalInterface string
	// ExcludeOverlay leaves the host's overlay addresses out of the
	// session: those on tunnel and overlay interfaces (Tailscale,
	// WireGuard, ZeroTier, tun, utun) and in 100.64/10 are then neither
	// reported to the peer nor aimed at. The
	// zero value includes them, ranked below the public and LAN paths: an
	// overlay path wins only when nothing else answers or when its RTT is
	// at most 0.8 × the best other one, and Result.Path.Kind says so.
	// Measurements that must not go through a tunnel exclude them.
	ExcludeOverlay bool
	// TransportMode is the upper-layer transport this side offers ("quic",
	// "kcp", ...; at most 16 bytes of printable ASCII, see
	// protocol.CheckTransportMode); the server's decision is
	// Result.TransportMode.
	TransportMode string
	// TransportData is opaque bytes for the peer, at most 8 KiB (a QUIC
	// caller may put its certificate digest here), delivered unchanged as
	// the peer's Result.PeerTransportData.
	TransportData []byte
	// Policy is this side's local policy. It only tightens the server's
	// (protocol.Tighten).
	Policy *protocol.Policy
	// ControlSecurity says how the control connection is protected. The
	// default, ControlSecurityAuto, lets the library judge the connection:
	// it accepts one that shows it is secure (ConnectionState, as *tls.Conn
	// has) and completes a handshake that has not run yet; Declared
	// vouches for a channel the library cannot judge (an encrypted bridge, a
	// QUIC stream);
	// InsecureForTesting is for tests and loopback only and is marked in
	// Diagnostics.Warn and every progress meta.
	ControlSecurity protocol.ControlSecurity
	// OnProgress receives a copy of every progress event, in order, on one
	// library goroutine (queue of 256, the oldest dropped when full). It must
	// not block for long; a panic is recovered and counted. It is never
	// called after Punch returns.
	OnProgress func(protocol.Progress) //holepunch:callback
	// Network is the network access of the session; nil is SystemNetwork().
	Network Network
	// PortMapper creates port mappings; nil disables them.
	PortMapper PortMapper
	// Clock is the session's time source; nil is the system clock.
	Clock clock.Clock
	// MaxPaths is how many confirmed paths the Session hands over: the
	// primary path, chosen exactly as with one, and up to MaxPaths-1 extra
	// paths that already carried the peer's packets, each confirmed on its
	// own pair within the handover. Paths differ
	// in family, in the kind of network (Path.Kind; a port mapping counts
	// as public) or in the sockets at both ends; two paths of different
	// kinds may share a socket. The session keeps as many as both sides
	// allow and found, waiting at most about 150 ms more before the
	// handover for them. 0 means 1; at most protocol.MaxPaths.
	MaxPaths int
	// AcceptBackground accepts a Background session when the server offers
	// one (coord.SessionOptions.Mode): the caller already relays its
	// traffic and nobody waits for this one, so a pair of hard NATs may run
	// the slow birthday — up to about a minute, many sockets opened slowly.
	// Without it every session runs interactive.
	AcceptBackground bool
}

// Punch runs one hole-punching session over an established control
// connection and returns the winning UDP socket.
//
// control must be a reliable stream the caller has authenticated and
// encrypted (Options.ControlSecurity) and that supports read and write
// deadlines (else invalid_argument, detail deadline_unsupported) with
// net.Conn's semantics: a deadline in the past makes a blocked Read or Write
// return a timeout error at once, and the zero time means none. The library
// hands control back by moving its read deadline into the past; a stream
// that only records the deadline delays Punch's return by about half a
// second and leaves Diagnostics.Warn with control_unreturnable. The first
// frame the library reads must be punch_start; bytes before it belong to the
// caller.
//
// When Punch returns:
//   - every library goroutine has exited;
//   - the library no longer reads or writes control, and has cleared its
//     deadlines; control always stays the caller's and is never closed;
//   - on success the Session owns the winning socket, which the library no
//     longer reads or writes and whose deadlines and TTL are back to normal;
//   - on failure the error is an *Error and every resource the library
//     created is released;
//   - even with context.Background() it returns within the session cap T (71 s
//     by default, at most 150 s), plus the TLS handshake when it ran one (at
//     most 15 s).
//
// Punch does not panic: a panic inside the library becomes an
// *Error with Reason internal. Closing control while the session runs stops
// it with Reason canceled (Err ErrClosed).
func Punch(ctx context.Context, control net.Conn, opts Options) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var sess *Session
	var err error
	if pe := life.Safe("attach", func() { sess, err = attach(ctx, control, opts) }); pe != nil {
		return nil, &Error{Reason: protocol.ReasonInternal, Phase: protocol.PhaseCreated, Detail: "panic:attach", Err: pe}
	}
	return sess, err
}

func attach(ctx context.Context, control net.Conn, opts Options) (*Session, error) {
	if life.IsNil(control) {
		return nil, argError("nil_control", nil)
	}
	if e := validateOptions(control, &opts); e != nil {
		return nil, e
	}
	if opts.ControlSecurity == protocol.ControlSecurityAuto {
		if e := completeTLS(ctx, control); e != nil {
			return nil, e
		}
	}
	rt := newRuntime(ctx, opts)
	if err := rt.ctl.open(control); err != nil {
		_ = rt.g.Close(joinBound)
		r, d := msgframe.ReasonOr(err, protocol.ReasonInvalidArgument, "control")
		return nil, &Error{Reason: r, Phase: protocol.PhaseCreated, Detail: d, Err: err}
	}
	if rt.sink != nil {
		rt.g.Go("progress", rt.sink.run)
	}
	var win *candidate.Action
	var cause error
	if pe := life.Safe("attach", func() { win, cause = rt.run() }); pe != nil {
		win, cause = nil, pe
	}
	return rt.finish(win, cause)
}

func argError(detail string, err error) *Error {
	return &Error{Reason: protocol.ReasonInvalidArgument, Phase: protocol.PhaseCreated, Detail: detail, Err: err}
}

// tlsState is the TLS check of ControlSecurityAuto.
type tlsState interface {
	ConnectionState() tls.ConnectionState
}

// completeTLS runs the handshake of a ControlSecurityAuto control connection
// that has not completed it, within ctx and startWait, and checks that it
// completed. It never closes control: a failed handshake leaves it unusable
// but the caller's.
func completeTLS(ctx context.Context, control net.Conn) *Error {
	ts := control.(tlsState) // validateOptions checked it
	if ts.ConnectionState().HandshakeComplete {
		return nil
	}
	h, ok := control.(life.TLSConn)
	if !ok {
		return argError("insecure_control", nil)
	}
	if err := life.Handshake(ctx, h, startWait); err != nil {
		if ctx.Err() != nil {
			return &Error{Reason: protocol.ReasonCanceled, Phase: protocol.PhaseCreated, Detail: "tls_handshake", Err: context.Cause(ctx)}
		}
		return argError("tls_handshake", err)
	}
	if !ts.ConnectionState().HandshakeComplete {
		return argError("insecure_control", nil)
	}
	return nil
}

// validateOptions checks the options and the control connection's security
// before anything is read or written.
func validateOptions(control net.Conn, o *Options) *Error {
	switch o.ControlSecurity {
	case protocol.ControlSecurityAuto:
		if _, ok := control.(tlsState); !ok {
			return argError("insecure_control", nil)
		}
	case protocol.ControlSecurityDeclared, protocol.ControlSecurityInsecureForTesting:
	default:
		return argError("control_security", nil)
	}
	switch {
	case protocol.CheckTransportMode(o.TransportMode) != nil:
		return argError("transport_mode", nil)
	case len(o.TransportData) > protocol.MaxTransportData:
		return argError("transport_data", nil)
	case o.Network != nil && life.IsNil(o.Network):
		return argError("nil_network", nil)
	case o.PortMapper != nil && life.IsNil(o.PortMapper):
		return argError("nil_port_mapper", nil)
	case o.Clock != nil && life.IsNil(o.Clock):
		return argError("nil_clock", nil)
	case o.LocalAddr.IsValid() && o.LocalAddr.IsMulticast():
		return argError("local_addr", nil)
	case o.MaxPaths < 0 || o.MaxPaths > protocol.MaxPaths:
		return argError("max_paths", nil)
	}
	if p := o.Policy; p != nil {
		if len(p.LowTTLHops) > protocol.MaxLowTTLHops {
			return argError("policy.low_ttl_hops", nil)
		}
		if b := p.Budget.Birthday; b != "" && !b.Valid() {
			return argError("policy.budget.birthday", nil)
		}
	}
	return nil
}

// waitPlan holds the local waits derived from the timeouts.
type waitPlan struct {
	summary   time.Duration // the summary wait, from reading punch_start
	goWait    time.Duration // the go wait, after punch_ready and between rounds
	handshake time.Duration // the handshake timeout, from the first go
	total     time.Duration // the session deadline, from reading punch_start
}

// sessionCounters are the session-level counts outside any family.
type sessionCounters struct {
	progressDropped atomic.Int64
	callbackPanics  atomic.Int64
}

type timings struct{ probe, summaryWait, goWait, handover, total time.Duration }

// runtime is one Punch. The orchestrator — the caller's goroutine —
// drives the phases; the session group owns every socket, mapping release
// and goroutine; the punching group holds the goroutines that may write the
// winning socket, so the handover can join them before handing it out.
type runtime struct {
	callerCtx context.Context
	opts      Options
	clk       clock.Clock
	netw      Network
	mapper    PortMapper
	abl       ablation.Set
	insecure  bool
	attachAt  time.Time

	g      *life.Group
	pg     *life.Group
	ctl    *control
	prog   progressState
	sink   *progressSink
	phases *phaseTracker
	cnt    sessionCounters
	fams   [2]*famState
	// punch and nom exist from the runtime's creation and are never
	// replaced: the read loops, which start with the probing sockets, read
	// both pointers without synchronisation. The summary only opens them
	// (startPunching): it starts the nomination goroutine with the settled
	// handover timeout and activates punch.
	punch *punchState
	nom   *nominator

	// set when punch_start is read; read-only afterwards
	started     bool
	start       protocol.PunchStart
	startAt     time.Time
	role        protocol.Role
	codec       *udpwire.Codec
	opener      *opener // nil under the NoOpener ablation
	pace        *pacer
	sender      *sender
	socks       *socketPool
	policy      protocol.Policy
	features    []protocol.Feature
	timeouts    protocol.Timeouts
	waits       waitPlan
	deadline    clock.Timer // the session deadline
	localIPs    map[netip.Addr]struct{}
	observers   map[netip.AddrPort]bool // punch_start's natprobe observers, main and alternate
	hosts       []hostAddr              // the host's addresses, read once at punch_start
	ifacePrefer []netip.Addr
	serverWin   seqWindow
	peerWin     seqWindow
	followUps   chan struct{}

	// set at the summary; read-only afterwards
	summary    protocol.ProbeSummary
	summaryAt  time.Time
	sessBudget protocol.Budget
	transport  protocol.TransportPick
	workers    []*worker
	readyAt    time.Time

	// orchestrator state
	curRound     atomic.Pointer[roundRun]
	roundsRun    []protocol.RoundPlan
	firstGoAt    time.Time
	lastRTT      time.Duration
	fired        bool
	birthdayRan  bool
	udpBlocked   atomic.Bool // set by a round goroutine
	timing       timings
	traitsSource [2]atomic.Bool
	primaryPath  protocol.PathInfo   // set by finish: the primary path handed over
	extraPaths   []protocol.PathInfo // set by finish: the extra paths handed over

	warnMu sync.Mutex
	warn   []protocol.Warning
}

func newRuntime(ctx context.Context, o Options) *runtime {
	rt := &runtime{
		callerCtx: ctx, opts: o, clk: o.Clock, netw: o.Network, mapper: o.PortMapper,
		abl: ablation.From(ctx), insecure: o.ControlSecurity == protocol.ControlSecurityInsecureForTesting,
		g: life.New(ctx), phases: newPhaseTracker(), followUps: make(chan struct{}, maxFollowUps),
		localIPs: map[netip.Addr]struct{}{}, punch: newPunchState(),
	}
	if rt.clk == nil {
		rt.clk = clock.System{}
	}
	rt.nom = newNominator(rt.clk, rt)
	if rt.netw == nil {
		rt.netw = SystemNetwork()
	}
	rt.attachAt = rt.clk.Now()
	rt.prog.bucket = newBucket(wireProgressRate, wireProgressBurst)
	for i, f := range []protocol.Family{protocol.FamilyUDP4, protocol.FamilyUDP6} {
		rt.fams[i] = &famState{fam: f}
	}
	rt.ctl = newControl(rt)
	if o.OnProgress != nil {
		rt.sink = newProgressSink(rt, o.OnProgress)
	}
	if rt.insecure {
		rt.addWarn(protocol.WarnInsecureControlForTesting)
	}
	return rt
}

// fam returns the state of family f.
func (rt *runtime) fam(f protocol.Family) *famState { return rt.fams[f.Index()] }

// isObserver reports whether ap is one of punch_start's natprobe observers.
func (rt *runtime) isObserver(ap netip.AddrPort) bool { return rt.observers[netaddr.Canon(ap)] }

// run drives the phases up to the handover decision.
func (rt *runtime) run() (*candidate.Action, error) {
	st, err := rt.waitStart()
	if err != nil {
		return nil, err
	}
	if err := rt.acceptStart(st); err != nil {
		return nil, err
	}
	if err := rt.probePhase(); err != nil {
		return nil, err
	}
	sum, err := rt.waitSummary()
	if err != nil {
		return nil, err
	}
	if err := rt.prepare(sum); err != nil {
		return nil, err
	}
	return rt.punchLoop()
}

// waitStart waits for the first library frame.
func (rt *runtime) waitStart() (startMsg, error) {
	ctx := rt.g.Context()
	t := rt.clk.NewTimer(startWait)
	defer t.Stop()
	if err := faultinject.Point(fiAttachReadStart); err != nil {
		return startMsg{}, err
	}
	s, w, err := waitControl(rt.ctl, ctx, rt.ctl.startCh, t.C(), nil)
	switch {
	case err != nil:
		return startMsg{}, err
	case w == wokeTick:
		return startMsg{}, fail(protocol.ReasonControlTimeout, "start_wait", nil)
	}
	return s, nil
}

// acceptStart validates punch_start and sets the session up
// (setupSession), reads the host's addresses, accepts the session on the
// control link and arms the session deadline. A start that names its
// session but is invalid is answered with punch_result{ok:false} by finish;
// a version mismatch is answered with nothing.
func (rt *runtime) acceptStart(s startMsg) error {
	m := s.msg
	if s.err != nil {
		r, d := msgframe.ReasonOr(s.err, protocol.ReasonProtocolViolation, "punch_start")
		if r != protocol.ReasonControlVersionMismatch && m.Role.IsPunch() && m.SessionID != "" {
			rt.start, rt.role, rt.startAt, rt.started = m, m.Role, s.at, true
			rt.initCounters()
		}
		return fail(r, d, s.err)
	}
	m, _ = m.Normalize()
	if err := rt.setupSession(m, s.at); err != nil {
		return err
	}
	rt.readHosts()
	rt.ctl.accept(m.SessionID)
	deadline := rt.waits.total
	rt.deadline = rt.clk.AfterFunc(max(s.at.Add(deadline).Sub(rt.clk.Now()), 0), func() {
		_ = life.Safe("session_deadline", func() { rt.g.Fail(fail(protocol.ReasonControlTimeout, "session_deadline", nil)) })
	})
	now := rt.clk.Now()
	rt.phases.advance(protocol.PhaseProbing, "start_received", now)
	rt.progress(progressEvent{stage: stageProbeStarted, status: protocol.StatusInfo})
	return nil
}

// setupSession installs the normalized punch_start m, read at `at`: codec,
// flow opener, timeouts and waits, merged policy, accepted features, pacer,
// send gate, socket pool and the natprobe observers.
func (rt *runtime) setupSession(m protocol.PunchStart, at time.Time) error {
	rt.start, rt.role, rt.startAt, rt.started = m, m.Role, at, true
	codec, err := udpwire.NewCodec(m.Token, m.Wire.RouteID, udpwire.Role(m.Role.Code()),
		udpwire.PadPolicy{Min: m.Wire.PayloadMin, Max: m.Wire.PayloadMax}, rt.clk.Now)
	if err != nil {
		rt.initCounters()
		return fail(protocol.ReasonProtocolViolation, "wire", err)
	}
	rt.codec = codec
	if !rt.abl.NoOpener {
		rt.opener = newOpener(codec)
	}
	rt.timeouts = m.Timeouts.Normalize()
	rt.computeWaits()
	rt.policy = protocol.Tighten(m.Policy, rt.opts.Policy)
	rt.features = protocol.AcceptFeatures(m.Control.Features, protocol.SupportedFeatures())
	rt.pace = newPacer(m.Token, m.Wire.RouteID, codec.Role())
	rt.initCounters()
	rt.observers = map[netip.AddrPort]bool{}
	for _, o := range m.Probe.Observers {
		rt.observers[netaddr.Canon(o.Addr)] = true
	}
	return nil
}

// initCounters creates the send gate and the socket pool: the counting
// objects the cleanup reads even when the session failed early.
func (rt *runtime) initCounters() {
	if rt.sender != nil {
		return
	}
	cnt := [2]*famCounters{&rt.fams[0].cnt, &rt.fams[1].cnt}
	rt.sender = newSender(rt.codec, rt.clk, rt.pace, cnt, rt, rt.punch)
	limit := int(rt.policy.Budget.MaxSockets)
	if limit == 0 {
		limit = int(protocol.DefaultBudget().MaxSockets)
	}
	rt.socks = newSocketPool(poolDeps{g: rt.g, netw: rt.netw, opener: rt.opener, pace: rt.pace, cnt: cnt,
		panics: &rt.cnt.callbackPanics, sink: rt}, limit)
}

// computeWaits derives the local waits from the timeouts: client waits that
// mirror a server deadline add 2 s, and T is compressed to 150 s by
// shrinking summary_wait and handshake in proportion.
func (rt *runtime) computeWaits() {
	ms := func(v uint32) time.Duration { return time.Duration(v) * time.Millisecond }
	t := rt.timeouts
	summary, handshake := ms(t.SummaryWaitMs), ms(t.HandshakeTimeoutMs)
	fixed := startWait + ms(t.ProbeTimeoutMs) + 2*waitSlack + ms(t.GoWaitMs) + ms(t.HandoverTimeoutMs) + totalSlack
	if over := fixed + summary + handshake - maxTotal; over > 0 && summary+handshake > 0 {
		keep := float64(summary+handshake-over) / float64(summary+handshake)
		summary = time.Duration(float64(summary) * keep)
		handshake = time.Duration(float64(handshake) * keep)
	}
	rt.waits = waitPlan{
		summary:   summary + waitSlack,
		goWait:    ms(t.GoWaitMs) + waitSlack,
		handshake: handshake,
		total:     fixed + summary + handshake - startWait,
	}
}

// waitSummary waits for probe_summary (counted from punch_start),
// refreshing the probing mappings every 10 s. Assists before the summary are
// ignored, but for round 1's anchor refresh, which the server sends
// right after the summary.
func (rt *runtime) waitSummary() (stamped[protocol.ProbeSummary], error) {
	ctx := rt.g.Context()
	var zero stamped[protocol.ProbeSummary]
	if err := faultinject.Point(fiWaitSummary); err != nil {
		return zero, err
	}
	deadline := rt.startAt.Add(rt.waits.summary)
	keepalive := rt.clk.Now().Add(rt.pace.spread(keepaliveInterval, 0.1))
	t := rt.clk.NewTimer(time.Hour)
	defer t.Stop()
	for {
		now := rt.clk.Now()
		t.Reset(max(earliest(deadline, keepalive).Sub(now), 0))
		s, w, err := waitControl(rt.ctl, ctx, rt.ctl.summaryCh, t.C(), func(a stamped[protocol.Assist]) {
			// Round 1's anchor refresh follows the summary on the link: when
			// both wait here, the select may take it first.
			if a.msg.Kind == protocol.AssistRefresh && !rt.abl.NoAssistRelay {
				rt.refreshAnchor(a.msg)
			}
		})
		switch {
		case err != nil:
			return zero, err
		case w == wokeValue:
			return s, nil
		case w == wokeTick:
			now = rt.clk.Now()
			if !now.Before(deadline) {
				return zero, fail(protocol.ReasonControlTimeout, "summary_wait", nil)
			}
			if !now.Before(keepalive) {
				rt.sendKeepalive()
				keepalive = now.Add(rt.pace.spread(keepaliveInterval, 0.1))
			}
		}
	}
}

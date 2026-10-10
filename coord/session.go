package coord

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

// SessionOptions configures one session.
type SessionOptions struct {
	// SessionID and Token are generated when empty (18 B id and 32 B token,
	// base64url). A Token given here must be the base64url of 32 bytes.
	SessionID, Token string
	// Wire is generated when zero: a random route and a per-session random
	// payload range. A given Wire needs a route, payload_min in [48, 160],
	// payload_max − payload_min in [64, 256] and payload_max <= 1024.
	Wire protocol.WireSpec
	// Timeouts replaces Config.Timeouts.
	Timeouts *protocol.Timeouts
	// InitiatorProbe and ResponderProbe replace Config.Probe for one role.
	InitiatorProbe, ResponderProbe *protocol.ProbeSpec
	// Policy replaces Config.Policy; its budget is clamped to the operator
	// ceiling.
	Policy *protocol.Policy
	// ClientKeys are the [initiator, responder] keys of the per-key limits
	// and packet quotas (a visitor's key, a provider's ID, for example); an
	// empty key is not limited.
	ClientKeys [2]string
	// Parent, when set, aborts the session with canceled when it is done.
	Parent context.Context
	// Labels are copied into events and the Result, never onto the wire.
	Labels map[string]string
	// Mode offers the clients a Background session: the caller already
	// relays their traffic and nobody waits.
	// It runs in Background only when both clients accept; a PDF × RND
	// pair then runs the slow birthday. A Background offer defaults the
	// session budget to protocol.BackgroundBudget and, without Timeouts,
	// the handshake to 60 s. The zero value is interactive.
	Mode protocol.SessionMode
}

// AttachOptions configures one Attach.
type AttachOptions struct {
	// Security vouches for the control stream: the
	// default accepts only a completed TLS connection; Declared trusts the
	// caller's outer encryption; InsecureForTesting accepts anything and
	// warns insecure_control_for_testing.
	Security protocol.ControlSecurity
}

// State is a session's state. States only move
// forward; whether a closed session succeeded is in its Result.
type State string

// States.
const (
	StateCreated    State = "created"    // no link yet
	StateBinding    State = "binding"    // one link attached
	StateProbing    State = "probing"    // both attached, waiting for both reports
	StateSummarized State = "summarized" // summaries written, waiting for both readies
	StatePunching   State = "punching"   // round k under way
	StateConfirming State = "confirming" // at least one confirmation
	StateClosed     State = "closed"
)

// Snapshot is a small copy of a session's state.
type Snapshot struct {
	ID                   string
	State                State
	Round                int
	Attached, Reported   [2]bool // index 0 initiator, 1 responder
	Ready, Confirmed     [2]bool
	LastStage            [2]string
	RTT                  [2]time.Duration
	Variant              string
	CreatedAt, UpdatedAt time.Time
}

// Session is one punch between two clients. Its methods are safe for
// concurrent use.
type Session struct {
	c      *Coordinator
	id     string
	epoch  time.Time // creation: the origin of session time
	labels map[string]string
	parent context.Context
	keys   [2]string
	token  protocol.Token
	wire   protocol.WireSpec
	starts [2]protocol.PunchStart
	to     protocol.Timeouts
	ttl    ttl
	budget protocol.Budget      // the session budget of each side
	offer  protocol.SessionMode // SessionOptions.Mode, in punch_start
	ablate ablation.Set
	handle *natprobe.Handle // nil in relay-only mode
	// regAt is the natprobe registration on session time (Handle.Registered,
	// registeredAt): the origin of the planner's FireAt axis, the one
	// Traits.PortAnchorMs is on. Relay-only sessions have no registration and
	// use the session's creation.
	regAt time.Duration
	// unobserved are the families no natprobe observer of the probe specs
	// covers: the server cannot verify them. Relay-only sessions leave
	// it empty; every family of theirs is unverified.
	unobserved []protocol.Family
	group      *life.Group
	timer      Timer
	wake       chan struct{} // capacity 1: work for the session goroutine
	quit       chan struct{} // closed when the session ends
	done       chan struct{}
	refs       atomic.Int32 // finish's share, the session goroutine, Attach and timer calls in flight
	result     atomic.Pointer[Result]

	stopParent func() bool
	stopWatch  func() bool

	mu sync.Mutex
	st sessionState // guarded by mu
}

// sessionState is everything the session mutex guards.
type sessionState struct {
	state     State
	gen       uint64 // changes invalidate planning done outside the lock
	links     [2]*link
	attaching [2]bool
	loop      bool // the session goroutine was started
	updated   time.Duration
	deadline  time.Duration // the stage deadline, session time
	expireAt  time.Duration // the defensive lifetime cap
	deferred  *terminal     // NoEarlyAbort: an end waiting for the stage deadline
	planning  bool          // the planner runs outside the lock
	work      work          // requests for the session goroutine
	rng       *rand.Rand    // round seeds and plan ids
	quota     quota

	reports [2]*protocol.ProbeReport
	echoed  [2]bool // the side accepted the sandwich feature

	planner   Planner // switches to the default planner after a panic
	cls       Classification
	planned   bool
	cin       ClassifyInput        // kept for a fallback classification
	views     [2]protocol.PeerView // merged views as sent (wire)
	rawViews  [2]protocol.PeerView // merged without the traits memory: this session's own evidence
	pviews    [2]protocol.PeerView // the planner's views: the wire views and the endpoints admitted since
	verified  [2]map[protocol.Family][]netip.Addr
	lan       [2]map[protocol.Family][]netip.Addr
	overlay   [2]map[protocol.Family][]netip.Addr     // overlay addresses
	upstream  [2]map[protocol.Family][]netip.AddrPort // private port mappings: upstream-LAN candidates
	pair      protocol.PairFacts
	transport string
	memory    StrategyMemory // nil once disabled for the session
	memKey    StrategyKey
	hasKey    bool
	memHit    bool
	promoted  bool
	// bgOnly: the built-in memory saw this pair connect only through the
	// slow birthday (plan.BackgroundOnly).
	bgOnly bool
	// mode is the session's mode: background when it was offered and both
	// clients accepted it.
	mode       protocol.SessionMode
	order      []VariantID
	sandwich   bool // negotiated: natprobe hands the sandwich probes to the session
	summaryAt  time.Duration
	summarized bool
	pairRND    bool

	ready   [2]bool
	portmap [2][]protocol.Assist  // port mappings for each side, sent with the next go (≤ maxQueuedAssists)
	pending [2][]protocol.Assist  // drifted mappings for each side, sent with the next go (≤ maxQueuedAssists)
	remaps  [2][2]*protocol.Remap // each side's latest remap echo per family index

	round         int // current round, 0 before the first go
	cur           roundState
	firstGoAt     time.Duration
	punchDeadline time.Duration
	rescueUsed    bool
	nonRescue     int
	prev          []RoundOutcome
	records       []RoundRecord
	ev            Evidence
	lastGranted   protocol.BudgetClass
	granted       [2]int                       // packets granted so far, per side, pushed targets included
	credit        [2]int                       // pushed targets' packets the audit has not yet paid
	strikes       [2]int                       // consecutive audit violations
	halve         [2]bool                      // the side's grants are halved after a violation
	gone          [2]bool                      // punching: the side's control link is lost
	recentPorts   [maxRound + 1][2]int         // distinct ports granted per round and side (10 s window)
	fireAt        [maxRound + 1]time.Duration  // each round's expected fire time, session time
	mappings      [2][]MappingSample           // each side's mappings its peer saw while punching
	directSent    [2][2]map[netip.AddrPort]int // per side and family: the most round sockets each Direct target went out from

	confirmed [2]bool
	confirmAt [2]time.Duration
	okResult  [2]bool
	finals    [2]*ClientFinal
	paths     [2]*protocol.PathInfo
	winRound  int
	winVar    VariantID
	winFam    protocol.Family

	rtt       [2]rttEstimator
	offset    [2]time.Duration
	offsetRTT [2]time.Duration // the sample behind offset (smallest wins)
	warn      []string
	ctr       Counters
	timeline  [timelineCap]StageMark
	tlN       int
	lastStage [2]string
	sandBox   []nat.SandwichEvent
	sandHalf  [2][2]sandwichHalf      // per side and family
	refresh   refreshState            // the anchor refresh of the next round
	drifted   map[netip.AddrPort]bool // drifted mappings already pushed (≤ maxDrifted)
}

// roundState is the round under way.
type roundState struct {
	n          int
	variant    VariantID
	name       string
	class      protocol.BudgetClass
	rescue     bool
	final      bool
	window     time.Duration
	align      alignment
	goAt       time.Duration
	deadline   time.Duration
	plans      [2]protocol.RoundPlan
	reanchored [2]bool // round 1's plan of the side was re-aimed after its summary: the go carries it
	results    [2]*protocol.RoundResult
	granted    [2]int
	sandwich   [2][2]bool    // the sandwich probe runs, per side and family
	targets    [2]int        // peer_targets sent to each side
	pushed     [2][2]int     // their targets and window ports, per side and family
	assists    [2][2]int     // peer_seen accepted per side and family
	families   []FamilyRound // the decision's families, as the outcome returns them
	evaluating bool          // ended; the next round is being decided
}

// work is what the session goroutine has to do besides frames.
type work struct {
	plan      bool // both reports are in: plan the session
	evalRound bool // a round ended: plan the next one
	refreshed bool // an anchor refresh ended: plan its round again
}

// timelineCap bounds the progress timeline.
const timelineCap = 32

// ID returns the session id.
func (s *Session) ID() string { return s.id }

// Start returns a copy of the punch_start pre-generated for role, for
// announcing the session out of band (a caller may signal the provider with
// it); the same message is written on the stream at Attach. It returns the zero
// value for an invalid role.
func (s *Session) Start(role protocol.Role) protocol.PunchStart {
	i, ok := roleIndex(role)
	if !ok {
		return protocol.PunchStart{}
	}
	return cloneStart(s.starts[i])
}

// Context is canceled when the session ends; its cause is ErrSessionDone
// after a success, the recovered panic after a panic in a session goroutine,
// and a *ReasonError with the end's reason and detail otherwise (server_shutdown
// after Coordinator.Close). Callers can tie their own resources to it.
func (s *Session) Context() context.Context { return s.group.Context() }

// Done is closed once the session has ended, every resource is released and
// every goroutine of the session has returned.
func (s *Session) Done() <-chan struct{} { return s.done }

// Result returns the session's Result once Done is closed.
func (s *Session) Result() (Result, bool) {
	select {
	case <-s.done:
		return *s.result.Load(), true
	default:
		return Result{}, false
	}
}

// Snapshot returns a copy of the session's state.
func (s *Session) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	snap := Snapshot{
		ID:        s.id,
		State:     st.state,
		Round:     st.round,
		Ready:     st.ready,
		Confirmed: st.confirmed,
		LastStage: st.lastStage,
		Variant:   st.cur.name,
		CreatedAt: s.epoch,
		UpdatedAt: s.epoch.Add(st.updated),
	}
	for r := range 2 {
		snap.Attached[r] = st.links[r] != nil
		snap.Reported[r] = st.reports[r] != nil
		snap.RTT[r], _ = st.rtt[r].min()
	}
	return snap
}

// Abort ends the session with code (an unknown code means canceled) and
// detail: each client still connected and not yet confirmed gets
// punch_abort{by: server, code}, within one shared 500 ms deadline, and the
// links are closed. It is idempotent and returns when the session's own
// cleanup is done.
func (s *Session) Abort(code protocol.Reason, detail string) {
	if !code.Known() {
		code = protocol.ReasonCanceled
	}
	s.guard("coord.abort", func() { s.finish(terminal{code: code, detail: truncate(detail, maxDetail)}) })
}

// acquire takes a reference for work that must finish before Done closes;
// it fails once the session has released its last reference.
func (s *Session) acquire() bool {
	for {
		n := s.refs.Load()
		if n <= 0 {
			return false
		}
		if s.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// release drops a reference; the last one closes Done and delivers the
// Result (EvClosed through the event queue, OnResult directly).
func (s *Session) release() {
	if s.refs.Add(-1) != 0 {
		return
	}
	res := s.result.Load()
	close(s.done)
	s.c.sessionGone()
	s.c.emit(Event{Kind: EvClosed, At: res.Timings.Closed, SessionID: s.id, Code: res.Code, Detail: res.Detail,
		Labels: s.labels, Result: res})
	if fn := s.c.cfg.OnResult; fn != nil {
		if err := life.Safe("coord.on_result", func() {
			if faultinject.Point(fiCallback) != nil {
				return
			}
			fn(*res)
		}); err != nil {
			s.c.noteCallbackPanic(s.id, err)
		}
	}
}

// since converts a clock reading to session time.
func (s *Session) since(t time.Time) time.Duration { return t.Sub(s.epoch) }

// at converts session time back to a clock reading.
func (s *Session) at(d time.Duration) time.Time { return s.epoch.Add(d) }

// kick wakes the session goroutine.
func (s *Session) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func roleIndex(r protocol.Role) (int, bool) {
	switch r {
	case protocol.RoleInitiator:
		return 0, true
	case protocol.RoleResponder:
		return 1, true
	}
	return 0, false
}

func roleOf(i int) protocol.Role {
	if i == 0 {
		return protocol.RoleInitiator
	}
	return protocol.RoleResponder
}

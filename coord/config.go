package coord

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

// Rate is a token bucket: PerSec tokens per second, at most Burst at once.
// A negative PerSec removes the limit; a zero field takes the default.
type Rate struct{ PerSec, Burst int }

// ProbeFunc returns the ProbeSpec a role receives in punch_start
// (normally built from natprobe.Server.ProbeSpec). It runs in NewSession,
// outside every lock and inside a recover boundary; an error or a panic fails
// NewSession.
type ProbeFunc func(role protocol.Role, opts *SessionOptions) (protocol.ProbeSpec, error)

// TargetPolicy says which peer addresses the clients may aim at
// (Config.Targets).
type TargetPolicy uint8

// Target policies.
const (
	// TargetsBounded is the default: the clients aim at the addresses the
	// server verified, and also at self-reported addresses where nothing
	// could be verified, within tight bounds: Direct stages only, at most 4 IPs and
	// 8 packets per target and round. That covers a family the server has
	// no observer for (IPv6 on a v4-only server with two dual-stack
	// clients) and a client the server saw only at a private address
	// (protocol.Traits.LANObserved: it reaches the server over a LAN route
	// or a hairpin without source NAT), which is then reached at the global
	// addresses its STUN servers and port mapping reported. The summary
	// marks such a family in pair.unverified and the Result warns
	// unverified_targets. A client could report a third party's address
	// there; the bounds keep what that third party receives small.
	TargetsBounded TargetPolicy = iota
	// TargetsVerifiedOnly aims only at addresses the server verified, and at
	// LAN and overlay addresses where both sides share one: a family no
	// observer covers is left out of the session, and a LAN-observed
	// client is reached only on the LAN.
	TargetsVerifiedOnly
)

// Config configures a Coordinator. Zero fields take the defaults.
type Config struct {
	// Registry is the natprobe registry the sessions register their probe
	// routes with, shared with the natprobe.Server that observes the
	// clients. It is required unless NoObserver is set.
	Registry *natprobe.Registry
	// NoObserver runs the coordinator without natprobe, with a nil
	// Registry: nothing is verified, so the plans may only aim Direct
	// stages at the peer's self-reported public endpoints (at most 16, 8
	// packets each per round), the summary marks every family in
	// pair.unverified and the Result warns unverified_targets. It needs
	// Targets TargetsBounded.
	NoObserver bool
	// Targets says whether the clients may aim at addresses the server
	// could not verify; see TargetPolicy.
	Targets TargetPolicy
	// Probe builds each role's ProbeSpec; nil uses DefaultProbe.
	Probe ProbeFunc
	// DefaultProbe is the ProbeSpec used when Probe is nil and the session
	// options give none: normally natprobe.Server.ProbeSpec of the server
	// whose Registry this is. Its zero V is ProbeSpecVersion.
	DefaultProbe protocol.ProbeSpec
	// Timeouts are the protocol timeouts of the sessions (zero fields:
	// protocol.DefaultTimeouts); summary_wait_ms is computed per link.
	Timeouts protocol.Timeouts
	// Policy is the default session policy; its budget is clamped to the
	// operator ceiling (protocol.SessionBudgetLimit).
	Policy *protocol.Policy
	// TransportFallback is the transport mode used when the clients' modes
	// conflict ("" → transport_mismatch; "kcp", for example).
	TransportFallback string
	// TTL holds the server's stage deadlines.
	TTL TTLConfig
	// Limits are the admission, rate and frame limits.
	Limits Limits
	// Budget holds the extreme switch.
	Budget BudgetConfig
	// Planner plans the rounds; nil uses the built-in planner.
	Planner Planner
	// Memory is the cross-session strategy memory; nil uses
	// NewStrategyMemory(StrategyMemoryConfig{}) and NoMemory{} turns it off.
	Memory StrategyMemory
	// StrategySalt is the StrategyKey salt (DeriveStrategyKey) for a Memory
	// that is not the built-in one, which keeps its own
	// StrategyMemoryConfig.Salt; nil draws a random salt per Coordinator.
	// Coordinators that share one such memory must share the salt.
	StrategySalt []byte
	// TraitsMemory is the cross-session NAT traits memory consulted by the
	// merge and fed at the end of a session; nil uses
	// natprobe.NewTraitsMemory with its defaults and NoMemory{} turns it off.
	TraitsMemory natprobe.TraitsMemory
	// Observer receives the session events, asynchronously and in order per
	// session, from one dispatcher goroutine with a bounded queue: events
	// that do not fit are dropped and counted. nil starts no dispatcher.
	// Coordinator.Close joins the dispatcher, so Observer must not call Close.
	//
	//holepunch:callback
	Observer func(Event)
	// ObserveProgress also turns every accepted punch_progress into an event.
	ObserveProgress bool
	// OnResult receives every session's Result exactly once, after all of the
	// session's resources were released, outside every lock and inside a
	// recover boundary. Coordinator.Close waits for the calls in progress, so
	// OnResult must not call Close: Close would wait for it until its bound.
	//
	//holepunch:callback
	OnResult func(Result)
	// Clock is the time source; nil uses the system clock. A Clock is
	// infrastructure for tests and simulation, not a callback: it is called
	// directly, with the session mutex held too, and must not panic.
	Clock clock.Clock
	// Rand is the randomness for session ids, tokens, routes, wire lengths
	// and round seeds; nil uses crypto/rand.
	Rand io.Reader
}

// TTLConfig holds the server deadlines. Each zero field
// takes its default; out-of-range values are clamped.
type TTLConfig struct {
	// BindTimeout bounds created and binding from NewSession: 15 s,
	// [3 s, 60 s].
	BindTimeout time.Duration
	// ReportSlack is added to probe_timeout after the second Attach:
	// 3 s, (0, 10 s].
	ReportSlack time.Duration
	// ReadyTimeout bounds summarized: go_wait_ms, [500 ms, 15 s].
	ReadyTimeout time.Duration
	// PunchSlack is added to handshake_timeout after the first go:
	// 1 s, (0, 5 s].
	PunchSlack time.Duration
	// ConfirmLinger is how long one confirmation waits for the other:
	// handover_timeout + 1 s, (0, 5 s]; a negative value ends the session at
	// the first confirmation.
	ConfirmLinger time.Duration
	// ResultGrace is how long two confirmations wait for both
	// punch_result frames: 300 ms, (0, 1 s]; a negative value ends the session
	// at the second confirmation.
	ResultGrace time.Duration
}

// BudgetConfig holds the operator's budget switches.
type BudgetConfig struct {
	// AllowExtreme permits the extreme budget class (from round 3, at most
	// ExtremePerHour times per client key) and the balanced and aggressive
	// birthday tiers.
	AllowExtreme bool
}

// Limits are the coordinator's admission and anti-abuse limits. A zero field
// takes the default; a negative count or rate removes the limit, except for the
// bounds of the coordinator's memory — MaxSessions, MaxKeys, ObserverQueue and
// FramesPerLink — which take the default instead.
type Limits struct {
	MaxSessions        int    // concurrent sessions, the bound of the session index: 4096
	MaxPending         int    // sessions in created or binding: 2048
	NewSessions        Rate   // NewSession rate: {200, 400}
	InitiatorKeyRate   Rate   // NewSession rate per initiator key: {2, 6}
	MaxPerInitiatorKey int    // concurrent sessions per initiator key: 8
	MaxPerResponderKey int    // concurrent sessions per responder key: 32
	PacketsPerMinute   [2]int // packets granted per key per minute, [initiator, responder]: 30000, 120000
	ExtremePerHour     int    // extreme rounds per client key per hour: 2
	FramesPerLink      int    // frames received per link: 512
	FrameRate          Rate   // client-to-server frames per link: {50, 100}
	ProgressPerLink    int    // punch_progress accepted per link: 64
	AssistIn           Rate   // peer_seen received per link: {20, 40}
	AssistPerRound     int    // peer_seen per link, round and family: 8
	AssistRelay        Rate   // peer_seen forwarded per direction: {30, 60}
	TargetsPerRound    int    // peer_targets per receiving link and round: 4
	ObserverQueue      int    // queued events: 4096
	// MaxKeys bounds the per-key quota table: 65536 entries of a fixed size
	// (about 300 B each with the map's share, some 20 MiB in all). A new key
	// in a full table evicts the entry idle the longest; with every entry in
	// use NewSession fails with ErrBusy. It cannot be removed: zero or less
	// takes the default.
	MaxKeys int

	// WriteTimeout is the deadline of one control frame: 3 s.
	WriteTimeout time.Duration
	// AbortTimeout is the absolute deadline shared by the punch_abort
	// notices of a closing session: 500 ms.
	AbortTimeout time.Duration
}

// Default limits.
const (
	defMaxSessions        = 4096
	defMaxPending         = 2048
	defMaxPerInitiatorKey = 8
	defMaxPerResponderKey = 32
	defInitiatorPackets   = 30000
	defResponderPackets   = 120000
	defExtremePerHour     = 2
	defFramesPerLink      = 512
	defProgressPerLink    = 64
	defAssistPerRound     = 8
	defTargetsPerRound    = 4
	defObserverQueue      = 4096
	defMaxKeys            = 65536
	defWriteTimeout       = 3 * time.Second
	defAbortTimeout       = 500 * time.Millisecond

	// Default TTLs.
	defBindTimeout = 15 * time.Second
	minBindTimeout = 3 * time.Second
	maxBindTimeout = 60 * time.Second
	defReportSlack = 3 * time.Second
	maxReportSlack = 10 * time.Second
	minReady       = 500 * time.Millisecond
	maxReady       = 15 * time.Second
	defPunchSlack  = time.Second
	maxPunchSlack  = 5 * time.Second
	maxLinger      = 5 * time.Second
	defResultGrace = 300 * time.Millisecond
	maxResultGrace = time.Second

	// registrySlack is added to the probing deadline for the registry
	// entry's fallback TTL.
	registrySlack = 5 * time.Second
)

func defaultRate(r Rate, perSec, burst int) Rate {
	if r.PerSec == 0 {
		r.PerSec = perSec
	}
	if r.Burst <= 0 {
		r.Burst = burst
	}
	return r
}

func defaultCount(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func (l Limits) withDefaults() Limits {
	l.MaxPending = defaultCount(l.MaxPending, defMaxPending)
	l.NewSessions = defaultRate(l.NewSessions, 200, 400)
	l.InitiatorKeyRate = defaultRate(l.InitiatorKeyRate, 2, 6)
	l.MaxPerInitiatorKey = defaultCount(l.MaxPerInitiatorKey, defMaxPerInitiatorKey)
	l.MaxPerResponderKey = defaultCount(l.MaxPerResponderKey, defMaxPerResponderKey)
	l.PacketsPerMinute[0] = defaultCount(l.PacketsPerMinute[0], defInitiatorPackets)
	l.PacketsPerMinute[1] = defaultCount(l.PacketsPerMinute[1], defResponderPackets)
	l.ExtremePerHour = defaultCount(l.ExtremePerHour, defExtremePerHour)
	l.FrameRate = defaultRate(l.FrameRate, 50, 100)
	l.ProgressPerLink = defaultCount(l.ProgressPerLink, defProgressPerLink)
	l.AssistIn = defaultRate(l.AssistIn, 20, 40)
	l.AssistPerRound = defaultCount(l.AssistPerRound, defAssistPerRound)
	l.AssistRelay = defaultRate(l.AssistRelay, 30, 60)
	l.TargetsPerRound = defaultCount(l.TargetsPerRound, defTargetsPerRound)
	// The session index, the key table, the event queue and the per-link
	// frame limit bound the coordinator's memory: they cannot be removed.
	if l.MaxSessions <= 0 {
		l.MaxSessions = defMaxSessions
	}
	if l.ObserverQueue <= 0 {
		l.ObserverQueue = defObserverQueue
	}
	if l.MaxKeys <= 0 {
		l.MaxKeys = defMaxKeys
	}
	if l.FramesPerLink <= 0 {
		l.FramesPerLink = defFramesPerLink
	}
	if l.WriteTimeout <= 0 {
		l.WriteTimeout = defWriteTimeout
	}
	if l.AbortTimeout <= 0 {
		l.AbortTimeout = defAbortTimeout
	}
	return l
}

// ttl is a session's resolved deadlines.
type ttl struct {
	bind, reportSlack, ready, punchSlack time.Duration
	linger, grace                        time.Duration // < 0: no wait
}

func clampDur(v, lo, hi time.Duration) time.Duration {
	return min(max(v, lo), hi)
}

// resolve applies the defaults that depend on the session's protocol
// timeouts (ReadyTimeout = go_wait_ms, ConfirmLinger = handover + 1 s).
func (t TTLConfig) resolve(to protocol.Timeouts) ttl {
	r := ttl{
		bind:        clampDur(cmpOr(t.BindTimeout, defBindTimeout), minBindTimeout, maxBindTimeout),
		reportSlack: clampDur(cmpOr(t.ReportSlack, defReportSlack), time.Millisecond, maxReportSlack),
		ready:       clampDur(cmpOr(t.ReadyTimeout, ms(to.GoWaitMs)), minReady, maxReady),
		punchSlack:  clampDur(cmpOr(t.PunchSlack, defPunchSlack), time.Millisecond, maxPunchSlack),
		linger:      t.ConfirmLinger,
		grace:       t.ResultGrace,
	}
	switch {
	case r.linger == 0:
		r.linger = min(ms(to.HandoverTimeoutMs)+time.Second, maxLinger)
	case r.linger > 0:
		r.linger = min(r.linger, maxLinger)
	}
	switch {
	case r.grace == 0:
		r.grace = defResultGrace
	case r.grace > 0:
		r.grace = min(r.grace, maxResultGrace)
	}
	return r
}

func cmpOr(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func ms(v uint32) time.Duration { return time.Duration(v) * time.Millisecond }

// settings is a validated Config with its defaults applied.
type settings struct {
	cfg        Config
	limits     Limits
	clock      clock.Clock
	rand       io.Reader
	planner    Planner
	memory     StrategyMemory
	traits     natprobe.TraitsMemory
	timeouts   protocol.Timeouts
	unverified bool
}

func newSettings(cfg Config) (settings, error) {
	switch {
	case cfg.Registry == nil && !cfg.NoObserver:
		return settings{}, errors.New("coord: Config.Registry is required (or NoObserver, which runs without natprobe)")
	case cfg.Registry != nil && cfg.NoObserver:
		return settings{}, errors.New("coord: NoObserver needs a nil Registry")
	case cfg.Targets != TargetsBounded && cfg.Targets != TargetsVerifiedOnly:
		return settings{}, errors.New("coord: unknown Targets policy")
	case cfg.NoObserver && cfg.Targets == TargetsVerifiedOnly:
		return settings{}, errors.New("coord: NoObserver verifies nothing, so it needs Targets TargetsBounded")
	}
	if err := protocol.CheckTransportMode(cfg.TransportFallback); err != nil {
		return settings{}, fmt.Errorf("coord: TransportFallback: %w", err)
	}
	if cfg.Policy != nil {
		if err := validatePolicy(*cfg.Policy); err != nil {
			return settings{}, err
		}
	}
	s := settings{
		cfg:        cfg,
		limits:     cfg.Limits.withDefaults(),
		clock:      cfg.Clock,
		rand:       cfg.Rand,
		planner:    cfg.Planner,
		memory:     cfg.Memory,
		traits:     cfg.TraitsMemory,
		timeouts:   cfg.Timeouts.Normalize(),
		unverified: cfg.Registry == nil,
	}
	if s.clock == nil {
		s.clock = clock.System{}
	}
	if s.rand == nil {
		s.rand = rand.Reader
	}
	if s.planner == nil {
		s.planner = plan.DefaultPlanner{}
	}
	if s.memory == nil {
		s.memory = NewStrategyMemory(StrategyMemoryConfig{Clock: s.clock})
	}
	switch s.traits.(type) {
	case nil:
		s.traits = natprobe.NewTraitsMemory(natprobe.TraitsMemoryConfig{Clock: s.clock})
	case NoMemory:
		// Internally a nil traits memory means "off", as for the natprobe merge.
		s.traits = nil
	}
	return s, nil
}

// validatePolicy checks a policy the way punch_start will carry it.
func validatePolicy(p protocol.Policy) error {
	if p.Budget.Birthday != "" && !p.Budget.Birthday.Valid() {
		return argumentError("policy.budget.birthday", "unknown birthday budget %q", p.Budget.Birthday)
	}
	return nil
}

package coord

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/internal/wiretype"
	"github.com/djylb/holepunch/protocol"
)

// Identity sizes.
const (
	sessionIDBytes = 18
	seedBytes      = 32
)

// NewSession creates a session; it needs no connection yet. It pre-generates
// both punch_start messages, registers the probe route with the Registry,
// reserves both client keys' quotas and arms the bind deadline.
//
// Errors: ErrClosed; ErrBusy (session count, pending count, creation rate or
// a key's limit); natprobe.ErrRouteInUse, ErrConflict or ErrRegistryFull from
// the Registry; a *protocol.ValidationError with Reason invalid_argument for
// invalid options.
func (c *Coordinator) NewSession(opts SessionOptions) (s *Session, err error) {
	if perr := life.Safe("coord.new_session", func() { s, err = c.newSession(opts) }); perr != nil {
		return nil, fmt.Errorf("coord: new session: %w", perr)
	}
	return s, err
}

func (c *Coordinator) newSession(opts SessionOptions) (*Session, error) {
	if c.isClosed() {
		return nil, ErrClosed
	}
	now := c.set.clock.Now()
	id, token, wire, rng, err := c.identity(opts)
	if err != nil {
		return nil, err
	}
	if !opts.Mode.Valid() {
		return nil, argumentError("mode", "unknown session mode %q", opts.Mode)
	}
	background := opts.Mode == protocol.ModeBackground
	ab := ablation.From(opts.Parent)
	to := c.set.timeouts
	switch {
	case opts.Timeouts != nil:
		to = opts.Timeouts.Normalize()
	case background:
		// The slow birthday's 45 s window after the cheap round.
		to.HandshakeTimeoutMs = max(to.HandshakeTimeoutMs, backgroundHandshakeMs)
	}
	if ab.NoRounds {
		to.MaxRounds = 1
	}
	pol := c.sessionPolicy(opts.Policy, background)
	t := c.set.cfg.TTL.resolve(to)

	var probes [2]protocol.ProbeSpec
	for r := range probes {
		if probes[r], err = c.probeSpec(roleOf(r), &opts, ab.SinglePortProbe); err != nil {
			return nil, err
		}
	}

	s := &Session{
		c:      c,
		id:     id,
		epoch:  now,
		labels: opts.Labels,
		parent: opts.Parent,
		keys:   opts.ClientKeys,
		token:  token,
		wire:   wire,
		to:     to,
		ttl:    t,
		budget: pol.Budget,
		offer:  opts.Mode,
		ablate: ab,
		wake:   make(chan struct{}, 1),
		quit:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	features := []protocol.Feature(nil)
	if c.cfg.Registry != nil && !ab.NoSandwich {
		features = []protocol.Feature{protocol.FeatureSandwich}
	}
	for r := range s.starts {
		p := pol.Clone()
		s.starts[r] = protocol.PunchStart{
			SessionID: id,
			Role:      roleOf(r),
			Token:     token,
			Wire:      wire,
			Control:   protocol.ControlSpec{Version: wiretype.Version, Features: slices.Clone(features)},
			Probe:     probes[r],
			Timeouts:  to,
			Policy:    &p,
			Mode:      opts.Mode,
		}
		s.starts[r].Timeouts.SummaryWaitMs = summaryWaitMs(t.bind, to, t)
		if _, err := msgframe.Encode(s.starts[r]); err != nil {
			return nil, fmt.Errorf("coord: punch_start for %s: %w (%w)", roleOf(r), argumentError("punch_start", "the options make an invalid punch_start"), err)
		}
	}

	q, dim, err := c.limiter.reserve(now, opts.ClientKeys)
	if err != nil {
		c.ctr.rateLimited.Add(1)
		c.emit(Event{Kind: EvRateLimited, At: now, SessionID: id, Reason: protocol.ReasonServerBusy,
			Labels: opts.Labels, Data: RateLimitedData{Dimension: dim, Key: limitedKey(dim, opts.ClientKeys)}})
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			c.limiter.release(now, &q)
		}
	}()

	if reg := c.cfg.Registry; reg != nil {
		s.unobserved = unobservedFamilies(probes)
		before := c.set.clock.Now()
		h, err := nat.RegisterProbe(reg, nat.Registration{
			SessionID: id,
			Route:     wire.RouteID,
			Token:     token,
			TTL:       t.bind + ms(to.ProbeTimeoutMs) + t.reportSlack + registrySlack,
		})
		if err != nil {
			return nil, err
		}
		s.handle = h
		for r := range s.starts {
			h.Announce(roleOf(r), s.starts[r].Probe.Observers)
		}
		s.regAt = registeredAt(h.Registered(), before, c.set.clock.Now()).Sub(now)
		defer func() {
			if !ok {
				h.Close()
			}
		}()
	}

	s.st = sessionState{
		state:    StateCreated,
		deadline: t.bind,
		expireAt: lifetime(t, to),
		rng:      rng,
		quota:    q,
		plan:     planState{planner: c.set.planner, memory: c.set.memory},
	}
	if ab.NoMemory {
		s.st.plan.memory = nil
	}
	s.refs.Store(1)
	if perr := life.Safe("coord.new_session", func() { err = s.start(now, &ok) }); perr != nil {
		if ok {
			// The session was live already: it ends, and releases what it
			// holds.
			s.finish(internalTerm(perr))
		}
		return nil, fmt.Errorf("coord: new session: %w", perr)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// start makes s live. Under the session mutex, so that nothing reaches s
// before it is complete, it admits s and only then creates what can end it —
// its context, its timer and the context watches: finish, which needs the
// mutex, never runs on a session that is not admitted. live turns true on
// admission; from then on the session owns its reservations and ends through
// finish.
func (s *Session) start(now time.Time, live *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.c
	if err := c.admit(s); err != nil {
		return err
	}
	*live = true
	s.group = life.New(c.sessCtx)
	s.timer = c.set.clock.AfterFunc(s.ttl.bind, s.onTimer)
	s.stopWatch = context.AfterFunc(s.group.Context(), s.onGroupDone)
	if s.parent != nil {
		s.stopParent = context.AfterFunc(s.parent, s.onParentDone)
	}
	c.emit(Event{Kind: EvCreated, At: now, SessionID: s.id, Labels: s.labels})
	return nil
}

// registeredAt is the instant of a natprobe registration on the
// coordinator's clock, the origin of the planner's FireAt axis.
// natprobe's own timestamp reg is exact — it is the origin of the slot times
// and of Traits.PortAnchorMs — when the Registry runs on the coordinator's
// clock, as by default (both use the system clock): it then lies between
// the readings taken before and after Register. A Registry on another clock
// has readings that mean nothing on this one; the clamp then leaves the
// nearer reading, off by the duration of Register only.
func registeredAt(reg, before, after time.Time) time.Time {
	switch {
	case reg.Before(before):
		return before
	case reg.After(after):
		return after
	}
	return reg
}

// admit makes s a live, indexed session, unless the coordinator closed or
// the id is in use.
func (c *Coordinator) admit(s *Session) error {
	sh := c.shard(s.id)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, dup := sh.m[s.id]; dup {
		return argumentError("session_id_in_use", "another live session has this id")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	c.live++
	sh.m[s.id] = s
	return nil
}

func (c *Coordinator) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// limitedKey names the key a refused dimension concerned.
func limitedKey(dim string, keys [2]string) string {
	switch dim {
	case "initiator_key", "initiator_key_rate":
		return keys[0]
	case "responder_key":
		return keys[1]
	}
	return ""
}

// identity returns the session id, token and wire spec, generated where the
// options leave them empty, and the session's own random source (round seeds
// and plan ids), seeded from Config.Rand.
func (c *Coordinator) identity(opts SessionOptions) (string, protocol.Token, protocol.WireSpec, *rand.Rand, error) {
	var buf [sessionIDBytes + len(protocol.Token{}) + len(protocol.RouteID{}) + seedBytes]byte
	if err := c.readRand(buf[:]); err != nil {
		return "", protocol.Token{}, protocol.WireSpec{}, nil, fmt.Errorf("coord: randomness: %w", err)
	}
	idb, tb := buf[:sessionIDBytes], buf[sessionIDBytes:sessionIDBytes+32]
	rb, sb := buf[sessionIDBytes+32:sessionIDBytes+48], buf[sessionIDBytes+48:]
	var seed [seedBytes]byte
	copy(seed[:], sb)
	rng := rand.New(rand.NewChaCha8(seed))

	id := opts.SessionID
	if id == "" {
		id = base64.RawURLEncoding.EncodeToString(idb)
	}
	var token protocol.Token
	if opts.Token == "" {
		copy(token[:], tb)
	} else if err := token.UnmarshalText([]byte(opts.Token)); err != nil {
		return "", token, protocol.WireSpec{}, nil, argumentError("token", "malformed session token")
	}
	wire := opts.Wire
	if wire == (protocol.WireSpec{}) {
		copy(wire.RouteID[:], rb)
		pad := udpwire.NewPadPolicy(rng)
		wire.PayloadMin, wire.PayloadMax = pad.Min, pad.Max
	}
	if !validWire(wire) {
		return "", token, wire, nil, argumentError("wire", "wire spec out of range")
	}
	return id, token, wire, rng, nil
}

// validWire checks the wire ranges: route set, payload_min in [48, 160],
// payload_max − payload_min in [64, 256], payload_max <= 1024.
func validWire(w protocol.WireSpec) bool {
	d := int(w.PayloadMax) - int(w.PayloadMin)
	return !w.RouteID.IsZero() && w.PayloadMin >= 48 && w.PayloadMin <= 160 && d >= 64 && d <= 256 && w.PayloadMax <= 1024
}

// sessionPolicy is the session's policy: the options' policy or the
// configured one, its budget defaulted and clamped to the operator ceiling
// (protocol.SessionBudgetLimit: balanced and aggressive birthday tiers need
// AllowExtreme).
func (c *Coordinator) sessionPolicy(p *protocol.Policy, background bool) protocol.Policy {
	src := c.cfg.Policy
	if p != nil {
		src = p
	}
	var pol protocol.Policy
	if src != nil {
		pol = src.Clone()
	}
	if background {
		// A field the policy leaves unset takes the Background default, the
		// slow birthday's sockets and targets; a set one stands.
		bg := protocol.BackgroundBudget()
		pol.Budget.MaxSockets = cmp.Or(pol.Budget.MaxSockets, bg.MaxSockets)
		pol.Budget.MaxDistinctTargets = cmp.Or(pol.Budget.MaxDistinctTargets, bg.MaxDistinctTargets)
	}
	pol.Budget = protocol.TightenBudget(pol.Budget, protocol.SessionBudgetLimit(c.cfg.Budget.AllowExtreme))
	return pol
}

// backgroundHandshakeMs is the handshake timeout of a Background session
// without its own Timeouts: the cheap round and the slow birthday's 45 s
// window, within the 60 s the protocol allows.
const backgroundHandshakeMs = 60000

// probeSpec returns role's ProbeSpec: the options' spec, Config.Probe or
// Config.DefaultProbe. singlePort (ablation SinglePortProbe) keeps one
// observer per family and no extra, alt, second socket, sibling or STUN.
func (c *Coordinator) probeSpec(role protocol.Role, opts *SessionOptions, singlePort bool) (protocol.ProbeSpec, error) {
	var spec protocol.ProbeSpec
	switch over := opts.InitiatorProbe; {
	case role == protocol.RoleResponder && opts.ResponderProbe != nil:
		spec = *opts.ResponderProbe
	case role == protocol.RoleInitiator && over != nil:
		spec = *over
	case c.cfg.Probe != nil:
		var err error
		if perr := life.Safe("coord.probe", func() { spec, err = c.cfg.Probe(role, opts) }); perr != nil {
			err = perr
		}
		if err != nil {
			return spec, fmt.Errorf("coord: probe spec for %s: %w", role, err)
		}
	default:
		spec = c.cfg.DefaultProbe
	}
	spec = spec.Clone()
	if spec.V == 0 {
		spec.V = protocol.ProbeSpecVersion
	}
	spec.RTTHintMs = 0 // a fresh link has no sample yet
	if singlePort {
		spec = singlePortSpec(spec)
	}
	return spec, nil
}

func singlePortSpec(spec protocol.ProbeSpec) protocol.ProbeSpec {
	var keep []protocol.ObserverSpec
	seen := map[protocol.Family]bool{}
	for _, o := range spec.Observers {
		f := protocol.FamilyOf(o.Addr.Addr())
		if o.Alt || seen[f] {
			continue
		}
		seen[f] = true
		keep = append(keep, o)
	}
	spec.Observers = keep
	spec.ExtraReply, spec.SecondSocket, spec.Siblings, spec.STUN = false, false, 0, nil
	return spec
}

// summaryWaitMs is the server's promise in punch_start: the probing
// deadline is at most untilBind + probe_timeout + ReportSlack away.
func summaryWaitMs(untilBind time.Duration, to protocol.Timeouts, t ttl) uint32 {
	d := untilBind + ms(to.ProbeTimeoutMs) + t.reportSlack
	return uint32(clampDur(d, time.Second, time.Minute) / time.Millisecond)
}

// lifetime is the defensive cap on a session's life: the sum of the
// stage deadlines, plus a second.
func lifetime(t ttl, to protocol.Timeouts) time.Duration {
	return t.bind + ms(to.ProbeTimeoutMs) + t.reportSlack + t.ready + ms(to.HandshakeTimeoutMs) + t.punchSlack +
		max(t.linger, 0) + max(t.grace, 0) + time.Second
}

// unobservedFamilies lists the families for which a role's probe spec has
// no observer: natprobe cannot verify that family's endpoints.
func unobservedFamilies(specs [2]protocol.ProbeSpec) []protocol.Family {
	var out []protocol.Family
	for _, f := range [...]protocol.Family{protocol.FamilyUDP6, protocol.FamilyUDP4} {
		for _, sp := range specs {
			if !slices.ContainsFunc(sp.Observers, func(o protocol.ObserverSpec) bool { return f.Matches(o.Addr.Addr()) }) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

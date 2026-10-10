package coord

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

// Attach gives the session role's control stream, which the caller has
// authenticated; the roles attach in either order, each once. On nil the
// connection belongs to the session — it is written punch_start and ping#1
// right away and closed when the session ends, even if the session ends while
// Attach runs, as it does with internal when the coordinator fails after taking
// the stream over. On error it is still the caller's and nothing was read or
// written: ErrSessionDone, ErrClosed, ErrAlreadyAttached, ErrInvalidRole,
// ErrInvalidConn (nil, typed nil, or no deadline support), a recovered panic,
// or a *protocol.ValidationError with Reason invalid_argument and Detail
// insecure_control when the stream is not vouched for.
func (s *Session) Attach(role protocol.Role, conn net.Conn, opts AttachOptions) (err error) {
	if perr := life.Safe("coord.attach", func() { err = s.attach(role, conn, opts) }); perr != nil {
		return fmt.Errorf("coord: attach: %w", perr)
	}
	return err
}

// connectionStater is what a TLS connection exposes.
type connectionStater interface {
	ConnectionState() tls.ConnectionState
}

// attach reserves the role, takes the stream over and settles the
// reservation. The reservation is a claim on the role and a reference that
// keeps Done open; both are returned on every path, a panic included: the
// claim when the reservation is settled, the reference last, once the link is
// the session's or closed. Until the stream is wrapped a failure leaves it
// untouched with the caller; afterwards it is the session's, and a failure
// ends the session with internal.
func (s *Session) attach(role protocol.Role, conn net.Conn, opts AttachOptions) error {
	r, insecure, err := checkAttach(role, conn, opts)
	if err != nil {
		return err
	}
	if err := s.reserveRole(r); err != nil {
		return err
	}
	defer s.release()
	l := newLink(r, role)
	l.insecure = insecure
	var fx effects
	perr := life.Safe("coord.attach", func() { fx, err = s.install(l, conn) })
	installed := s.settleRole(l)
	switch {
	case l.conn == nil:
		if perr != nil {
			return fmt.Errorf("coord: attach: %w", perr)
		}
		return err
	case !installed:
		// The session ended while the stream was being wrapped, or the install
		// failed: the stream is the session's and goes with it.
		l.close()
	}
	if perr == nil {
		perr = life.Safe("coord.attach", func() { s.apply(fx) })
	}
	if perr != nil {
		s.finish(internalTerm(perr))
	}
	return nil
}

// checkAttach validates an Attach before anything is reserved.
func checkAttach(role protocol.Role, conn net.Conn, opts AttachOptions) (r int, insecure bool, err error) {
	r, ok := roleIndex(role)
	if !ok {
		return 0, false, ErrInvalidRole
	}
	if life.IsNil(conn) {
		return 0, false, ErrInvalidConn
	}
	switch opts.Security {
	case protocol.ControlSecurityUnknown:
		cs, ok := conn.(connectionStater)
		if !ok || !cs.ConnectionState().HandshakeComplete {
			return 0, false, argumentError(detailInsecureControl, "the control stream is not TLS and not vouched for")
		}
	case protocol.ControlSecurityDeclared:
	case protocol.ControlSecurityInsecureForTesting:
		insecure = true
	default:
		return 0, false, argumentError("security", "unknown control security %d", opts.Security)
	}
	return r, insecure, nil
}

// install wraps conn into l and installs l in the session; it returns the
// effects to apply. l.conn is set once the stream is wrapped.
func (s *Session) install(l *link, conn net.Conn) (effects, error) {
	if err := faultinject.Point(fiAttach); err != nil {
		return effects{}, fmt.Errorf("coord: attach: %w", err)
	}
	c := s.c
	cw, err := controlwire.NewConn(conn, controlwire.ConnOptions{
		Side:         controlwire.SideServer,
		WriteTimeout: c.set.limits.WriteTimeout,
		MaxFrames:    c.set.limits.FramesPerLink,
		InboxSize:    1, // every accepted frame is consumed by Intercept
		Intercept:    l.intercept,
		Now:          c.set.clock.Now,
	})
	if err != nil {
		return effects{}, fmt.Errorf("%w: %w", ErrInvalidConn, err)
	}
	l.conn = cw
	return s.commitAttach(l, c.set.clock.Now()), nil
}

// reserveRole claims role r for an Attach in progress; the claim holds a
// reference so that Done waits for the Attach to finish.
func (s *Session) reserveRole(r int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.st.state == StateClosed && s.c.isClosed():
		return ErrClosed
	case s.st.state == StateClosed:
		return ErrSessionDone
	case s.st.links[r] != nil || s.st.attaching[r]:
		return ErrAlreadyAttached
	}
	s.st.attaching[r] = true
	s.refs.Add(1)
	return nil
}

// settleRole ends the claim on l's role and reports whether l was installed.
func (s *Session) settleRole(l *link) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.attaching[l.idx] = false
	return s.st.links[l.idx] == l
}

// commitAttach installs the link unless the session ended: it queues
// punch_start (with this link's summary_wait_ms) and ping#1, moves the state
// forward, re-arms the timer and starts the session goroutine with the first
// link. The link is installed before anything that can fail, so that finish
// closes it whatever happens next.
func (s *Session) commitAttach(l *link, now time.Time) effects {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	r := l.idx
	if st.state == StateClosed {
		return effects{}
	}
	t := s.since(now)
	l.attachAt = t
	l.frames = newBucket(s.c.set.limits.FrameRate, now)
	l.assistIn = newBucket(s.c.set.limits.AssistIn, now)
	l.relayTo = newBucket(s.c.set.limits.AssistRelay, now)
	st.links[r] = l
	st.updated = t
	if l.insecure {
		st.addWarn(protocol.WarnInsecureControlForTesting)
	}

	var fx effects
	other := st.links[1-r]
	start := cloneStart(s.starts[r])
	if other != nil {
		start.Timeouts.SummaryWaitMs = summaryWaitMs(0, s.to, s.ttl)
		st.state = StateProbing
		st.deadline = t + ms(s.to.ProbeTimeoutMs) + s.ttl.reportSlack
		s.c.limiter.leavePending(&st.quota)
	} else {
		start.Timeouts.SummaryWaitMs = summaryWaitMs(st.deadline-t, s.to, s.ttl)
		st.state = StateBinding
	}
	fx.merge(s.sendMarkedLocked(r, start, &l.markStart))
	if !l.dead {
		fx.merge(s.sendPingLocked(r))
	}
	if !st.loop {
		st.loop = true
		s.refs.Add(1) // the session goroutine's share; it drops it when it returns
		if !s.group.Go("coord.session", func(context.Context) { s.run() }) {
			s.refs.Add(-1) // never the last reference: finish has not dropped its own
		}
	}
	s.kick() // the session goroutine picks up the new link
	s.rearmLocked(t)
	s.c.emit(Event{Kind: EvAttached, At: now, SessionID: s.id, Role: l.role, Labels: s.labels,
		Data: AttachedData{ClientKey: s.keys[r]}})
	return fx
}

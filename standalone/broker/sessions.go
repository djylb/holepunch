package broker

import (
	"errors"
	"fmt"
	"maps"
	"net"

	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/internal/life"
	"github.com/djylb/holepunch/standalone/proto"
)

// OpenRequest asks for a session with a host.
type OpenRequest struct {
	HostID   string
	DialerID string // optional, self-declared
	Metadata map[string]string
	// ClientKey is the dialer's key for the coordinator's per-key limits and
	// quotas (coord.SessionOptions.ClientKeys); the server uses the dialer's
	// address, since dialer IDs are self-declared. "" is not limited.
	ClientKey string
}

// Session is one session the broker matched: a dialer and a host around a
// coord.Session.
type Session struct {
	b         *Broker
	cs        *coord.Session
	host      *Host
	info      proto.SessionInfo
	ticketSum secret

	joined bool // guarded by b.mu
}

// Open matches a dialer with the registered host req.HostID: it calls
// Authorize, creates the coord session (its responder key is "host:" + the
// host ID), and sends the host an Incoming with a fresh ticket. The dialer's
// stream is then attached as the initiator. Errors: ErrInvalidRequest,
// ErrClosed, ErrHostNotFound (also when the host cannot be notified),
// ErrRefused, and the coordinator's (coord.ErrBusy, …).
func (b *Broker) Open(req OpenRequest) (*Session, error) {
	if !proto.ValidName(req.HostID) || req.DialerID != "" && !proto.ValidName(req.DialerID) {
		return nil, fmt.Errorf("%w: host or dialer ID", ErrInvalidRequest)
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	h := b.hosts[req.HostID]
	if h == nil {
		b.mu.Unlock()
		return nil, ErrHostNotFound
	}
	hi := h.infoLocked()
	b.mu.Unlock()

	policy, err := b.policy(req, hi)
	if err != nil {
		return nil, err
	}
	labels := map[string]string{"host_id": req.HostID}
	if req.DialerID != "" {
		labels["dialer_id"] = req.DialerID
	}
	cs, err := b.coord.NewSession(coord.SessionOptions{
		ClientKeys: [2]string{req.ClientKey, "host:" + req.HostID},
		Labels:     labels,
	})
	if err != nil {
		return nil, err
	}
	ticket, sum := newSecret()
	s := &Session{b: b, cs: cs, host: h, ticketSum: sum, info: proto.SessionInfo{
		SessionID: cs.ID(), HostID: req.HostID, DialerID: req.DialerID,
		HostMetadata: maps.Clone(h.metadata), DialerMetadata: maps.Clone(req.Metadata), Policy: policy,
	}}
	if err := b.index(s); err != nil {
		cs.Abort(protocol.ReasonPeerOffline, "host_gone")
		return nil, err
	}
	in := proto.Incoming{SessionID: cs.ID(), Ticket: ticket, DialerID: req.DialerID, DialerMetadata: maps.Clone(req.Metadata)}
	if err := h.notify(in); err != nil {
		cs.Abort(protocol.ReasonPeerOffline, "host_unreachable")
		return nil, err
	}
	return s, nil
}

// policy runs the Authorize hook and canonicalises its policy. The hook
// gets copies of the metadata, and its error is formatted inside the
// recover boundary, since the error's methods are the hook's code too.
func (b *Broker) policy(req OpenRequest, hi HostInfo) (proto.AccessPolicy, error) {
	if b.authorize == nil {
		return proto.AccessPolicy{}, nil
	}
	req.Metadata = maps.Clone(req.Metadata)
	var (
		p   proto.AccessPolicy
		err error
	)
	if perr := life.Safe("broker.Authorize", func() {
		if p, err = b.authorize(req, hi); err != nil {
			err = fmt.Errorf("%w: %v", ErrRefused, err)
		}
	}); perr != nil {
		return proto.AccessPolicy{}, fmt.Errorf("%w: authorize failed", ErrRefused)
	}
	if err != nil {
		return proto.AccessPolicy{}, err
	}
	if len(p.Targets) > proto.MaxTargets {
		return proto.AccessPolicy{}, fmt.Errorf("broker: Authorize returned %d targets > %d", len(p.Targets), proto.MaxTargets)
	}
	out := proto.AccessPolicy{Targets: make([]string, 0, len(p.Targets))}
	for _, t := range p.Targets {
		c, err := proto.CanonicalTarget(t)
		if err != nil {
			return proto.AccessPolicy{}, fmt.Errorf("broker: Authorize returned target %q: %w", t, err)
		}
		out.Targets = append(out.Targets, c)
	}
	if len(out.Targets) == 0 {
		out.Targets = nil
	}
	return out, nil
}

// index records a new session, unless its host went away or the session
// ended meanwhile. The Done check under the lock closes the race with
// forget: the coordinator closes Done before it reports the Result, so a
// session that ended before it was indexed is never indexed.
func (b *Broker) index(s *Session) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.closed:
		return ErrClosed
	case s.host.gone:
		return ErrHostNotFound
	}
	select {
	case <-s.cs.Done():
		return fmt.Errorf("%w: session ended", ErrHostNotFound)
	default:
	}
	b.sessions[s.info.SessionID] = s
	s.host.sessions[s.info.SessionID] = s
	return nil
}

// Join returns the session a host was told about, once: the ticket must be
// the one its Incoming carried. Any mismatch — unknown or finished session,
// a second join, a wrong ticket — is ErrSessionNotFound.
func (b *Broker) Join(sessionID, ticket string) (*Session, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[sessionID]
	if s == nil || s.joined || !s.ticketSum.matches(ticket) {
		return nil, ErrSessionNotFound
	}
	s.joined = true
	return s, nil
}

// ID returns the session ID.
func (s *Session) ID() string { return s.info.SessionID }

// Info returns the session's description, the SessionInfo both sides
// receive.
func (s *Session) Info() proto.SessionInfo { return s.info.Clone() }

// Coord returns the coord session, for Inject, Snapshot, Done and Result.
func (s *Session) Coord() *coord.Session { return s.cs }

// Attach hands role's control stream to the session and always takes it:
// on success the coordinator owns conn, on failure Attach closes conn and
// aborts the session, which cannot complete without that side. The error is
// the coordinator's (coord.ErrSessionDone, coord.ErrInvalidConn, an
// insecure_control invalid_argument, …).
func (s *Session) Attach(role protocol.Role, conn net.Conn, opts coord.AttachOptions) error {
	err := s.cs.Attach(role, conn, opts)
	if err == nil {
		return nil
	}
	if !life.IsNil(conn) {
		_ = life.Safe("broker.Attach.close", func() { _ = conn.Close() })
	}
	code := protocol.ReasonControlInterrupted
	if invalidArgument(err) {
		code = protocol.ReasonInvalidArgument
	}
	s.cs.Abort(code, "attach_failed")
	return err
}

// invalidArgument reports whether err, an error of the coordinator, is an
// invalid_argument refusal. A recovered panic is tested first, since its
// panic value may wrap any error.
func invalidArgument(err error) bool {
	if life.IsPanic(err) {
		return false
	}
	var ve *protocol.ValidationError
	return errors.As(err, &ve) && ve.Reason == protocol.ReasonInvalidArgument
}

// Abort ends the session (coord.Session.Abort).
func (s *Session) Abort(code protocol.Reason, detail string) { s.cs.Abort(code, detail) }

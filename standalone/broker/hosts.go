package broker

import (
	"fmt"
	"maps"
	"time"

	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/internal/life"
	"github.com/djylb/holepunch/standalone/proto"
)

// Signal is the broker's handle on a host's registration link. The server
// implements it; both methods are called outside the broker's lock, inside a
// recover boundary, and must not block for long.
type Signal interface {
	// Notify delivers an Incoming to the host. An error means the host
	// cannot be reached: the session is aborted and the open fails.
	Notify(in proto.Incoming) error //holepunch:callback
	// Revoke tells the link's owner that the broker dropped the registration
	// on its own — a takeover with the credential, or Close — so the link
	// should be closed.
	Revoke() //holepunch:callback
}

// Registration registers a host.
type Registration struct {
	HostID string
	// Credential is the credential of the registration that holds HostID,
	// if any; it is only needed to take a live ID over.
	Credential string
	// Metadata goes to the dialers in SessionInfo.HostMetadata.
	Metadata map[string]string
}

// HostInfo describes a registered host.
type HostInfo struct {
	HostID       string
	Metadata     map[string]string
	RegisteredAt time.Time
	Sessions     int // live sessions with the host
}

// Host is one registration. Close it when its link ends.
type Host struct {
	b        *Broker
	id       string
	metadata map[string]string
	at       time.Time
	cred     string
	credSum  secret
	sig      Signal

	// Guarded by b.mu.
	gone     bool
	sessions map[string]*Session
}

// Register registers reg.HostID with sig. A live ID is taken over only with
// its registration's credential (reg.Credential): the previous Host is then
// unregistered, its Signal revoked and its sessions that were not joined yet
// aborted. Errors: ErrInvalidRequest, ErrClosed, ErrHostExists,
// ErrRegistryFull.
func (b *Broker) Register(reg Registration, sig Signal) (*Host, error) {
	if !proto.ValidName(reg.HostID) || life.IsNil(sig) {
		return nil, fmt.Errorf("%w: host ID or signal", ErrInvalidRequest)
	}
	cred, sum := newSecret()
	h := &Host{
		b: b, id: reg.HostID, metadata: maps.Clone(reg.Metadata), at: b.now(),
		cred: cred, credSum: sum, sig: sig, sessions: map[string]*Session{},
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	old := b.hosts[reg.HostID]
	switch {
	case old != nil && (reg.Credential == "" || !old.credSum.matches(reg.Credential)):
		b.mu.Unlock()
		return nil, ErrHostExists
	case old == nil && len(b.hosts) >= b.maxHosts:
		b.mu.Unlock()
		return nil, ErrRegistryFull
	}
	b.hosts[reg.HostID] = h
	var orphans []*Session
	if old != nil {
		old.gone = true
		orphans = old.pendingLocked()
	}
	b.mu.Unlock()
	if old != nil {
		old.revoke()
		abortAll(orphans, "host_replaced")
	}
	return h, nil
}

// ID returns the host ID.
func (h *Host) ID() string { return h.id }

// Credential returns the credential the host must present to take its ID
// over later (proto.Registered.Credential).
func (h *Host) Credential() string { return h.cred }

// Info describes the host.
func (h *Host) Info() HostInfo {
	h.b.mu.Lock()
	defer h.b.mu.Unlock()
	return h.infoLocked()
}

func (h *Host) infoLocked() HostInfo {
	return HostInfo{HostID: h.id, Metadata: maps.Clone(h.metadata), RegisteredAt: h.at, Sessions: len(h.sessions)}
}

// Close unregisters the host, unless it was replaced already, and aborts
// its sessions that the host has not joined: their Incoming went to the
// link that ended. Sessions already joined run on. It is idempotent.
func (h *Host) Close() {
	b := h.b
	b.mu.Lock()
	if h.gone {
		b.mu.Unlock()
		return
	}
	h.gone = true
	if b.hosts[h.id] == h {
		delete(b.hosts, h.id)
	}
	orphans := h.pendingLocked()
	b.mu.Unlock()
	abortAll(orphans, "host_disconnected")
}

// pendingLocked returns the host's sessions it has not joined.
func (h *Host) pendingLocked() []*Session {
	var out []*Session
	for _, s := range h.sessions {
		if !s.joined {
			out = append(out, s)
		}
	}
	return out
}

func (h *Host) revoke() {
	_ = life.Safe("broker.Signal.Revoke", func() { h.sig.Revoke() })
}

// notify tells the host about a session; any failure is ErrHostNotFound,
// which also wraps a recovered panic. The Signal's error is formatted inside
// the recover boundary, since its methods are the Signal's code too.
func (h *Host) notify(in proto.Incoming) error {
	var err error
	if perr := life.Safe("broker.Signal.Notify", func() {
		if err = h.sig.Notify(in); err != nil {
			err = fmt.Errorf("%w: %v", ErrHostNotFound, err)
		}
	}); perr != nil {
		return fmt.Errorf("%w: %w", ErrHostNotFound, perr)
	}
	return err
}

// abortAll aborts sessions whose host is gone; the caller holds no lock,
// since an abort may report the Result synchronously.
func abortAll(sessions []*Session, detail string) {
	for _, s := range sessions {
		s.cs.Abort(protocol.ReasonPeerOffline, detail)
	}
}

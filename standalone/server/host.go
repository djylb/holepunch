package server

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/djylb/holepunch/standalone/broker"
	"github.com/djylb/holepunch/standalone/internal/life"
	"github.com/djylb/holepunch/standalone/proto"
)

// hostLink is a host's registration link, the broker.Signal of its Host.
type hostLink struct {
	s    *Server
	conn net.Conn // the TLS stream
	raw  net.Conn // closing it fails a blocked write at once, unlike a TLS close

	mu sync.Mutex // serialises writes: Incoming from dialers' goroutines, heartbeats from the reader
	// A dialer can open a session as soon as the broker has registered the
	// host: until Registered is written, its Incoming waits in queued.
	registered bool
	queued     []proto.Incoming
}

// errLinkLost is Notify's error. What failed concerns the host's
// connection, and the dialer whose open fails is told no more.
var errLinkLost = errors.New("server: registration link lost")

// Notify writes the Incoming, or queues it until Registered is written; a
// failed write closes the link, whose reader then unregisters the host.
func (l *hostLink) Notify(in proto.Incoming) error {
	if err := l.deliver(&in); err != nil {
		l.s.log.Debug("incoming write failed", "session", in.SessionID, "err", err)
		return errLinkLost
	}
	return nil
}

// deliver writes or queues in. The write runs the connection's methods,
// which may panic on this dialer's goroutine: the deferred unlock leaves
// the lock free for the link's reader and the other dialers.
func (l *hostLink) deliver(in *proto.Incoming) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.registered {
		l.queued = append(l.queued, *in)
		return nil
	}
	return l.writeLocked(in)
}

// welcome writes Registered, then the Incoming notices queued before it.
func (l *hostLink) welcome(m *proto.Registered) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.registered = true
	queued := l.queued
	l.queued = nil
	err := l.writeLocked(m)
	for i := 0; err == nil && i < len(queued); i++ {
		err = l.writeLocked(&queued[i])
	}
	return err
}

// Revoke closes the link: the broker gave the host ID to a new
// registration, or is closing.
func (l *hostLink) Revoke() { _ = l.raw.Close() }

func (l *hostLink) write(m proto.Message) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.writeLocked(m)
}

// writeLocked writes m with l.mu held. A write that fails or panics closes
// the link: the stream may end in part of a frame.
func (l *hostLink) writeLocked(m proto.Message) error {
	written := false
	defer func() {
		if !written {
			_ = l.raw.Close()
		}
	}()
	err := proto.Write(l.conn, m, l.s.cfg.WriteTimeout)
	written = err == nil
	return err
}

// serveHost registers the host and serves its link until it ends: the link
// is read with a deadline of three heartbeat intervals, every Heartbeat is
// answered and every Transport report passed to Config.OnTransport.
func (s *Server) serveHost(st *stream, m *proto.Register) {
	if err := s.authorize(st, AuthRequest{Scope: ScopeRegister, HostID: m.HostID, Token: m.AuthToken, Metadata: m.Metadata}); err != nil {
		s.refuse(st, proto.CodeUnauthorized, "")
		return
	}
	link := &hostLink{s: s, conn: st.conn, raw: st.raw}
	h, err := s.cfg.Broker.Register(broker.Registration{HostID: m.HostID, Credential: m.Credential, Metadata: m.Metadata}, link)
	if err != nil {
		s.refuseErr(st, err)
		return
	}
	defer h.Close()
	if err := link.welcome(&proto.Registered{Credential: h.Credential(), HeartbeatMs: uint32(s.cfg.Heartbeat / time.Millisecond)}); err != nil {
		return
	}
	s.registered.Add(1)
	s.hostLinks(1)
	defer s.hostLinks(-1)
	s.log.Debug("host registered", "host", h.ID(), "remote", st.remote)
	for {
		if err := st.conn.SetReadDeadline(time.Now().Add(3 * s.cfg.Heartbeat)); err != nil {
			return
		}
		m, err := proto.Decode(st.conn)
		if err != nil {
			s.log.Debug("host link ended", "host", h.ID(), "err", err)
			return
		}
		switch m := m.(type) {
		case *proto.Heartbeat:
			if link.write(&proto.Heartbeat{}) != nil {
				return
			}
		case *proto.Transport:
			s.onTransport(TransportReport{HostID: h.ID(), SessionID: m.SessionID, OK: m.OK, Detail: m.Detail})
		default:
			s.log.Debug("host link protocol error", "host", h.ID(), "type", m.Type())
			return
		}
	}
}

func (s *Server) onTransport(r TransportReport) {
	if s.cfg.OnTransport == nil {
		return
	}
	if perr := life.Safe("server.OnTransport", func() { s.cfg.OnTransport(r) }); perr != nil {
		s.panics.Add(1)
		s.log.Warn("OnTransport panicked", "err", perr)
	}
}

func (s *Server) hostLinks(delta int) {
	s.mu.Lock()
	s.hosts += delta
	s.mu.Unlock()
}

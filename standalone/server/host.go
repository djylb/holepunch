package server

import (
	"net"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/standalone/broker"
	"github.com/djylb/holepunch/standalone/proto"
)

// hostLink is a host's registration link, the broker.Signal of its Host.
type hostLink struct {
	s    *Server
	conn net.Conn // the TLS stream
	raw  net.Conn // closing it fails a blocked write at once, unlike a TLS close

	mu sync.Mutex // serialises writes: Incoming from dialers' goroutines, heartbeats from the reader
}

// Notify writes the Incoming; a failed write closes the link, whose reader
// then unregisters the host.
func (l *hostLink) Notify(in proto.Incoming) error {
	return l.write(&in)
}

// Revoke closes the link: the broker gave the host ID to a new
// registration, or is closing.
func (l *hostLink) Revoke() { _ = l.raw.Close() }

func (l *hostLink) write(m proto.Message) error {
	l.mu.Lock()
	err := proto.Write(l.conn, m, l.s.cfg.WriteTimeout)
	l.mu.Unlock()
	if err != nil {
		_ = l.raw.Close()
	}
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
	if err := link.write(&proto.Registered{Credential: h.Credential(), HeartbeatMs: uint32(s.cfg.Heartbeat / time.Millisecond)}); err != nil {
		return
	}
	s.registered.Add(1)
	s.hostLinks(1)
	defer s.hostLinks(-1)
	s.log.Debug("host registered", "host", h.ID(), "remote", remote(st.raw))
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

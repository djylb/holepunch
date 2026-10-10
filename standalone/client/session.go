package client

import (
	"maps"
	"net"
	"strings"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/proto"
	"github.com/djylb/holepunch/udpwire"
)

// Session is a punched session: the UDP path to the peer and what the server
// said about the session. Its methods are safe for concurrent use.
type Session struct {
	info   proto.SessionInfo
	role   protocol.Role
	hp     *holepunch.Session
	pc     net.PacketConn
	report func(proto.Transport) error // nil for sessions opened as a dialer
}

func newSession(info proto.SessionInfo, role protocol.Role, hp *holepunch.Session, report func(proto.Transport) error) *Session {
	rf := hp.ResidualFilter()
	return &Session{
		info:   info,
		role:   role,
		hp:     hp,
		pc:     udpwire.DropResidual(hp.PacketConn(), rf.Codec, rf.Window),
		report: report,
	}
}

// ID returns the session ID.
func (s *Session) ID() string { return s.info.SessionID }

// Role returns this side's role: initiator for Open, responder for Serve.
func (s *Session) Role() protocol.Role { return s.role }

// Info returns the server's description of the session.
func (s *Session) Info() proto.SessionInfo {
	info := s.info
	info.HostMetadata = maps.Clone(info.HostMetadata)
	info.DialerMetadata = maps.Clone(info.DialerMetadata)
	info.Policy.Targets = append([]string(nil), info.Policy.Targets...)
	if len(info.Policy.Targets) == 0 {
		info.Policy.Targets = nil
	}
	return info
}

// Result returns the punch's result: addresses, transport decision and
// peer data, keepalive advice.
func (s *Session) Result() holepunch.Result { return s.hp.Result() }

// Diagnostics returns the punch's diagnostics.
func (s *Session) Diagnostics() holepunch.Diagnostics { return s.hp.Diagnostics() }

// Holepunch returns the underlying holepunch session; its PacketConn is the
// raw winning socket, which a QUIC upper layer takes.
func (s *Session) Holepunch() *holepunch.Session { return s.hp }

// PacketConn returns the winning socket wrapped in udpwire.DropResidual, so
// that a non-QUIC upper layer never sees the late handshake packets of the
// punch (holepunch Session.ResidualFilter). Closing it closes the socket;
// close the Session instead, which also releases a port mapping.
func (s *Session) PacketConn() net.PacketConn { return s.pc }

// ReportTransport tells the server, over the host's registration link,
// whether the upper-layer transport came up on the punched path. It is
// telemetry: a failed report changes nothing about the session. Sessions
// opened with Open have no link to report on (ErrNoLink).
func (s *Session) ReportTransport(ok bool, detail string) error {
	if s.report == nil {
		return ErrNoLink
	}
	if len(detail) > proto.MaxTextLen {
		detail = strings.ToValidUTF8(detail[:proto.MaxTextLen], "")
	}
	return s.report(proto.Transport{SessionID: s.info.SessionID, OK: ok, Detail: detail})
}

// Close closes the session: its port mapping, if any, and its socket. It is
// idempotent.
func (s *Session) Close() error { return s.hp.Close() }

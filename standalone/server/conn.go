package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"maps"
	"net"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/broker"
	"github.com/djylb/holepunch/standalone/internal/life"
	"github.com/djylb/holepunch/standalone/proto"
)

// stream is one accepted connection while the server serves it.
type stream struct {
	raw  net.Conn // as accepted: what the server tracks and closes
	conn net.Conn // raw, or its TLS server side
	// The fields below belong to the connection's goroutine.
	remote string // raw's remote address, for the log
	// handedOver is set just before the stream is attached to a session,
	// which takes it whether the attach succeeds or not.
	handedOver bool
}

// handle serves one connection inside a recover boundary and closes it
// unless it was handed to a session. The connection's methods are the
// caller's code, so every call on it is inside that boundary or closeConn.
func (s *Server) handle(ctx context.Context, st *stream) {
	if perr := life.Safe("standalone.conn", func() { s.serve(ctx, st) }); perr != nil {
		s.panics.Add(1)
		s.log.Warn("connection handler panicked", "remote", st.remote, "err", perr)
	}
	if !st.handedOver {
		s.drop(st)
	}
}

// serve terminates TLS, reads the first request and dispatches it.
func (s *Server) serve(ctx context.Context, st *stream) {
	st.remote = remote(st.raw)
	hctx, cancel := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
	defer cancel()
	if s.cfg.TLS != nil {
		tc := tls.Server(st.raw, s.cfg.TLS)
		if err := tc.HandshakeContext(hctx); err != nil {
			s.handshakeFailed.Add(1)
			s.log.Debug("tls handshake failed", "remote", st.remote, "err", err)
			return
		}
		st.conn = tc
	}
	m, err := proto.Read(hctx, st.conn)
	if err != nil {
		s.handshakeFailed.Add(1)
		s.log.Debug("first request failed", "remote", st.remote, "err", err)
		if detail := malformed(err); detail != "" {
			s.refuse(st, proto.CodeInvalidRequest, detail)
		}
		return
	}
	switch m := m.(type) {
	case *proto.Register:
		s.serveHost(st, m)
	case *proto.Open:
		s.serveOpen(st, m)
	case *proto.Join:
		s.serveJoin(st, m)
	default:
		s.refuse(st, proto.CodeInvalidRequest, "unexpected "+m.Type().String())
	}
}

func (s *Server) serveOpen(st *stream, m *proto.Open) {
	if err := s.authorize(st, AuthRequest{Scope: ScopeOpen, HostID: m.HostID, DialerID: m.DialerID, Token: m.AuthToken, Metadata: m.Metadata}); err != nil {
		s.refuse(st, proto.CodeUnauthorized, "")
		return
	}
	sess, err := s.cfg.Broker.Open(broker.OpenRequest{
		HostID: m.HostID, DialerID: m.DialerID, Metadata: m.Metadata, ClientKey: clientKey(st.raw),
	})
	if err != nil {
		s.refuseErr(st, err)
		return
	}
	if s.reply(st, sess) {
		s.opened.Add(1)
		s.attach(st, sess, protocol.RoleInitiator)
	}
}

func (s *Server) serveJoin(st *stream, m *proto.Join) {
	sess, err := s.cfg.Broker.Join(m.SessionID, m.Ticket)
	if err != nil {
		s.refuseErr(st, err)
		return
	}
	if s.reply(st, sess) {
		s.joined.Add(1)
		s.attach(st, sess, protocol.RoleResponder)
	}
}

// reply writes the session's SessionInfo; a stream that cannot take it
// cannot carry the session either, which is aborted.
func (s *Server) reply(st *stream, sess *broker.Session) bool {
	info := sess.Info()
	if err := proto.Write(st.conn, &info, s.cfg.WriteTimeout); err != nil {
		sess.Abort(protocol.ReasonControlInterrupted, "session_info_write")
		s.log.Debug("session info write failed", "session", sess.ID(), "err", err)
		return false
	}
	return true
}

// attach hands the stream over for good; Attach takes it even on failure.
func (s *Server) attach(st *stream, sess *broker.Session, role protocol.Role) {
	st.handedOver = true
	s.untrack(st)
	if err := sess.Attach(role, st.conn, coord.AttachOptions{Security: s.cfg.Security}); err != nil {
		s.log.Debug("attach failed", "session", sess.ID(), "role", role, "err", err)
	}
}

// authorize checks the shared token in constant time — comparing SHA-256
// digests, so that not even the token's length leaks — and then asks
// Config.Authorize.
func (s *Server) authorize(st *stream, req AuthRequest) error {
	if s.tokenSum != nil {
		given := sha256.Sum256([]byte(strings.TrimSpace(req.Token)))
		if subtle.ConstantTimeCompare(given[:], s.tokenSum[:]) != 1 {
			return errUnauthorized
		}
	}
	if s.cfg.Authorize == nil {
		return nil
	}
	// The hook gets its own copy: the request's metadata goes on to the
	// broker.
	req.Metadata = maps.Clone(req.Metadata)
	req.Remote = st.raw.RemoteAddr()
	if tc, ok := st.conn.(*tls.Conn); ok {
		cs := tc.ConnectionState()
		req.TLS = &cs
	}
	var err error
	if perr := life.Safe("server.Authorize", func() { err = s.cfg.Authorize(req) }); perr != nil {
		s.panics.Add(1)
		s.log.Warn("Authorize panicked", "err", perr)
		return errUnauthorized
	}
	return err
}

var errUnauthorized = errors.New("server: unauthorized")

// malformed is the Fail detail of a first request that failed to decode —
// "version", "type" or "message" — or "" for a read that failed otherwise.
func malformed(err error) string {
	switch {
	case errors.Is(err, proto.ErrVersion):
		return "version"
	case errors.Is(err, proto.ErrType):
		return "type"
	case errors.Is(err, proto.ErrInvalid):
		return "message"
	}
	return ""
}

// refuseErr answers a broker or coordinator error with its code and, for a
// refused argument, the field the coordinator named; the error's text goes
// to the log only.
func (s *Server) refuseErr(st *stream, err error) {
	code := codeOf(err)
	s.log.Debug("request refused", "remote", st.remote, "code", code, "err", err)
	detail := ""
	var ve *protocol.ValidationError
	if code == proto.CodeInvalidRequest && !life.IsPanic(err) && errors.As(err, &ve) {
		detail = ve.Detail
	}
	s.refuse(st, code, detail)
}

// refuse answers Fail; the stream is closed by handle afterwards.
func (s *Server) refuse(st *stream, code proto.Code, msg string) {
	s.refused.Add(1)
	_ = proto.Write(st.conn, &proto.Fail{Code: code, Message: sanitize(msg)}, s.cfg.WriteTimeout)
}

// codeOf maps an error of the broker or the coordinator to a Fail code. A
// recovered panic is tested first, since it may wrap any error.
func codeOf(err error) proto.Code {
	var ve *protocol.ValidationError
	switch {
	case life.IsPanic(err):
		return proto.CodeInternal
	case errors.Is(err, broker.ErrClosed), errors.Is(err, coord.ErrClosed):
		return proto.CodeShutdown
	case errors.Is(err, broker.ErrInvalidRequest), errors.As(err, &ve) && ve.Reason == protocol.ReasonInvalidArgument:
		return proto.CodeInvalidRequest
	case errors.Is(err, broker.ErrHostNotFound):
		return proto.CodeHostNotFound
	case errors.Is(err, broker.ErrHostExists):
		return proto.CodeHostExists
	case errors.Is(err, broker.ErrRegistryFull), errors.Is(err, coord.ErrBusy):
		return proto.CodeBusy
	case errors.Is(err, broker.ErrRefused):
		return proto.CodeUnauthorized
	case errors.Is(err, broker.ErrSessionNotFound):
		return proto.CodeSessionNotFound
	}
	return proto.CodeInternal
}

// sanitize makes an error text fit Fail.Message: printable, at most
// proto.MaxTextLen bytes.
func sanitize(msg string) string {
	msg = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(msg, " "))
	if len(msg) > proto.MaxTextLen {
		msg = msg[:proto.MaxTextLen]
		for !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
	}
	return msg
}

// clientKey is the dialer's key for the coordinator's per-key limits: its
// IP address, since dialer IDs are self-declared.
func clientKey(c net.Conn) string {
	a := c.RemoteAddr()
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return "addr:" + a.String()
	}
	return "ip:" + host
}

func remote(c net.Conn) string {
	if a := c.RemoteAddr(); a != nil {
		return a.String()
	}
	return ""
}

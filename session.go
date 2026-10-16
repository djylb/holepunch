package holepunch

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// Session is a successful hole punch: the caller owns the sockets of the
// confirmed paths — the primary path's and, with Options.MaxPaths above 1,
// those of the extra paths. When AttachSession
// returns it, the library has stopped reading and writing these sockets for
// good, cleared their deadlines and restored their TTL; it never touches
// them again. The methods are safe for concurrent use.
type Session struct {
	result   Result
	diag     Diagnostics
	conn     net.PacketConn   // the primary path's socket
	extra    []net.PacketConn // the extra paths' sockets, in the order of Result.ExtraPaths
	residual ResidualFilter
	releases []func() error // the handed-over sockets' port-mapping releases

	closeOnce sync.Once
	closeErr  error
}

// PacketConn returns the primary path's socket, exactly as
// Network.ListenPacket returned it (no wrapper, so optional capabilities such
// as *net.UDPConn's stay available). Close the Session rather than the conn
// directly, so that a port mapping on it is released too.
func (s *Session) PacketConn() net.PacketConn { return s.conn }

// ExtraPacketConns returns the sockets of Result.ExtraPaths, in the same
// order and as Network.ListenPacket returned them; empty with one path. Two
// paths of different kinds of network — a LAN and a public path — can run
// through one socket: the conn then appears for both (and may be
// PacketConn's), and the caller tells their datagrams apart by the remote
// address. Close the Session rather than these conns directly.
func (s *Session) ExtraPacketConns() []net.PacketConn { return slices.Clone(s.extra) }

// Result returns what the session achieved (a copy).
func (s *Session) Result() Result { return s.result }

// Diagnostics returns the session's diagnostics (a deep copy).
func (s *Session) Diagnostics() Diagnostics { return s.diag.clone() }

// ResidualFilter returns the residual-packet filter of the handover. A
// listener whose upper layer is not QUIC — a provider serving KCP, for
// example — must wrap each handed-over socket, so that late
// holepunch handshake packets never reach it:
//
//	rf := sess.ResidualFilter()
//	pc := udpwire.DropResidual(sess.PacketConn(), rf.Codec, rf.Window)
//
// QUIC needs no wrapper: it drops these packets by their first byte.
func (s *Session) ResidualFilter() ResidualFilter { return s.residual }

// Close releases the port mappings of the handed-over sockets, if any, and
// then closes every socket of the session's paths, each once. It is
// idempotent and safe for concurrent use: every caller gets the first error
// (net.ErrClosed is not an error). It returns within the port mapper's
// release bound (2 s per mapping, released one after the other).
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		var errs []error
		for _, release := range s.releases {
			var rerr error
			if p := life.Safe("portmap.release", func() { rerr = release() }); p != nil {
				rerr = p
			}
			errs = append(errs, rerr)
		}
		var closed []net.PacketConn
		for _, c := range append([]net.PacketConn{s.conn}, s.extra...) {
			if slices.ContainsFunc(closed, func(x net.PacketConn) bool { return sameConn(x, c) }) {
				continue
			}
			closed = append(closed, c)
			var cerr error
			// The conn and its error are the Network's: both are inspected
			// inside the boundary.
			if p := life.Safe("session.close", func() {
				if cerr = c.Close(); errors.Is(cerr, net.ErrClosed) {
					cerr = nil
				}
			}); p != nil {
				cerr = p
			}
			errs = append(errs, cerr)
		}
		for _, e := range errs {
			if e != nil {
				s.closeErr = e
				break
			}
		}
	})
	return s.closeErr
}

// sameConn reports whether a and b are the same conn. A Network may return a
// conn whose dynamic type == cannot compare, which panics; such conns count
// as different, so one on two paths is closed twice (net.ErrClosed, the
// usual answer to the second Close, is no error).
func sameConn(a, b net.PacketConn) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}

// ResidualFilter carries the parameters of udpwire.DropResidual for the
// handed-over sockets. The remotes of every confirmed path are bound in the
// codec (Codec.Peers()), so one filter serves them all.
type ResidualFilter struct {
	Codec  *udpwire.Codec // the session codec, peers bound at handover: only recognises residual packets, never answers them
	Window time.Duration  // how long after the handover to filter (udpwire.DefaultResidualWindow)
}

// Result describes a successful session.
type Result struct {
	SessionID string
	Role      protocol.Role
	Path      Path // the primary path, on Session.PacketConn
	// ExtraPaths are the other confirmed paths, on Session.ExtraPacketConns in
	// the same order: at most Options.MaxPaths-1, empty with one path. The peer
	// holds the same paths.
	ExtraPaths       []Path
	TransportMode    string        // the server's transport decision (probe_summary.transport.mode), equal on both sides
	TransportData    string        // the peer's TransportData (probe_summary.transport.peer_data)
	TransportTimeout time.Duration // timeouts.transport_timeout_ms, for the upper layer
	Variant          string        // the winning round's RoundPlan.variant (always the server's)
	Rounds           int           // rounds run
	Timing           Timing
}

// Path is one confirmed path of a session: its socket's address, the
// peer's address on it, the kind of network between the two
// and what the upper layer needs to keep it
// alive. A caller that must not run over a tunnel checks Kind, or excludes
// overlay paths up front (Options.ExcludeOverlay).
type Path struct {
	Family      protocol.Family
	Kind        protocol.PathKind         // public, lan, overlay or portmap
	LocalAddr   netip.AddrPort            // concrete local address; wildcards replaced by the interface address
	RemoteAddr  netip.AddrPort            // the confirmed peer address
	RTT         time.Duration             // the smallest UDP round trip measured on the path; 0 without a sample
	Keepalive   KeepaliveAdvice           // keepalive advice for the upper layer on this path
	PortMapping *protocol.PortMappingInfo // the port mapping of the path's socket, released by Session.Close; nil without
}

// Timing breaks a session's duration down by phase.
type Timing struct{ Probe, SummaryWait, GoWait, Punch, Handover, Total time.Duration }

// KeepaliveAdvice is the keepalive the upper layer should run on a
// confirmed path: both sides send every Interval and declare the path dead
// after Timeout without inbound traffic. Interval is within [5 s, 30 s] and
// Timeout = 3 × Interval.
type KeepaliveAdvice struct {
	Interval            time.Duration
	Timeout             time.Duration
	MappingLifetimeHint time.Duration // the estimated NAT mapping idle timeout; 0 without NAT evidence
	Reason              string        // no_nat | eim_known | restricted_or_edm | cgnat | portmapped | unknown
}

// Keepalive reasons.
const (
	keepNoNAT      = "no_nat"
	keepEIMKnown   = "eim_known"
	keepRestricted = "restricted_or_edm"
	keepCGNAT      = "cgnat"
	keepPortmapped = "portmapped"
	keepUnknown    = "unknown"
)

// keepaliveFor derives the advice from the winning path: the most conservative
// row that the evidence of either side matches. A LAN path crosses no NAT, nor
// does an overlay path on this side of the tunnel, which keeps its own links
// alive; a side without NAT is only behind a stateful firewall at worst, whose
// UDP state outlives the NAT rows; a port-mapping lease caps the interval at a
// third of the lease.
func keepaliveFor(fam protocol.Family, kind protocol.PathKind, self, peer protocol.Traits, pm *protocol.PortMappingInfo) KeepaliveAdvice {
	interval, hint, reason := 30*time.Second, time.Duration(0), keepNoNAT
	consider := func(iv, h time.Duration, r string) {
		if iv < interval {
			interval, hint, reason = iv, h, r
		}
	}
	switch {
	case kind == protocol.PathLAN || kind == protocol.PathOverlay:
	case self.Samples == 0 || peer.Samples == 0:
		interval, reason = 15*time.Second, keepUnknown
	default:
		for _, t := range [2]protocol.Traits{self, peer} {
			if t.NoNAT == protocol.TriTrue {
				if fam == protocol.FamilyUDP6 || t.Filtering != protocol.FiltEIF {
					consider(25*time.Second, 30*time.Second, keepNoNAT)
				}
				continue
			}
			known := t.Mapping == protocol.MapEIM && t.MappingConf >= protocol.ConfMedium &&
				t.FilteringConf >= protocol.ConfMedium && t.Filtering != protocol.FiltPDF && t.Filtering != protocol.FiltUnknown
			if known {
				consider(20*time.Second, 30*time.Second, keepEIMKnown)
			} else {
				consider(15*time.Second, 30*time.Second, keepRestricted)
			}
			if t.CGNAT == protocol.TriTrue || t.MultiExit || t.Drifted {
				consider(10*time.Second, 20*time.Second, keepCGNAT)
			}
		}
	}
	if pm != nil && pm.Lease > 0 {
		interval = min(interval, pm.Lease/3)
		hint, reason = pm.Lease, keepPortmapped
	}
	iv := min(max(interval, 5*time.Second), 30*time.Second)
	return KeepaliveAdvice{Interval: iv, Timeout: 3 * iv, MappingLifetimeHint: hint, Reason: reason}
}

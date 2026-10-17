package holepunch

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// Session is a successful hole punch: the caller owns the sockets of the
// confirmed paths — the primary path's and, with Options.MaxPaths above 1,
// those of the extra paths. When Punch
// returns it, the library has stopped reading and writing these sockets for
// good, cleared their deadlines and restored their TTL; it never touches
// them again. The methods are safe for concurrent use.
type Session struct {
	result   Result
	diag     Diagnostics
	conns    []net.PacketConn // every distinct socket of the paths, the primary path's first
	codec    *udpwire.Codec   // the session codec, every confirmed remote bound: recognises residual packets
	releases []func() error   // the handed-over sockets' port-mapping releases

	closeOnce sync.Once
	closeErr  error
}

// PacketConn returns the primary path's socket (Result.Path.Conn), exactly
// as Network.ListenPacket returned it: no wrapper, so optional capabilities
// such as *net.UDPConn's stay available. Close the Session rather than the
// conn directly, so that a port mapping on it is released too.
func (s *Session) PacketConn() net.PacketConn { return s.conns[0] }

// PacketConns returns every socket of the session's paths once, the primary
// path's first: what an upper layer reads from. Two paths of different kinds
// of network — a LAN and a public path — can run through one socket, which
// then appears once here and in both paths' Path.Conn; their datagrams differ
// by the remote address. Close the Session rather than these conns directly.
func (s *Session) PacketConns() []net.PacketConn { return slices.Clone(s.conns) }

// Result returns what the session achieved (a copy).
func (s *Session) Result() Result { return s.result.clone() }

// Diagnostics returns the session's diagnostics (a deep copy).
func (s *Session) Diagnostics() Diagnostics { return s.diag.clone() }

// FilterResidual wraps pc, one of the session's sockets, so that the late
// holepunch handshake packets still arriving after the handover — the
// peer's retransmissions — never reach the upper layer, which might take
// them for a new connection. An upper layer other than QUIC — KCP, a custom
// protocol — reads through it:
//
//	pc := sess.FilterResidual(sess.PacketConn())
//
// QUIC needs no wrapper: it drops these packets by their first byte.
//
// For 10 s after the call, a datagram from a confirmed remote that
// authenticates as a session packet is dropped and the next one read; every
// other datagram is returned unchanged, and an upper-layer packet is dropped
// only if it forges a GCM tag. Afterwards a read costs one atomic load more
// than pc's. The wrapper starts no goroutine and never touches deadlines;
// closing it closes pc. It returns nil for a nil pc.
func (s *Session) FilterResidual(pc net.PacketConn) FilteredConn {
	fc, _ := udpwire.DropResidual(pc, s.codec, udpwire.DefaultResidualWindow).(FilteredConn)
	return fc
}

// FilteredConn is a socket read through Session.FilterResidual.
type FilteredConn interface {
	net.PacketConn
	// Dropped returns how many residual handshake packets the filter has
	// dropped so far.
	Dropped() uint64
}

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
		for _, c := range s.conns {
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

// Result describes a successful session.
type Result struct {
	SessionID string
	Role      protocol.Role
	Path      Path // the primary path, on Session.PacketConn
	// ExtraPaths are the other confirmed paths: at most Options.MaxPaths-1,
	// empty with one path. The peer holds the same paths.
	ExtraPaths        []Path
	TransportMode     string        // the server's transport decision, equal on both sides
	PeerTransportData []byte        // the peer's Options.TransportData
	TransportTimeout  time.Duration // timeouts.transport_timeout_ms, for the upper layer
	Variant           string        // the winning round's RoundPlan.variant (always the server's)
	Rounds            int           // rounds run
	Timing            Timing
}

// Paths returns every confirmed path, the primary one first.
func (r Result) Paths() []Path { return append([]Path{r.Path}, r.ExtraPaths...) }

func (r Result) clone() Result {
	r.Path = r.Path.clone()
	r.ExtraPaths = slices.Clone(r.ExtraPaths)
	for i := range r.ExtraPaths {
		r.ExtraPaths[i] = r.ExtraPaths[i].clone()
	}
	r.PeerTransportData = slices.Clone(r.PeerTransportData)
	return r
}

func (p Path) clone() Path {
	if p.PortMapping != nil {
		pm := *p.PortMapping
		p.PortMapping = &pm
	}
	return p
}

// Path is one confirmed path of a session: its socket's address, the
// peer's address on it, the kind of network between the two
// and what the upper layer needs to keep it
// alive. A caller that must not run over a tunnel checks Kind, or excludes
// overlay paths up front (Options.ExcludeOverlay).
type Path struct {
	Conn        net.PacketConn // the path's socket, owned by the Session
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
// after Timeout without inbound traffic. Interval is within [5 s, 25 s] and
// Timeout = 3 × Interval.
type KeepaliveAdvice struct {
	Interval            time.Duration
	Timeout             time.Duration
	MappingLifetimeHint time.Duration   // the estimated NAT mapping idle timeout; 0 without NAT evidence
	Reason              KeepaliveReason // what set the interval
}

// KeepaliveReason is the evidence a KeepaliveAdvice rests on.
type KeepaliveReason string

// Keepalive reasons.
const (
	KeepaliveNoNAT      KeepaliveReason = "no_nat"            // no NAT on the path, at most a stateful firewall
	KeepaliveEIMKnown   KeepaliveReason = "eim_known"         // endpoint-independent NATs measured with confidence
	KeepaliveRestricted KeepaliveReason = "restricted_or_edm" // restricted filtering or endpoint-dependent mapping
	KeepaliveCGNAT      KeepaliveReason = "cgnat"             // carrier-grade NAT, several exits or a drifting mapping
	KeepalivePortmapped KeepaliveReason = "portmapped"        // a port-mapping lease caps the interval
	KeepaliveUnknown    KeepaliveReason = "unknown"           // too little evidence
)

// keepaliveFor derives the advice from the winning path: the most conservative
// row that the evidence of either side matches. A LAN path crosses no NAT, nor
// does an overlay path on this side of the tunnel, which keeps its own links
// alive; a side without NAT is only behind a stateful firewall at worst, whose
// UDP state outlives the NAT rows; a port-mapping lease caps the interval at a
// third of the lease.
func keepaliveFor(fam protocol.Family, kind protocol.PathKind, self, peer protocol.Traits, pm *protocol.PortMappingInfo) KeepaliveAdvice {
	interval, hint, reason := 25*time.Second, time.Duration(0), KeepaliveNoNAT
	consider := func(iv, h time.Duration, r KeepaliveReason) {
		if iv < interval {
			interval, hint, reason = iv, h, r
		}
	}
	switch {
	case kind == protocol.PathLAN || kind == protocol.PathOverlay:
	case self.Samples == 0 || peer.Samples == 0:
		interval, reason = 15*time.Second, KeepaliveUnknown
	default:
		for _, t := range [2]protocol.Traits{self, peer} {
			if t.NoNAT == protocol.TriTrue {
				if fam == protocol.FamilyUDP6 || t.Filtering != protocol.FiltEIF {
					consider(25*time.Second, 30*time.Second, KeepaliveNoNAT)
				}
				continue
			}
			known := t.Mapping == protocol.MapEIM && t.MappingConf >= protocol.ConfMedium &&
				t.FilteringConf >= protocol.ConfMedium && t.Filtering != protocol.FiltPDF && t.Filtering != protocol.FiltUnknown
			if known {
				consider(20*time.Second, 30*time.Second, KeepaliveEIMKnown)
			} else {
				consider(15*time.Second, 30*time.Second, KeepaliveRestricted)
			}
			if t.CGNAT == protocol.TriTrue || t.MultiExit || t.Drifted {
				consider(10*time.Second, 20*time.Second, KeepaliveCGNAT)
			}
		}
	}
	if pm != nil && pm.Lease > 0 {
		interval = min(interval, pm.Lease/3)
		hint, reason = pm.Lease, KeepalivePortmapped
	}
	iv := min(max(interval, 5*time.Second), 25*time.Second)
	return KeepaliveAdvice{Interval: iv, Timeout: 3 * iv, MappingLifetimeHint: hint, Reason: reason}
}

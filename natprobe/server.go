package natprobe

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

// panicLogInterval rate-limits the log line of recovered panics.
const panicLogInterval = time.Second

type serverState uint8

const (
	stateNew serverState = iota
	stateStarting
	stateStarted
	stateClosed
)

// Server is the natprobe observer: listeners, extra and alt pools, readers.
type Server struct {
	cfg ServerConfig
	reg *Registry
	src *sourceLimiter

	mu        sync.Mutex
	state     serverState
	g         *life.Group
	listeners []*listener
	readers   []*readerStats
	altPools  [2]*pool // by family index

	wildcard      atomic.Bool
	deadListeners atomic.Int64
	serverPanics  atomic.Uint64 // panics outside the readers: sandwich sinks run by AttachSandwichSink
	closeTimeouts atomic.Uint64
	lastPanicLog  atomic.Int64

	closeOnce sync.Once
	closeErr  error
}

// NewServer validates cfg and returns a server that is not bound yet.
func NewServer(cfg ServerConfig) (*Server, error) {
	cfg, err := normalize(cfg)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, reg: cfg.Registry, src: newSourceLimiter(cfg.SourceRate, cfg.SourceTableSize)}, nil
}

// Start binds every listener and every extra and alt pool socket
// synchronously, so that a port conflict is returned here, where a caller's
// start-up check needs it, starts the readers and returns. A configured group that
// cannot be bound is an error: there is no silent fallback. On failure
// everything opened is closed by the same path as Close, and the server stays
// closed.
func (s *Server) Start() (err error) {
	if s == nil {
		return errors.New("natprobe: nil server")
	}
	s.mu.Lock()
	switch s.state {
	case stateNew: // the only state Start proceeds from
	case stateStarting, stateStarted:
		s.mu.Unlock()
		return errors.New("natprobe: server already started")
	case stateClosed:
		s.mu.Unlock()
		return fmt.Errorf("natprobe: server closed: %w", net.ErrClosed)
	}
	s.state = stateStarting
	g := life.New(context.Background())
	s.g = g
	s.mu.Unlock()

	ls, alt, err := s.bind(g)
	if err != nil {
		_ = s.Close()
		return err
	}
	readers := make([]*readerStats, len(ls)*s.cfg.ReadersPerListener)
	for i := range readers {
		readers[i] = &readerStats{}
	}
	s.mu.Lock()
	if s.state != stateStarting {
		s.mu.Unlock()
		return fmt.Errorf("natprobe: server closed: %w", net.ErrClosed)
	}
	s.state, s.listeners, s.altPools, s.readers = stateStarted, ls, alt, readers
	s.mu.Unlock()

	for i, l := range ls {
		for k := range s.cfg.ReadersPerListener {
			st := readers[i*s.cfg.ReadersPerListener+k]
			g.Go(fmt.Sprintf("natprobe/read[%d/%s/%d]", l.id, l.fam, k), func(ctx context.Context) { s.readLoop(ctx, l, st) })
		}
	}
	if s.cfg.Listen == nil {
		s.checkWildcard()
	}
	return nil
}

// checkWildcard flags the wildcard groups that cannot reply from the probed
// address (no destination reports on this system) on a host with several
// global addresses of their family; the server still starts, since virtual
// interfaces (docker and the like) trigger the check too.
func (s *Server) checkWildcard() {
	var blind []ObserverGroup
	for _, l := range s.listeners {
		if g := s.cfg.Groups[l.group]; g.Bind.IsUnspecified() && l.msg == nil {
			blind = append(blind, g)
		}
	}
	if len(blind) == 0 {
		return
	}
	prefixes, err := interfacePrefixes()
	if err != nil {
		return
	}
	for _, fam := range wildcardFamilies(blind, prefixes) {
		s.wildcard.Store(true)
		s.log(slog.LevelWarn, "natprobe: wildcard_multi_ip: bind each IP explicitly", "family", string(fam))
	}
}

// Close closes every socket, which ends the readers, and joins them for at
// most 2 s; on timeout it returns ErrCloseTimeout and still returns. It is
// idempotent and safe for concurrent use: every call returns the result of
// the first, the first error from closing a socket other than
// net.ErrClosed. The Registry is not touched.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		g := s.g
		s.state = stateClosed
		s.mu.Unlock()
		if g == nil {
			return
		}
		err := g.Close(life.JoinTimeout)
		if g.Stats().Leaked > 0 {
			s.closeTimeouts.Add(1)
			err = errors.Join(ErrCloseTimeout, err)
		}
		s.closeErr = err
	})
	return s.closeErr
}

// Observers returns the observers of family f for punch_start.probe: one
// per address of Advertise and port of each live listener, ordered by id.
func (s *Server) Observers(f protocol.Family) []protocol.ObserverSpec { return s.observersAt(f, nil) }

// observersAt is Observers with the free address slots of the groups
// filled from at. An address is announced once per family: a group's
// Advertise first, then each address of at in the first group with a free
// slot. The same address in two observer groups would tell the classifier
// two server IPs where there is one.
func (s *Server) observersAt(f protocol.Family, at []netip.Addr) []protocol.ObserverSpec {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateStarted {
		return nil
	}
	slots := map[uint8][]netip.Addr{} // config group -> its slots' addresses
	var used []netip.Addr
	for gi, g := range s.cfg.Groups {
		if protocol.FamilyOf(g.Bind) == f {
			slots[uint8(gi)] = slices.Clone(g.Advertise)
			used = append(used, g.Advertise...)
		}
	}
	for _, a := range at {
		a = a.Unmap().WithZone("")
		if protocol.FamilyOf(a) != f || a.IsUnspecified() || a.IsMulticast() || slices.Contains(used, a) {
			continue
		}
		for gi, g := range s.cfg.Groups {
			if l := slots[uint8(gi)]; protocol.FamilyOf(g.Bind) == f && !g.Alt && len(l) < g.Slots {
				slots[uint8(gi)] = append(l, a)
				used = append(used, a)
				break
			}
		}
	}
	var out []protocol.ObserverSpec
	for _, l := range s.listeners {
		if l.fam != f || l.dead.Load() {
			continue
		}
		for k, a := range slots[l.group] {
			og := int(l.og) + k
			out = append(out, protocol.ObserverSpec{ID: uint8(og*portsPerGroup + int(l.pi)), Addr: netip.AddrPortFrom(a, l.port),
				Group: uint8(og), Alt: l.alt})
		}
	}
	slices.SortFunc(out, func(a, b protocol.ObserverSpec) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

// ProbeSpec returns the ProbeSpec that sends clients to this server, for
// coord.Config.DefaultProbe: the live observers of both families at the
// groups' Advertise addresses, extra replies unless the server was
// configured with NoExtraReply, and the second-socket probe, which tells the
// port allocation of a symmetric NAT apart. The caller adds third-party
// STUN servers, if any:
//
//	spec := probe.ProbeSpec()
//	spec.STUN, _ = natprobe.ResolveSTUN(ctx, nil, stun.DefaultServers())
//	co, err := coord.New(coord.Config{Registry: reg, DefaultProbe: spec})
//
// A ProbeSpec holds at most 16 observers in all, while a server may have 16
// of each family: a server with more keeps at least 8 of each family that
// has them and gives the rest to the other family, and within a family keeps
// its first main group's observers, then its alt observer, then its other
// groups'.
//
// Call it after Start; before Start, and after Close, the spec has no
// observers.
func (s *Server) ProbeSpec() protocol.ProbeSpec { return s.ProbeSpecAt() }

// ProbeSpecAt is ProbeSpec with the free address slots of the groups
// (ObserverGroup.Slots) announced at addrs, in order, each at its
// observer's ports: the addresses a session's clients reach this server at
// that are known only now — the current address of a host whose public
// address changes, the address a client says it connected to, a DDNS name's
// address. Each address goes to the first group of its family with a free
// slot; one of another family, one already announced, or one beyond the free
// slots is left out. When the spec outgrows its 16 observers the groups'
// first slots are kept first, so list the address that matters most first,
// in a group's Advertise or at the front of addrs. For a client's own
// session give the spec to coord.AttachOptions.Probe; for every session,
// return it from coord.Config.Probe.
func (s *Server) ProbeSpecAt(addrs ...netip.Addr) protocol.ProbeSpec {
	spec := protocol.ProbeSpec{V: protocol.ProbeSpecVersion, SecondSocket: true}
	if s == nil {
		return spec
	}
	spec.ExtraReply = !s.cfg.NoExtraReply
	spec.Observers = specObservers(s.observersAt(protocol.FamilyUDP4, addrs), s.observersAt(protocol.FamilyUDP6, addrs))
	return spec
}

// specObservers joins the two families' observers within protocol.MaxObservers
// (ProbeSpec).
func specObservers(v4, v6 []protocol.ObserverSpec) []protocol.ObserverSpec {
	n4 := min(len(v4), max(protocol.MaxObservers/2, protocol.MaxObservers-len(v6)))
	n6 := min(len(v6), protocol.MaxObservers-n4)
	return append(pickObservers(v4, n4), pickObservers(v6, n6)...)
}

// pickObservers keeps n of one family's observers, ordered by id: the first
// main group's, then the alt observer, then the other groups' in id order.
func pickObservers(obs []protocol.ObserverSpec, n int) []protocol.ObserverSpec {
	if len(obs) <= n {
		return slices.Clone(obs)
	}
	first := -1
	for _, o := range obs {
		if !o.Alt && (first < 0 || int(o.Group) < first) {
			first = int(o.Group)
		}
	}
	rank := func(o protocol.ObserverSpec) int {
		switch {
		case !o.Alt && int(o.Group) == first:
			return 0
		case o.Alt:
			return 1
		}
		return 2
	}
	kept := slices.Clone(obs)
	slices.SortStableFunc(kept, func(a, b protocol.ObserverSpec) int {
		return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(a.ID, b.ID))
	})
	kept = kept[:n]
	slices.SortFunc(kept, func(a, b protocol.ObserverSpec) int { return cmp.Compare(a.ID, b.ID) })
	return kept
}

// Stats returns a snapshot of the counters.
func (s *Server) Stats() ServerStats {
	if s == nil {
		return ServerStats{}
	}
	s.mu.Lock()
	readers := s.readers
	s.mu.Unlock()
	var st ServerStats
	for _, r := range readers {
		r.addTo(&st)
	}
	// Sink panics recovered on the coordinator's goroutine are counted once,
	// by the first Server of the Registry that reads its Stats.
	s.serverPanics.Add(s.reg.sinkPanics.Swap(0))
	st.Panics += s.serverPanics.Load()
	st.CloseTimeouts = s.closeTimeouts.Load()
	st.DeadListeners = int(s.deadListeners.Load())
	st.WildcardMultiIP = s.wildcard.Load()
	return st
}

// markDead stops a listener after a reader-loop panic: it leaves Observers,
// its socket is closed (its other readers end, and clients get ICMP rather
// than a black hole), and the rest of the server keeps running.
func (s *Server) markDead(l *listener) {
	if !l.dead.CompareAndSwap(false, true) {
		return
	}
	s.deadListeners.Add(1)
	_ = life.Safe("natprobe/close-listener", func() { _ = l.raw.Close() })
	s.log(slog.LevelError, "natprobe: listener stopped after a panic", "observer", int(l.id), "family", string(l.fam))
}

// logPanic logs a recovered panic at most once per second. The text of a
// PanicError carries no stack.
func (s *Server) logPanic(err error) {
	if s.cfg.Logger == nil {
		return
	}
	now := time.Now().UnixNano()
	last := s.lastPanicLog.Load()
	if now-last < int64(panicLogInterval) || !s.lastPanicLog.CompareAndSwap(last, now) {
		return
	}
	s.log(slog.LevelError, "natprobe: recovered panic", "err", err.Error())
}

// log calls the caller's Logger, whose handler is user code.
func (s *Server) log(level slog.Level, msg string, args ...any) {
	if s.cfg.Logger == nil {
		return
	}
	_ = life.Safe("natprobe/log", func() { s.cfg.Logger.Log(context.Background(), level, msg, args...) })
}

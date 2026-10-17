package holepunch

import (
	"context"
	"math"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/probe"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// Probing constants.
const (
	probeSlack        = 500 * time.Millisecond // probing ends at probe_timeout_ms + 0.5 s
	keepaliveInterval = 10 * time.Second       // mapping refresh while waiting for summary or go
	maxLocalAddrs     = 16
	maxOverlayAddrs   = 2 // FamilyReport.overlay
	maxSiblings       = 2
	implName          = "holepunch-go/1.0.0"
)

// famState is everything the session holds for one address family: its
// counters, its probing sockets and prober, and later its punching worker.
type famState struct {
	fam protocol.Family
	cnt famCounters

	// probing; written by the orchestrator before the prober starts, read-only
	// afterwards except second (set by openSecond on the prober goroutine)
	primary   *udpSock
	siblings  []*udpSock
	prober    atomic.Pointer[probe.Prober] // read by the read loops
	observers []protocol.ObserverSpec      // main-group observers of this family, by id
	mapping   *portMapping
	mu        sync.Mutex
	second    *udpSock
	result    probe.Result
	probed    bool // Run returned with at least one sample usable for the report
	bindErr   error

	worker *worker // set at the summary
}

func (f *famState) probeSockets() []*udpSock {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*udpSock
	if f.primary != nil {
		out = append(out, f.primary)
	}
	if f.second != nil {
		out = append(out, f.second)
	}
	return append(out, f.siblings...)
}

// sockHandle is a probing socket as the prober sees it: write-only, through
// the send gate's probe class.
type sockHandle struct {
	rt   *runtime
	sock *udpSock
}

func (h sockHandle) ID() uint8             { return h.sock.id }
func (h sockHandle) Local() netip.AddrPort { return h.sock.local }
func (h sockHandle) WriteTo(b []byte, to netip.AddrPort) error {
	return h.rt.sender.SendRaw(h.rt.g.Context(), h.sock, to, b)
}

// probePhase binds the probing sockets of every family the server observes,
// starts the port mappings, runs the probers in parallel within
// probe_timeout_ms + probeSlack and writes probe_report — or, when no family
// produced a usable result, punch_result{ok:false}.
func (rt *runtime) probePhase() error {
	ctx := rt.g.Context()
	var fams []*famState
	for _, f := range []protocol.Family{protocol.FamilyUDP4, protocol.FamilyUDP6} {
		obs := nat.Observers(f, rt.start.Probe.Observers)
		if len(obs) == 0 {
			continue
		}
		fs := rt.fam(f)
		for _, o := range rt.start.Probe.Observers {
			if f.Matches(o.Addr.Addr().Unmap()) && !o.Alt {
				fs.observers = append(fs.observers, o)
			}
		}
		slices.SortFunc(fs.observers, func(a, b protocol.ObserverSpec) int { return int(a.ID) - int(b.ID) })
		fams = append(fams, fs)
	}
	if len(fams) == 0 {
		return fail(protocol.ReasonNoProbeEndpoint, "no_observer", nil)
	}
	var bound []*famState
	for _, fs := range fams {
		if rt.bindProbeSockets(ctx, fs) {
			bound = append(bound, fs)
		}
	}
	if len(bound) == 0 {
		return fail(protocol.ReasonLocalPortBindFailed, "", fams[0].bindErr)
	}
	unprobed := rt.bindUnobserved(ctx)
	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	probeEnd := rt.clk.AfterFunc(time.Duration(rt.timeouts.ProbeTimeoutMs)*time.Millisecond+probeSlack, pcancel)
	defer probeEnd.Stop()
	var live atomic.Int32
	done := make(chan struct{})
	live.Store(int32(len(bound)))
	exited := func() {
		if live.Add(-1) == 0 {
			close(done)
		}
	}
	for _, fs := range bound {
		if len(rt.portMapMethods()) > 0 {
			fs.mapping = rt.startPortMap(fs.primary, rt.policy.PortMapping)
		}
		pr := rt.newProber(fs)
		fs.prober.Store(pr)
		if !rt.g.Go("probe:"+string(fs.fam), func(context.Context) {
			defer exited()
			res := pr.Run(pctx)
			fs.mu.Lock()
			fs.result = res
			fs.probed = res.Traits.Samples > 0
			fs.mu.Unlock()
		}) {
			exited()
		}
	}
	// The probers return at the latest when probeEnd cancels their ctx.
	// Meanwhile the control link is watched: a failure, an abort or a fault
	// ends the session now rather than after probing.
	var early error
	select {
	case <-done:
	case <-rt.ctl.conn.Done():
		early = rt.ctl.lost()
	case ab := <-rt.ctl.abortCh:
		early = abortFailure(ab.msg)
	case f := <-rt.ctl.faultCh:
		early = f
	case <-ctx.Done():
		early = context.Cause(ctx)
	}
	if early != nil {
		pcancel()
		<-done
		return early
	}
	return rt.writeReport(bound, unprobed)
}

// bindUnobserved binds a primary socket for each family the server has no
// observer for but this host has a global address in: the server may run
// that family with unverified, Direct-only targets, which needs this
// side's socket and its self-reported addresses.
func (rt *runtime) bindUnobserved(ctx context.Context) []*famState {
	var out []*famState
	for _, fs := range rt.fams {
		if fs.primary != nil || len(nat.Observers(fs.fam, rt.start.Probe.Observers)) > 0 {
			continue
		}
		a := globalAddr(fs.fam, rt.hosts)
		if !a.IsValid() {
			continue
		}
		s, err := rt.socks.open(ctx, fs.fam, netip.AddrPortFrom(a, 0), PurposeProbe, nat.IndexPrimary, primaryRecvBuffer)
		if err != nil {
			continue
		}
		fs.primary = s
		out = append(out, fs)
	}
	return out
}

// bindProbeSockets binds the primary socket of fs (on Options.LocalAddr or
// the preferred interface when they name this family) and up to two sibling
// sockets on the host's other LAN addresses of the family — never on an
// overlay address, whose route to the observers is the tunnel's.
func (rt *runtime) bindProbeSockets(ctx context.Context, fs *famState) bool {
	laddr := netip.AddrPortFrom(rt.preferredAddr(fs.fam), 0)
	s, err := rt.socks.open(ctx, fs.fam, laddr, PurposeProbe, nat.IndexPrimary, primaryRecvBuffer)
	if err != nil {
		fs.bindErr = err
		return false
	}
	fs.primary = s
	want := min(int(rt.start.Probe.Siblings), maxSiblings)
	idx := nat.IndexSibling
	for _, h := range rt.hosts {
		if len(fs.siblings) >= want {
			break
		}
		a := h.addr
		if !h.lanAddr() || !fs.fam.Matches(a) || netaddr.Unusable(a) || a.IsLinkLocalUnicast() || a == s.local.Addr() {
			continue
		}
		sib, err := rt.socks.open(ctx, fs.fam, netip.AddrPortFrom(a, 0), PurposeSibling, idx, primaryRecvBuffer)
		if err != nil {
			continue
		}
		fs.siblings = append(fs.siblings, sib)
		idx++
	}
	return true
}

// preferredAddr is the bind address of a family's primary socket.
func (rt *runtime) preferredAddr(f protocol.Family) netip.Addr {
	if a := rt.opts.LocalAddr; a.IsValid() && f.Matches(a.Unmap()) {
		return a.Unmap()
	}
	for _, a := range rt.ifacePrefer {
		if f.Matches(a) {
			return a
		}
	}
	return netip.Addr{}
}

// newProber builds the prober of fs, wiring the second-socket opener.
func (rt *runtime) newProber(fs *famState) *probe.Prober {
	sibs := make([]probe.SocketHandle, len(fs.siblings))
	for i, s := range fs.siblings {
		sibs[i] = sockHandle{rt, s}
	}
	openSecond := func() (probe.SocketHandle, error) {
		s, err := rt.socks.open(rt.g.Context(), fs.fam, netip.AddrPortFrom(fs.primary.local.Addr(), 0),
			PurposeProbe, nat.IndexSecond, primaryRecvBuffer)
		if err != nil {
			return nil, err
		}
		fs.mu.Lock()
		fs.second = s
		fs.mu.Unlock()
		return sockHandle{rt, s}, nil
	}
	spec := probe.Spec{
		Codec:   rt.codec,
		Probe:   rt.start.Probe,
		Family:  fs.fam,
		Timeout: time.Duration(rt.timeouts.ProbeTimeoutMs) * time.Millisecond,
		Clock:   rt.clk,
	}
	return probe.New(spec, sockHandle{rt, fs.primary}, sibs, openSecond)
}

// writeReport builds probe_report from the families that produced a result,
// or fails with the most informative family failure when none did.
func (rt *runtime) writeReport(bound, unprobed []*famState) error {
	var reports []protocol.FamilyReport
	var caps []protocol.FamilyCaps
	var clk protocol.ClockSample
	failures := map[protocol.Reason]famFailure{} // each family failure as it came first
	for _, fs := range bound {
		fs.mu.Lock()
		res, ok := fs.result, fs.probed
		fs.mu.Unlock()
		status := protocol.StatusOK
		if !ok {
			status = protocol.StatusFail
			r := res.Failure
			if r == "" {
				r = protocol.ReasonProbeTimeout
			}
			if _, seen := failures[r]; !seen {
				failures[r] = famFailure{detail: res.Detail, panic: res.Panic}
			}
		}
		rt.progress(progressEvent{stage: stageProbeDone, status: status, detail: string(res.Failure), family: fs.fam,
			counters: map[string]uint32{"sent": uint32(res.Sent.Primary + res.Sent.Second + res.Sent.Sibling), "icmp": res.Sent.ICMP}})
		if !ok {
			continue
		}
		fr := res.Table.Snapshot()
		fr.Failure = res.Failure
		fr.Traits = res.Traits
		fr.LocalAddrs = localAddrs(fs.fam, rt.hosts)
		fr.Overlay = rt.overlayAddrs(fs)
		if fs.mapping != nil {
			fr.PortMap = fs.mapping.takeReport()
		}
		reports = append(reports, fr)
		caps = append(caps, protocol.FamilyCaps{Family: fs.fam, LowTTL: rt.lowTTLCapable(fs)})
		if clk.RTTMs == 0 || (res.Clock.RTTMs > 0 && res.Clock.RTTMs < clk.RTTMs) {
			clk = res.Clock
		}
	}
	for _, fs := range unprobed {
		reports = append(reports, protocol.FamilyReport{
			Family: fs.fam, Failure: protocol.ReasonNoProbeEndpoint,
			Sockets:    []protocol.SocketReport{{ID: fs.primary.id, Kind: protocol.SocketPrimary, Local: fs.primary.local}},
			LocalAddrs: localAddrs(fs.fam, rt.hosts),
			Overlay:    rt.overlayAddrs(fs),
		})
		caps = append(caps, protocol.FamilyCaps{Family: fs.fam, LowTTL: rt.lowTTLCapable(fs)})
	}
	if len(reports) == 0 {
		// The detail goes along, and the panic: a prober that panicked
		// failed its family with internal, detail panic:<where>, and the
		// session's Error.Err is that *PanicError.
		r := probeFailure(failures)
		f := failures[r]
		var cause error
		if f.panic != nil {
			cause = f.panic
		}
		return fail(r, f.detail, cause)
	}
	rep := protocol.ProbeReport{
		SessionID: rt.start.SessionID,
		Role:      rt.role,
		Control:   protocol.ControlSpec{Version: rt.start.Control.Version, Features: rt.features},
		Caps: protocol.ClientCaps{Impl: implName, Families: caps, MaxSockets: rt.policy.Budget.MaxSockets,
			PortMap: rt.portMapMethods()},
		Families:  reports,
		Clock:     clk,
		Transport: protocol.Transport{Mode: rt.opts.TransportMode, Data: rt.opts.TransportData},
		Mode:      acceptedMode(rt.start.Mode, rt.opts.AcceptBackground),
	}
	startAt := rt.startAt
	if err := rt.ctl.sendBuilt(controlwire.TypeProbeReport, func(now time.Time) protocol.Message {
		r := rep
		r.ElapsedMs = elapsedMs(startAt, now)
		return r
	}); err != nil {
		return rt.ctl.sendFailure("probe_report", err)
	}
	rt.timing.probe = rt.clk.Now().Sub(rt.startAt)
	rt.phases.advance(protocol.PhaseReported, "probe_reported", rt.clk.Now())
	return nil
}

// famFailure is how a family's probing failed: the prober's detail and, when
// a panic inside it failed the family, the recovered panic.
type famFailure struct {
	detail string
	panic  *life.PanicError
}

// acceptedMode is the mode a client accepts: background only when
// the server offered it and the caller asked for it.
func acceptedMode(offer protocol.SessionMode, accept bool) protocol.SessionMode {
	if offer == protocol.ModeBackground && accept {
		return protocol.ModeBackground
	}
	return ""
}

// probeFailure picks the family failure reported when every family failed:
// the one closest to working, since it says the most about this network.
func probeFailure(seen map[protocol.Reason]famFailure) protocol.Reason {
	for _, r := range []protocol.Reason{protocol.ReasonProbeTimeout, protocol.ReasonUDPBlocked,
		protocol.ReasonLocalPortBindFailed, protocol.ReasonNoProbeEndpoint} {
		if _, ok := seen[r]; ok {
			return r
		}
	}
	for r := range seen {
		return r
	}
	return protocol.ReasonProbeTimeout
}

// lowTTLCapable reports whether the family can send low-TTL packets: the
// policy allows it and the primary socket can set its TTL.
func (rt *runtime) lowTTLCapable(fs *famState) bool {
	if rt.policy.LowTTL != nil && !*rt.policy.LowTTL {
		return false
	}
	return fs.primary.hop.ok
}

func (rt *runtime) portMapMethods() []protocol.PortMapMethod {
	if rt.mapper == nil {
		return nil
	}
	var out []protocol.PortMapMethod
	for _, m := range []protocol.PortMapMethod{protocol.PortMapPCP, protocol.PortMapNATPMP, protocol.PortMapUPnP} {
		if rt.policy.PortMapping.Enabled(m) {
			out = append(out, m)
		}
	}
	return out
}

// elapsedMs is a local monotonic duration in whole milliseconds, within
// the wire field's range.
func elapsedMs(from, to time.Time) uint32 {
	d := to.Sub(from)
	if d < 0 {
		return 0
	}
	return uint32(min(d/time.Millisecond, math.MaxUint32))
}

// sendKeepalive refreshes the probing sockets' mappings while the session
// waits for summary or go: one probe from each probing socket to the
// family's observer 0.
func (rt *runtime) sendKeepalive() {
	ctx := rt.g.Context()
	for _, fs := range rt.fams {
		if len(fs.observers) == 0 {
			continue
		}
		obs := fs.observers[0]
		for _, s := range fs.probeSockets() {
			h := udpwire.Header{Type: udpwire.TProbe, Cand: udpwire.NoCand, Aux: uint16(obs.ID)}
			_ = rt.sender.Send(ctx, s, netaddr.Canon(obs.Addr), &h, nil, sendOpt{class: classProbe, stage: txProbe})
		}
	}
}

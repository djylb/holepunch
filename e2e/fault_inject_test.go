//go:build holepunch_faultinject

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// injectCase is one injection point of the fault matrix's injection row: the
// point panics once, at its first hit anywhere in the process — in either client
// or in the server — during a session between two clients behind PRC NATs.
type injectCase struct {
	point string
	// want is the expected outcome.
	want injectOutcome
	// mapper gives the clients a port mapper, so that portmap.map is hit.
	mapper bool
	// progress gives the clients an OnProgress, so that progress.deliver is
	// hit.
	progress bool
	// late makes the responder join late, so that the coordinator's timer
	// fires while it waits.
	late time.Duration
	// onClose: the point lies on Coordinator.Close.
	onClose bool
}

// injectOutcome is what a panic at a point does to a session.
type injectOutcome int

const (
	// absorbed: the panic is recovered where it happens and the session
	// succeeds (callbacks only count, the memories and finish steps go on,
	// natprobe drops the packet).
	absorbed injectOutcome = iota
	// clientInternal: the client whose goroutine panicked ends with
	// internal, detail panic:<goroutine>, and hands over no socket; its peer
	// ends as the server tells it, or succeeds if it already confirmed.
	clientInternal
	// clientInternalOrAbsorbed: the probe goroutines may also absorb the
	// panic as a failed probe (only that family fails).
	clientInternalOrAbsorbed
	// serverInternal: the server's session ends with internal and both
	// clients fail with it.
	serverInternal
	// linkLost: a panic in a control stream's goroutine kills that stream;
	// the client sees internal or a lost link, its peer the server's notice.
	linkLost
	// initiatorInternal: a server panic while the responder has not joined
	// yet: the initiator fails with internal, the late responder finds the
	// session gone (its Attach is refused and it sees the link closed).
	initiatorInternal
	// noJoin: a panic in Attach leaves the client without a link: it sees
	// the link closed (control_interrupted), its peer peer_offline at
	// BindTimeout.
	noJoin
	// closeReported: a panic on Coordinator.Close is absorbed by the
	// shutdown, which still completes, and Close returns it as a
	// *life.PanicError.
	closeReported
)

func (o injectOutcome) String() string {
	return [...]string{"absorbed", "client_internal", "client_internal_or_absorbed", "server_internal", "link_lost", "initiator_internal", "no_join", "close_reported"}[o]
}

// errMapperUnavailable is the answer of the trivial port mapper.
var errMapperUnavailable = errors.New("e2e: no gateway")

// noGateway is a port mapper that finds no gateway.
type noGateway struct{}

func (noGateway) Map(context.Context, net.PacketConn, protocol.PortMappingPolicy) (protocol.PortMappingInfo, func() error, error) {
	return protocol.PortMappingInfo{}, nil, errMapperUnavailable
}

// injectCases are the injection points a session reaches (the
// portmapper's own points and natprobe.sweep need their packages' tests).
// Expectations: a client panic before the
// confirmation is internal (detail panic:<goroutine>); a callback-class
// point only counts; a server panic in a handler ends the session as
// internal; with the DefaultPlanner a planner panic has no fallback left and
// ends the session as internal too.
func injectCases() []injectCase {
	return []injectCase{
		{point: "attach.read_start", want: clientInternal},
		{point: "probe.bind", want: clientInternal},
		{point: "probe.send", want: clientInternalOrAbsorbed},
		{point: "probe.recv", want: clientInternalOrAbsorbed},
		{point: "portmap.map", want: clientInternal, mapper: true},
		{point: "wait.summary", want: clientInternal},
		{point: "wait.go", want: clientInternal},
		{point: "round.stage", want: clientInternal},
		{point: "readloop.packet", want: clientInternal},
		{point: "assist.handle", want: clientInternal},
		{point: "nomination.retry", want: clientInternal},
		{point: "handover.ack", want: clientInternal},
		{point: "finalize.disown", want: clientInternal},
		{point: "result.write", want: clientInternal},
		{point: "progress.deliver", want: absorbed, progress: true},
		{point: "ctl.read", want: linkLost},
		{point: "ctl.write", want: linkLost},
		{point: "coord.attach", want: noJoin},
		{point: "coord.handle.report", want: serverInternal},
		{point: "coord.handle.ready", want: serverInternal},
		{point: "coord.plan", want: serverInternal},
		{point: "coord.memory", want: absorbed},
		{point: "coord.timer", want: initiatorInternal, late: 500 * time.Millisecond},
		{point: "coord.callback", want: absorbed},
		{point: "coord.finish.notify", want: absorbed},
		{point: "coord.finish.conns", want: absorbed},
		{point: "coord.finish.registry", want: absorbed},
		{point: "coord.finish.quota", want: absorbed},
		{point: "coord.finish.index", want: absorbed},
		{point: "coord.finish.parent", want: absorbed},
		{point: "coord.finish.ctx", want: absorbed},
		{point: "coord.finish.memory", want: absorbed},
		{point: "coord.finish.traits", want: absorbed},
		{point: "coord.finish.stats", want: absorbed},
		{point: "natprobe.packet", want: absorbed},
		{point: "natprobe.extra", want: absorbed},
		{point: "coord.close", want: closeReported, onClose: true},
	}
}

// panicked reports whether a side failed with internal from a panic it
// recovered itself (detail panic:<goroutine>, not a notice from the server
// about its peer).
func panicked(o *sideResult) bool {
	return o.herr != nil && o.herr.Reason == protocol.ReasonInternal && o.herr.AbortedBy == "" && strings.HasPrefix(o.herr.Detail, "panic:")
}

// localInternal reports whether a side failed with internal of its own,
// whatever the detail.
func localInternal(o *sideResult) bool {
	return o.herr != nil && o.herr.Reason == protocol.ReasonInternal && o.herr.AbortedBy == ""
}

// checkOutcome checks a session against the expected outcome of a point.
func checkOutcome(want injectOutcome, r *run) error {
	out := [2]*sideResult{&r.out[0], &r.out[1]}
	n := 0
	for _, o := range out {
		if panicked(o) {
			n++
		}
	}
	ok := out[0].ok() && out[1].ok()
	switch want {
	case absorbed:
		if !ok {
			return fmt.Errorf("outcomes %q/%q, want both successful", out[0].reason(), out[1].reason())
		}
	case clientInternal, clientInternalOrAbsorbed:
		if want == clientInternalOrAbsorbed && ok {
			return nil
		}
		if n == 0 {
			for i, o := range out {
				if localInternal(o) {
					return fmt.Errorf("%s: internal with detail %q, want panic:<goroutine>", roles[i], o.herr.Detail)
				}
			}
			return fmt.Errorf("outcomes %q (%v) / %q (%v), want a client internal of its own with detail panic:<goroutine>",
				out[0].reason(), out[0].err, out[1].reason(), out[1].err)
		}
	case serverInternal:
		for i, o := range out {
			if o.reason() != protocol.ReasonInternal {
				return fmt.Errorf("%s: outcome %q (%v), want internal", roles[i], o.reason(), o.err)
			}
		}
	case linkLost:
		for _, o := range out {
			switch o.reason() {
			case protocol.ReasonInternal, protocol.ReasonControlInterrupted:
				return nil
			}
		}
		return fmt.Errorf("outcomes %q/%q, want a client with internal or control_interrupted", out[0].reason(), out[1].reason())
	case initiatorInternal:
		if out[0].reason() != protocol.ReasonInternal || out[1].reason() != protocol.ReasonControlInterrupted {
			return fmt.Errorf("outcomes %q/%q, want internal/control_interrupted", out[0].reason(), out[1].reason())
		}
	case noJoin:
		var got []protocol.Reason
		for _, o := range out {
			got = append(got, o.reason())
		}
		slices.Sort(got)
		if !slices.Equal(got, []protocol.Reason{protocol.ReasonControlInterrupted, protocol.ReasonPeerOffline}) {
			return fmt.Errorf("outcomes %q, want control_interrupted and peer_offline", got)
		}
	case closeReported: // the panic shows on Coordinator.Close, which runInject checks
	}
	return nil
}

// runInject runs one point and returns its violations.
func runInject(t *testing.T, ic injectCase, seed int64) (v []string) {
	faultinject.Reset()
	defer faultinject.Reset()
	disarm := faultinject.Arm(ic.point, faultinject.Panic(), 1)
	defer disarm()
	add := func(format string, args ...any) { v = append(v, fmt.Sprintf(format, args...)) }
	w := newWorld(t, worldConfig{seed: seed})
	var sides [2]*side
	for i := range sides {
		sides[i] = w.behind([]nattest.NATConfig{profPRC()})
		if ic.mapper {
			sides[i].pm = noGateway{}
		}
	}
	spec := sessionSpec{late: ic.late}
	if ic.progress {
		spec.onProgress = [2]func(protocol.Progress){func(protocol.Progress) {}, func(protocol.Progress) {}}
	}
	r, err := newRun(w, sides, spec)
	if err != nil {
		return w.abandon(err)
	}
	start := time.Now()
	r.execute()
	cr := &cellRun{c: &cell{name: "inject/" + ic.point, class: classMust}, seed: seed, w: w, sides: sides, r: r}
	cr.measure()
	if !ic.onClose {
		if faultinject.Hits(ic.point) == 0 {
			add("point %s not reached", ic.point)
		} else if f := faultinject.Fired(ic.point); f != 1 {
			add("point %s fired %d times, want 1", ic.point, f)
		} else if err := checkOutcome(ic.want, r); err != nil {
			add("%s: %v", ic.want, err)
		}
		if ic.progress && r.out[0].diag.Counters.CallbackPanics+r.out[1].diag.Counters.CallbackPanics == 0 {
			add("the progress panic was not counted")
		}
		if !r.done {
			add("the coordinator's session did not end")
		}
	}
	for i := range 2 {
		oi := &r.out[i]
		if d := oi.end.Sub(start); d > scaled(injectBound) {
			add("%s: returned after %v", roles[i], d)
		}
		if oi.inflight != 0 || (!oi.rdl.IsZero() || !oi.wdl.IsZero()) && !slices.Contains(oi.diag.Warn, warnControlUnreturnable) {
			add("%s: control conn not returned clean", roles[i])
		}
	}
	v = append(v, cr.checkResources()...)
	err = w.close()
	if ic.want == closeReported {
		var reported bool
		if err, reported = takeClosePanic(err, ic.point); !reported {
			add("Coordinator.Close did not return the panic at %s", ic.point)
		}
	}
	if err != nil {
		add("world close: %v", err)
	}
	if ic.onClose && faultinject.Fired(ic.point) != 1 {
		add("point %s fired %d times on Close, want 1", ic.point, faultinject.Fired(ic.point))
	}
	if len(v) > 0 {
		v = append(v, cr.dumpNote(t, v, "inject"))
	}
	return v
}

// takeClosePanic takes out of the world's close error the failure of a Close
// that returned exactly the *life.PanicError of point, and reports whether
// there was one; every other failure is returned, so that a Close that also
// timed out still fails the case.
func takeClosePanic(err error, point string) (rest error, found bool) {
	errs := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		errs = j.Unwrap()
	}
	var others []error
	for _, e := range errs {
		pe, ok := errors.Unwrap(e).(*life.PanicError)
		if !found && ok && pe.Where() == point {
			found = true
			continue
		}
		others = append(others, e)
	}
	return errors.Join(others...), found
}

// injectBound bounds a session with an injected panic: the e2e session cap
// of a failing session is well below it (about 43 s).
const injectBound = 45 * time.Second

// TestFaultInject is the injection-point row of the client fault matrix:
// every injection point that a session reaches panics once.
// The registry of injection points is process-wide, so the points run one
// after the other and no other test runs meanwhile.
func TestFaultInject(t *testing.T) {
	for _, ic := range injectCases() {
		name := "inject/" + ic.point
		if !suite().selected("fault/" + name) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			seed := cellSeed("fault/"+name, 0)
			for _, p := range runInject(t, ic, seed) {
				t.Errorf("seed %d: %s", seed, p)
			}
		})
	}
	goleak.VerifyNone(t)
}

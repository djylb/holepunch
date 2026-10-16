package holepunch

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/leak"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// solo is one client against a scripted server, for the phase and timeout
// tests: the script plays every server step by hand.
type solo struct {
	t      *testing.T
	w      *world
	host   *nattest.Host
	track  *leak.TrackingNetwork
	cli    *nattest.PipeConn
	srvEnd *nattest.PipeConn
	link   *srvLink
	s      *session
	res    <-chan attachResult
	cancel context.CancelFunc
	stop   context.CancelCauseFunc // cancel with a cause of the test's
	role   protocol.Role
}

func newSolo(t *testing.T, w *world, cfg *nattest.NATConfig, tweak func(o *Options)) *solo {
	t.Helper()
	return newSoloOn(t, w, w.host(cfg), tweak)
}

// newSoloOn is newSolo on a given host.
func newSoloOn(t *testing.T, w *world, host *nattest.Host, tweak func(o *Options)) *solo {
	t.Helper()
	so := &solo{t: t, w: w, host: host, role: protocol.RoleInitiator}
	so.track = leak.NewTrackingNetwork(so.host)
	so.cli, so.srvEnd = w.pipe(so.host, time.Millisecond)
	so.s = w.newSession()
	o := clientOpts(so.host)
	o.Network = so.track
	if tweak != nil {
		tweak(&o)
	}
	ctx, stop := context.WithCancelCause(context.Background())
	so.stop = stop
	so.cancel = func() { stop(nil) }
	t.Cleanup(so.cancel)
	so.res = runClient(ctx, so.cli, o)
	return so
}

// open wraps the server end in a controlwire.Conn.
func (so *solo) open() *srvLink {
	so.link = newSrvLink(so.t, so.srvEnd)
	so.t.Cleanup(so.link.close)
	return so.link
}

// start sends punch_start (and ping#1) with the given timeouts.
func (so *solo) start(to protocol.Timeouts) protocol.PunchStart { return so.startWith(to, nil) }

// startWith is start with the server's policy pol.
func (so *solo) startWith(to protocol.Timeouts, pol *protocol.Policy) protocol.PunchStart {
	ps := so.w.startFor(so.s, so.role, to, pol)
	so.open().send(ps)
	so.link.send(protocol.Ping{Seq: 1})
	return ps
}

// report waits for the client's probe_report and merges it.
func (so *solo) report() (protocol.ProbeReport, protocol.PeerView) {
	so.t.Helper()
	m, ok := so.link.next(10*time.Second, protocol.MsgProbeReport)
	if !ok {
		so.t.Fatal("no probe_report")
	}
	rep := *m.(*protocol.ProbeReport)
	v, _, err := so.s.h.Merge(so.role, rep, nil, natprobeKey())
	if err != nil {
		so.t.Fatal(err)
	}
	return rep, v
}

// fakePeer is a peer view whose endpoint is the given address, verified.
func fakePeer(addr string) protocol.PeerView {
	ap := netip.MustParseAddrPort(addr)
	return protocol.PeerView{Families: []protocol.FamilyView{{Family: protocol.FamilyUDP4,
		Traits:    protocol.Traits{Mapping: protocol.MapEIM, MappingConf: protocol.ConfHigh, Filtering: protocol.FiltPDF, FilteringConf: protocol.ConfMedium, Samples: 3, Observed: ap, PublicIP: ap.Addr()},
		Endpoints: []protocol.Endpoint{{Addr: ap, Source: protocol.EndpointServer, Verified: true}}}}}
}

// summary sends probe_summary with a direct first round towards peer.
func (so *solo) summary(self, peer protocol.PeerView, to protocol.Timeouts) protocol.RoundPlan {
	r1 := directPlan(1, so.role, roleViews(so.role, self, peer))
	so.link.send(protocol.ProbeSummary{
		SessionID: so.s.sid, Self: self, Peer: peer,
		Pair:      protocol.PairFacts{SharedFamilies: []protocol.Family{protocol.FamilyUDP4}},
		Transport: protocol.TransportPick{Mode: "quic"}, Timeouts: to,
		Plan: protocol.PlanSpec{ID: "p", PairClass: "test", RoundsMax: 3, Budget: protocol.DefaultBudget(), Round1: r1},
	})
	return r1
}

func roleViews(r protocol.Role, self, peer protocol.PeerView) [2]protocol.PeerView {
	if r == protocol.RoleInitiator {
		return [2]protocol.PeerView{self, peer}
	}
	return [2]protocol.PeerView{peer, self}
}

// result waits for AttachSession.
func (so *solo) result(d time.Duration) attachResult {
	so.t.Helper()
	select {
	case r := <-so.res:
		return r
	case <-time.After(d):
		so.t.Fatal("AttachSession did not return")
	}
	return attachResult{}
}

// wantFailure checks the error's reason and the socket accounting.
func (so *solo) wantFailure(r attachResult, reason protocol.Reason) {
	so.t.Helper()
	var e *Error
	if !errors.As(r.err, &e) {
		so.t.Fatalf("want *Error %s, got %v", reason, r.err)
	}
	if e.Reason != reason {
		so.t.Fatalf("reason %s (%s, phase %s), want %s", e.Reason, e.Detail, e.Phase, reason)
	}
	if err := so.track.CheckOpen(0); err != nil {
		so.t.Fatal(err)
	}
}

// wantError is wantFailure returning the *Error.
func (so *solo) wantError(r attachResult, reason protocol.Reason) *Error {
	so.t.Helper()
	so.wantFailure(r, reason)
	var e *Error
	_ = errors.As(r.err, &e) // wantFailure checked that it matches
	return e
}

// checkControlReturned asserts that after AttachSession the control
// connection reads with no deadline, and the library no longer reads it.
func (so *solo) checkControlReturned() {
	so.t.Helper()
	if so.link != nil {
		_ = so.link.conn.Release()
	}
	got := make(chan error, 1)
	go func() {
		b := make([]byte, 1)
		_, err := so.cli.Read(b)
		got <- err
	}()
	_, _ = so.srvEnd.Write([]byte{0x42})
	select {
	case err := <-got:
		if err != nil {
			so.t.Fatalf("control read after return: %v", err)
		}
	case <-time.After(2 * time.Second):
		so.t.Fatal("control conn not readable after return")
	}
}

// punchResult waits for the client's punch_result.
func (so *solo) punchResult() *protocol.PunchResult {
	so.t.Helper()
	m, ok := so.link.next(10*time.Second, protocol.MsgPunchResult)
	if !ok {
		so.t.Fatal("no punch_result")
	}
	return m.(*protocol.PunchResult)
}

func natprobeKey() natprobe.TraitsKey { return natprobe.TraitsKey{} }

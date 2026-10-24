package coord

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/ablation"
	engine "github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

func ablated(s ablation.Set) SessionOptions {
	return SessionOptions{Parent: ablation.With(context.Background(), s)}
}

// readyGated is a session whose round 1 waits for both readies
// (NoEagerGo), for the tests of that wait.
func readyGated() SessionOptions { return ablated(ablation.Set{NoEagerGo: true}) }

// TestAblationSwitches: each ablation switch turns its mechanism off.
func TestAblationSwitches(t *testing.T) {
	t.Run("NoRTTAlign", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(ablated(ablation.Set{NoRTTAlign: true}))
		for _, g := range p.punching() {
			if g.DelayMs != 0 {
				t.Fatalf("delay %d", g.DelayMs)
			}
		}
		p.s.Abort(protocol.ReasonCanceled, "")
		r.wait(p.s)
	})
	t.Run("NoAssistRelay", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(ablated(ablation.Set{NoAssistRelay: true}))
		p.punching()
		send(t, p.cl[0], peerSeen(p, 0, 1, pubR))
		p.waitCounters(func(c Counters) bool { return c.AssistDropped == 1 })
		p.s.Abort(protocol.ReasonCanceled, "")
		if res := r.wait(p.s); res.Counters.AssistForwarded != 0 {
			t.Fatalf("forwarded %d", res.Counters.AssistForwarded)
		}
	})
	t.Run("NoSandwich", func(t *testing.T) {
		r := newRig(t, withRegistry(natprobe.NewRegistry(natprobe.RegistryConfig{})))
		s := r.session(ablated(ablation.Set{NoSandwich: true}))
		if len(s.PunchStart(protocol.RoleInitiator).Control.Features) != 0 {
			t.Fatal("sandwich offered")
		}
		s.Abort(protocol.ReasonCanceled, "")
		r.wait(s)
	})
	t.Run("NoRounds", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(ablated(ablation.Set{NoRounds: true}))
		if p.starts[0].Timeouts.MaxRounds != 1 {
			t.Fatalf("max_rounds %d", p.starts[0].Timeouts.MaxRounds)
		}
		gos := p.punching()
		if !gos[0].Final {
			t.Fatal("the only round is not final")
		}
		heard := simclient.Outcome{Family: protocol.FamilyUDP4, Sent: 3, SeenFrom: []netip.AddrPort{pubR}}
		p.endRound(1, [2]simclient.Outcome{heard, fired(3)})
		if res := r.wait(p.s); len(res.Rounds) != 1 || res.Reason != protocol.ReasonOneWayUDPOnly {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("NoMemory", func(t *testing.T) {
		m, _ := newMem(t, StrategyMemoryConfig{})
		r := newRig(t, func(c *Config) { c.Memory = m })
		p := r.pair(ablated(ablation.Set{NoMemory: true}))
		p.summaries()
		p.s.Abort(protocol.ReasonCanceled, "")
		r.wait(p.s)
		if m.len() != 0 {
			t.Fatal("memory used")
		}
	})
	t.Run("NoEarlyAbort", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(ablated(ablation.Set{NoEarlyAbort: true}))
		send(t, p.cl[1], simclient.Failure(p.s.ID(), protocol.RoleResponder, protocol.ReasonProbeTimeout, protocol.PhaseProbing))
		p.report(0)
		testkit.WaitFor(t, "report", func() bool { return p.s.Snapshot().Reported[0] })
		if p.s.Snapshot().State == StateClosed {
			t.Fatal("ended early")
		}
		r.clk.Advance(5 * time.Second)
		if res := r.wait(p.s); res.Reason != protocol.ReasonProbeTimeout || res.FailedRole != protocol.RoleResponder {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("NoEarlyAbort reject", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(ablated(ablation.Set{NoEarlyAbort: true}))
		p.report(0)
		send(t, p.cl[1], simclient.Report(*p.starts[1], 1, "kcp", fam(1, simclient.OpenTraits)))
		testkit.WaitFor(t, "planned", func() bool {
			p.s.mu.Lock()
			defer p.s.mu.Unlock()
			return p.s.st.deferred != nil
		})
		r.clk.Advance(5 * time.Second)
		if res := r.wait(p.s); res.Reason != protocol.ReasonTransportMismatch {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("NoEarlyAbort stop", func(t *testing.T) {
		// A planner's stop after round 1 waits for the punching deadline
		// as well, and no round follows it.
		r := newRig(t, func(c *Config) { c.Planner = stopAfterFirst{} })
		p := r.pair(ablated(ablation.Set{NoEarlyAbort: true}))
		p.punching()
		for i := range 2 {
			p.windowEnd(i, 1, fired(5))
		}
		testkit.WaitFor(t, "deferred", func() bool {
			p.s.mu.Lock()
			defer p.s.mu.Unlock()
			return p.s.st.deferred != nil
		})
		// Had a round followed, its go would have come with round 1's end.
		for i := range 2 {
			if m, _, err := p.cl[i].Next(ctxShort(t)); err == nil {
				t.Fatalf("a round followed the stop: %T", m)
			}
		}
		if p.s.Snapshot().State == StateClosed {
			t.Fatal("ended early")
		}
		r.clk.Advance(time.Minute)
		if res := r.wait(p.s); res.Reason != protocol.ReasonCandidateTimeout {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("NoRoleAssign", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(ablated(ablation.Set{NoRoleAssign: true}))
		for _, sum := range p.summaries() {
			for _, s := range sum.Plan.Round1.Sides {
				if s.Role != protocol.SideBoth && s.Role != protocol.SideReplyOnly || s.SendDelayMs != 0 {
					t.Fatalf("side %+v", s)
				}
				for _, st := range s.Stages {
					if st.TTL != 0 {
						t.Fatalf("low TTL %+v", st)
					}
				}
			}
		}
		p.s.Abort(protocol.ReasonCanceled, "")
		r.wait(p.s)
	})
	t.Run("SinglePortProbe", func(t *testing.T) {
		spec := protocol.ProbeSpec{ExtraReply: true, SecondSocket: true, Siblings: 2,
			STUN: []netip.AddrPort{mustAP("192.0.2.1:3478")},
			Observers: []protocol.ObserverSpec{
				{ID: 0, Addr: mustAP("192.0.2.9:3000")}, {ID: 1, Addr: mustAP("192.0.2.9:3001")},
				{ID: 8, Addr: mustAP("192.0.2.10:3000"), Group: 1, Alt: true}, {ID: 16, Addr: mustAP("[2001:db8::9]:3000"), Group: 2},
			}}
		r := newRig(t, func(c *Config) { c.DefaultProbe = spec })
		s := r.session(ablated(ablation.Set{SinglePortProbe: true}))
		got := s.PunchStart(protocol.RoleInitiator).Probe
		if len(got.Observers) != 2 || got.ExtraReply || got.SecondSocket || got.Siblings != 0 || got.STUN != nil {
			t.Fatalf("probe spec %+v", got)
		}
		s.Abort(protocol.ReasonCanceled, "")
		r.wait(s)
	})
}

// TestProbeSpecSources: the options' spec wins over Config.Probe, which wins
// over Config.DefaultProbe; a failing Probe fails NewSession.
func TestProbeSpecSources(t *testing.T) {
	def := protocol.ProbeSpec{Observers: []protocol.ObserverSpec{{ID: 0, Addr: mustAP("192.0.2.9:3000")}}}
	calls := 0
	r := newRig(t, func(c *Config) {
		c.DefaultProbe = def
		c.Probe = func(role protocol.Role, opts *SessionOptions) (protocol.ProbeSpec, error) {
			calls++
			switch opts.Labels["probe"] {
			case "fail":
				return protocol.ProbeSpec{}, context.Canceled
			case "panic":
				panic("probe")
			}
			return protocol.ProbeSpec{V: protocol.ProbeSpecVersion, Siblings: 1}, nil
		}
	})
	over := protocol.ProbeSpec{Siblings: 2}
	s := r.session(SessionOptions{ResponderProbe: &over, InitiatorProbe: &over})
	if s.PunchStart(protocol.RoleResponder).Probe.Siblings != 2 || s.PunchStart(protocol.RoleInitiator).Probe.V != protocol.ProbeSpecVersion {
		t.Fatal("options' spec ignored")
	}
	s2 := r.session(SessionOptions{})
	if s2.PunchStart(protocol.RoleInitiator).Probe.Siblings != 1 || calls != 2 {
		t.Fatalf("Config.Probe not used (%d calls)", calls)
	}
	for _, mode := range []string{"fail", "panic"} {
		if _, err := r.c.NewSession(SessionOptions{Labels: map[string]string{"probe": mode}}); err == nil {
			t.Fatalf("%s: NewSession succeeded", mode)
		}
	}
	bad := protocol.ProbeSpec{V: 9}
	if _, err := r.c.NewSession(SessionOptions{InitiatorProbe: &bad}); err == nil {
		t.Fatal("invalid probe spec accepted")
	}
}

// TestTTLResolve: TTL defaults, ranges and the negative "no wait" values.
func TestTTLResolve(t *testing.T) {
	to := protocol.DefaultTimeouts()
	got := TTLConfig{}.resolve(to)
	if got.bind != defBindTimeout || got.reportSlack != defReportSlack || got.ready != 5*time.Second ||
		got.punchSlack != defPunchSlack || got.linger != 3*time.Second || got.grace != defResultGrace {
		t.Fatalf("defaults %+v", got)
	}
	got = TTLConfig{BindTimeout: time.Second, ReportSlack: time.Hour, ReadyTimeout: time.Millisecond,
		PunchSlack: time.Hour, ConfirmLinger: time.Hour, ResultGrace: time.Hour}.resolve(to)
	if got.bind != minBindTimeout || got.reportSlack != maxReportSlack || got.ready != minReady ||
		got.punchSlack != maxPunchSlack || got.linger != maxLinger || got.grace != maxResultGrace {
		t.Fatalf("clamped %+v", got)
	}
	got = TTLConfig{ConfirmLinger: -1, ResultGrace: -1}.resolve(to)
	if got.linger >= 0 || got.grace >= 0 {
		t.Fatalf("negative %+v", got)
	}
	if l := (Limits{ObserverQueue: -5, FramesPerLink: -1, WriteTimeout: -1}).withDefaults(); l.ObserverQueue != defObserverQueue ||
		l.FramesPerLink != defFramesPerLink || l.WriteTimeout != defWriteTimeout {
		t.Fatalf("limits %+v", l)
	}
}

// stopAfterFirst plans like the default planner and stops after round 1.
type stopAfterFirst struct{ engine.DefaultPlanner }

func (p stopAfterFirst) Round(in plan.RoundInput) plan.RoundDecision {
	if in.Round > 1 {
		return plan.RoundDecision{Stop: protocol.ReasonCandidateTimeout}
	}
	return p.DefaultPlanner.Round(in)
}

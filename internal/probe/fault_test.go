//go:build holepunch_faultinject

package probe

import (
	"context"
	"testing"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/protocol"
)

// A panic inside the prober fails its family with internal and
// detail panic:probe/<family>, the panic in Result.Panic; the
// process does not crash.
func TestPanicInjectedOnReceive(t *testing.T) {
	defer faultinject.Reset()
	disarm := faultinject.Arm(pointRecv, faultinject.Panic(), 1)
	defer disarm()
	s := newSim(t, defaultOpts())
	r := s.loopRun(context.Background())
	if r.Failure != protocol.ReasonInternal || r.Detail != "panic:probe/udp4" || r.Table == nil || r.Traits.Family != protocol.FamilyUDP4 ||
		r.Panic == nil || r.Panic.Where() != "probe/udp4" {
		t.Fatalf("result %+v", r)
	}
	if faultinject.Fired(pointRecv) != 1 {
		t.Fatal("the injection did not fire")
	}
	if s.fake.Pending() != 0 {
		t.Fatalf("%d timers left behind", s.fake.Pending())
	}
}

// An injected send error is a failed send like any write error.
func TestSendErrorInjected(t *testing.T) {
	defer faultinject.Reset()
	disarm := faultinject.Arm(pointSend, faultinject.Error(nil), 0)
	defer disarm()
	s := newSim(t, defaultOpts())
	r := s.stepRun()
	if r.Failure != protocol.ReasonUDPBlocked || r.Detail != "send_failed" {
		t.Fatalf("result %+v", r)
	}
}

// An injected receive error rejects the packet.
func TestReceiveErrorInjected(t *testing.T) {
	defer faultinject.Reset()
	disarm := faultinject.Arm(pointRecv, faultinject.Error(nil), 0)
	defer disarm()
	s := newSim(t, defaultOpts())
	s.spec.Timeout = minTimeout
	s.p = New(s.spec, s.socks[0], nil, nil)
	r := s.stepRun()
	if r.Failure != protocol.ReasonProbeTimeout || r.Sent.Rejected == 0 {
		t.Fatalf("result %+v", r)
	}
}

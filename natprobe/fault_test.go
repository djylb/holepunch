//go:build holepunch_faultinject

package natprobe

import (
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/udpwire"
)

// A panic injected while handling packet k is contained: counted
// once, the packet is dropped, the reader goes on.
func TestPacketPanicInjected(t *testing.T) {
	defer faultinject.Reset()
	reg := NewRegistry(RegistryConfig{})
	s := startServer(t, ServerConfig{Registry: reg, ReadersPerListener: 1})
	register(t, reg, "s1", tok(1), rt(1))
	c := newUDPClient(t, tok(1), rt(1))
	disarm := faultinject.Arm(pointPacket, faultinject.Panic(), 1)
	defer disarm()
	to := observerAddr(t, s, 0)
	c.send(to, probeOpts{obs: 0})
	if reps := c.recv(1, 200*time.Millisecond); len(reps) != 0 {
		t.Fatal("the panicking packet was answered")
	}
	c.send(to, probeOpts{obs: 0})
	if reps := c.await(1); len(reps) != 1 {
		t.Fatal("the reader stopped after a packet panic")
	}
	if st := s.Stats(); st.Panics != 1 || st.DeadListeners != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// An injected failure at the extra send point leaves the ack alone.
func TestExtraPointInjected(t *testing.T) {
	defer faultinject.Reset()
	r := newRig(t, rigOpts{})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	disarm := faultinject.Arm(pointExtra, faultinject.Error(nil), 0)
	defer disarm()
	if out := r.deliver(0, c.probe(probeOpts{extra: true}), srcA); len(out) != 1 {
		t.Fatalf("%d replies", len(out))
	}
}

// An injected error at the packet point drops the packet.
func TestPacketErrorInjected(t *testing.T) {
	defer faultinject.Reset()
	r := newRig(t, rigOpts{})
	register(t, r.reg, "s1", tok(1), rt(1))
	c := newClient(t, tok(1), rt(1), udpwire.RoleInitiator)
	disarm := faultinject.Arm(pointPacket, faultinject.Error(nil), 1)
	defer disarm()
	if out := r.deliver(0, c.probe(probeOpts{}), srcA); len(out) != 0 || r.stats.packetsIn.Load() != 1 {
		t.Fatalf("%d replies", len(out))
	}
	if out := r.deliver(0, c.probe(probeOpts{}), srcA); len(out) != 1 {
		t.Fatalf("%d replies after the fault", len(out))
	}
}

// A panic in the sweeper is contained and the sweeper keeps running; an
// injected error skips one sweep.
func TestSweepFaultsInjected(t *testing.T) {
	defer faultinject.Reset()
	disarm := faultinject.Arm(pointSweep, faultinject.Panic(), 1)
	defer disarm()
	reg := NewRegistry(RegistryConfig{})
	s := startServer(t, ServerConfig{Registry: reg, SweepInterval: 5 * time.Millisecond})
	if _, err := reg.Register(Registration{SessionID: "s", Route: rt(1), Token: tok(1), TTL: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(waitBound(t))
	for (reg.Len() != 0 || s.Stats().Panics != 1) && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if reg.Len() != 0 || s.Stats().Panics != 1 {
		t.Fatalf("len %d stats %+v", reg.Len(), s.Stats())
	}
	disarm2 := faultinject.Arm(pointSweep, faultinject.Error(nil), 1)
	defer disarm2()
	if _, err := reg.Register(Registration{SessionID: "s2", Route: rt(2), Token: tok(1), TTL: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(waitBound(t))
	for reg.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if reg.Len() != 0 || faultinject.Fired(pointSweep) < 2 {
		t.Fatalf("len %d fired %d", reg.Len(), faultinject.Fired(pointSweep))
	}
}

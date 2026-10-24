package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/internal/testkit"
	"github.com/djylb/holepunch/standalone/internal/testworld"
)

func TestMain(m *testing.M) { goroutines.VerifyTestMain(m) }

// TestProbeEcho runs both sides of the diagnostic over a punched session.
func TestProbeEcho(t *testing.T) {
	w := testworld.New(t, testworld.Options{})
	hostC := w.Client(w.NATHost(nattest.PortRestricted()), nil)
	ctx, cancel := context.WithCancel(context.Background())
	handling := make(chan struct{}, 1)
	echoed := make(chan int, 1)
	served := make(chan error, 1)
	go func() {
		served <- hostC.Serve(ctx, client.Registration{HostID: "echo", TransportMode: mode}, func(ctx context.Context, s *client.Session) {
			handling <- struct{}{}
			echoed <- echo(ctx, s)
		})
	}()
	defer func() {
		cancel()
		<-served
	}()
	testkit.WaitFor(t, "the echo host to register", func() bool { return len(w.Broker.Snapshot().Hosts) != 0 })
	dialC := w.Client(w.NATHost(nattest.SymmetricSeq(1)), nil)
	s, err := dialC.Open(context.Background(), client.OpenRequest{HostID: "echo", TransportMode: mode})
	if err != nil {
		t.Fatal(err)
	}
	// Until the host has handed over too (mostly before us, later on a slow
	// runner), its session reads the punched socket and takes a ping as
	// handover evidence instead of passing it on: wait for the handler,
	// which runs after the handover.
	select {
	case <-handling:
	case <-time.After(5 * time.Second):
		t.Fatal("echo handler not started")
	}
	var out bytes.Buffer
	report(&out, s)
	if err := ping(context.Background(), &out, s, 3, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	text := out.String()
	for _, want := range []string{"session " + s.ID(), "path", "self  udp4", "peer  udp4", "keepalive", "seq=2 rtt=", "3 sent, 0 lost"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output lacks %q:\n%s", want, text)
		}
	}
	cancel()
	if n := <-echoed; n < 3 {
		t.Fatalf("echoed %d", n)
	}
}

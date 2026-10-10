package protocol

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/djylb/holepunch/controlwire"
)

// answerPings is a client's controlwire.ConnOptions.Intercept: ping is
// answered from the reading goroutine with a P0 pong built at write time, so
// hold_us covers the queue wait.
func answerPings(c *controlwire.Conn, f controlwire.Frame) bool {
	if MessageType(f.Type) != MsgPing {
		return false
	}
	ping, err := Unmarshal[Ping](f)
	if err != nil {
		return false // delivered; the dispatcher fails the session with protocol_violation
	}
	_ = c.SendFunc(controlwire.TypePong, func(now time.Time) ([]byte, error) {
		fr, err := Marshal(PongFor(ping, f.At, now))
		return fr.Payload, err
	})
	return true
}

// TestControlLinkEndToEnd wires protocol and controlwire the way the client
// and the coordinator do: punch_start + ping#1 from the server, an immediate
// pong, probe_report back, origin checks, then Release on the client and
// Close on the server.
func TestControlLinkEndToEnd(t *testing.T) {
	cs, ss := net.Pipe()
	defer func() { _ = cs.Close() }()
	client, err := controlwire.NewConn(cs, controlwire.ConnOptions{Side: controlwire.SideClient, Intercept: answerPings})
	if err != nil {
		t.Fatal(err)
	}
	server, err := controlwire.NewConn(ss, controlwire.ConnOptions{Side: controlwire.SideServer, WriteTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := sampleMessages()[0].(PunchStart)
	for _, m := range []Message{start, Ping{Seq: 1}} {
		f, err := Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := server.Send(f); err != nil {
			t.Fatal(err)
		}
	}
	f, err := client.ReadFrame(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal[PunchStart](f)
	if err != nil || got.SessionID != start.SessionID || got.Token != start.Token || got.Wire.RouteID != start.Wire.RouteID {
		t.Fatalf("client got %v, %v", got, err)
	}
	f, err = server.ReadFrame(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pong, err := Unmarshal[Pong](f)
	if err != nil || pong.Seq != 1 || pong.HoldUs > uint32(time.Second.Microseconds()) || pong.ClientUnixMs == 0 {
		t.Fatalf("server got pong %+v, %v", pong, err)
	}

	report := sampleMessages()[3].(ProbeReport)
	report.Control.Features = AcceptFeatures(start.Control.Features, SupportedFeatures())
	rf, err := Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteFrame(ctx, rf); err != nil {
		t.Fatal(err)
	}
	f, err = server.ReadFrame(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckOrigin(m, start.SessionID, start.Role); err != nil {
		t.Fatalf("CheckOrigin: %v", err)
	}
	if err := CheckOrigin(m, start.SessionID, start.Role.Peer()); !isViolation(err) {
		t.Fatalf("CheckOrigin on the wrong link: %v", err)
	}

	// A client never sends S→C types (no punch_abort from clients).
	af, _ := Marshal(Abort{SessionID: start.SessionID, By: RoleServer, Code: ReasonInternal})
	if err := client.Send(af); !errors.Is(err, controlwire.ErrWrongDirection) {
		t.Fatalf("client sending punch_abort: %v", err)
	}

	if err := client.Release(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := WireReason(client.Err()); ok {
		t.Fatalf("a clean Release maps to a wire reason: %v", client.Err())
	}
}

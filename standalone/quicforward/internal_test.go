package quicforward

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/internal/testkit"
	"github.com/djylb/holepunch/standalone/internal/testworld"
	"github.com/djylb/holepunch/standalone/proto"
)

func TestStreamFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, streamRequest{Target: "a.test:1"}); err != nil {
		t.Fatal(err)
	}
	var req streamRequest
	if err := readFrame(&buf, &req); err != nil || req.Target != "a.test:1" {
		t.Fatalf("%+v %v", req, err)
	}
	if err := writeFrame(&buf, streamRequest{Target: strings.Repeat("x", maxStreamFrame)}); err == nil {
		t.Fatal("oversized frame written")
	}
	if err := readFrame(bytes.NewReader([]byte{0xff, 0xff}), &req); err == nil {
		t.Fatal("oversized frame read")
	}
	if err := readFrame(bytes.NewReader([]byte{0, 5, '{'}), &req); err == nil {
		t.Fatal("truncated frame read")
	}
	if err := readFrame(bytes.NewReader(nil), &req); err == nil {
		t.Fatal("empty stream read")
	}
	if err := writeFrame(&buf, make(chan int)); err == nil {
		t.Fatal("unencodable value written")
	}
}

func TestResolve(t *testing.T) {
	cfg, err := HostConfig{Targets: []string{"A.test:1", "[::1]:22"}}.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dial == nil || cfg.Logger == nil || cfg.DialTimeout != DefaultDialTimeout {
		t.Fatalf("defaults %+v", cfg)
	}
	open := proto.AccessPolicy{}
	only := proto.AccessPolicy{Targets: []string{"[::1]:22"}}
	for _, c := range []struct {
		req    string
		policy proto.AccessPolicy
		want   string
	}{
		{"", open, "a.test:1"},
		{"a.TEST:01", open, "a.test:1"},
		{"[0:0::1]:22", open, "[::1]:22"},
		{"[::1]:22", only, "[::1]:22"},
		{"", only, ""},
		{"b.test:1", open, ""},
		{"nonsense", open, ""},
	} {
		got, err := cfg.resolve(c.req, c.policy)
		if got != c.want || (c.want == "") != (err != nil) {
			t.Errorf("%q %v: %q %v", c.req, c.policy, got, err)
		}
	}
}

// FuzzStreamRequest: whatever a dialer writes as a stream's request, the
// host never panics and never resolves a target outside its list.
func FuzzStreamRequest(f *testing.F) {
	var buf bytes.Buffer
	_ = writeFrame(&buf, streamRequest{Target: "a.test:1"})
	f.Add(buf.Bytes())
	f.Add([]byte{0, 2, '{', '}'})
	f.Add([]byte{0xff, 0xff})
	cfg, err := HostConfig{Targets: []string{"a.test:1", "[::1]:22"}}.normalize()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var req streamRequest
		if readFrame(bytes.NewReader(data), &req) != nil {
			return
		}
		target, err := cfg.resolve(req.Target, proto.AccessPolicy{})
		if err == nil && target != "a.test:1" && target != "[::1]:22" {
			t.Fatalf("resolved %q", target)
		}
	})
}

// quicPair punches a quicforward session in a World and returns both ends
// of its QUIC connection; the host end accepts no stream.
func quicPair(t *testing.T) (host, dial *Conn) {
	t.Helper()
	w := testworld.New(t, testworld.Options{})
	hostID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dialID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hostC := w.Client(w.NATHost(nattest.FullCone()), nil)
	ctx, cancel := context.WithCancel(context.Background())
	sessions := make(chan *client.Session, 1)
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = hostC.Serve(ctx, client.Registration{HostID: "office", TransportMode: Mode, TransportData: hostID.TransportData()},
			func(ctx context.Context, s *client.Session) {
				sessions <- s
				<-ctx.Done()
			})
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	testkit.WaitFor(t, "the host to register", func() bool { return len(w.Broker.Snapshot().Hosts) != 0 })
	dialC := w.Client(w.NATHost(nattest.FullCone()), nil)
	ds, err := dialC.Open(ctx, client.OpenRequest{HostID: "office", TransportMode: Mode, TransportData: dialID.TransportData()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ds.Close() })
	var hs *client.Session
	select {
	case hs = <-sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("no session on the host")
	}
	type accepted struct {
		c   *Conn
		err error
	}
	acc := make(chan accepted, 1)
	go func() {
		c, err := Accept(ctx, hs, hostID)
		acc <- accepted{c, err}
	}()
	dial, err = Dial(ctx, ds, dialID)
	a := <-acc
	if err != nil || a.err != nil {
		t.Fatalf("dial %v, accept %v", err, a.err)
	}
	t.Cleanup(func() {
		_ = dial.Close()
		_ = a.c.Close()
	})
	return a.c, dial
}

// TestOpenStreamUnanswered: a stream the host never answers marks the
// connection as dead (unanswered), a stream the host's stream limit does
// not grant yet does not; and the end of ctx ends the wait for either.
func TestOpenStreamUnanswered(t *testing.T) {
	_, dial := quicPair(t)
	open := func() (unanswered bool, d time.Duration, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, unanswered, err = dial.openStream(ctx, "")
		return unanswered, time.Since(start), err
	}
	if unanswered, d, err := open(); !unanswered || !errors.Is(err, context.DeadlineExceeded) || d > 5*time.Second {
		t.Fatalf("no answer: unanswered %v, %v after %v", unanswered, err, d)
	}
	for i := 0; ; i++ {
		if _, err := dial.qc.OpenStream(); err != nil {
			break
		}
		if i > 1<<16 {
			t.Fatal("no stream limit")
		}
	}
	if unanswered, d, err := open(); unanswered || !errors.Is(err, context.DeadlineExceeded) || d > 5*time.Second {
		t.Fatalf("stream limit: unanswered %v, %v after %v", unanswered, err, d)
	}
}

package broker

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/internal/life"
	"github.com/djylb/holepunch/standalone/proto"
)

func TestMain(m *testing.M) { goroutines.VerifyTestMain(m) }

// signal is a broker.Signal that records what the broker tells the host.
type signal struct {
	mu       sync.Mutex
	incoming []proto.Incoming
	revoked  int
	err      error
	panics   bool
}

func (s *signal) Notify(in proto.Incoming) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.panics {
		panic("notify boom")
	}
	if s.err != nil {
		return s.err
	}
	s.incoming = append(s.incoming, in)
	return nil
}

func (s *signal) Revoke() {
	s.mu.Lock()
	s.revoked++
	s.mu.Unlock()
}

func (s *signal) last(t *testing.T) proto.Incoming {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.incoming) == 0 {
		t.Fatal("no incoming")
	}
	return s.incoming[len(s.incoming)-1]
}

func (s *signal) revocations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked
}

// rig is a broker in NoObserver mode (no natprobe) with its results.
type rig struct {
	b       *Broker
	results chan coord.Result
}

func newRig(t *testing.T, mutate func(*Config)) *rig {
	t.Helper()
	r := &rig{results: make(chan coord.Result, 16)}
	cfg := Config{Coord: coord.Config{
		NoObserver: true,
		OnResult:   func(res coord.Result) { r.results <- res },
	}}
	if mutate != nil {
		mutate(&cfg)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.b = b
	t.Cleanup(func() { _ = b.Close() })
	return r
}

func (r *rig) result(t *testing.T) coord.Result {
	t.Helper()
	select {
	case res := <-r.results:
		return res
	case <-time.After(5 * time.Second):
		t.Fatal("no result")
	}
	return coord.Result{}
}

func (r *rig) register(t *testing.T, id string) (*Host, *signal) {
	t.Helper()
	sig := &signal{}
	h, err := r.b.Register(Registration{HostID: id, Metadata: map[string]string{"os": "linux"}}, sig)
	if err != nil {
		t.Fatal(err)
	}
	return h, sig
}

// link returns the session end of a control link whose client end is
// drained, so that the coordinator's writes never block.
func link(t *testing.T) (server net.Conn, client net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, b) }()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

var insecure = coord.AttachOptions{Security: protocol.ControlSecurityInsecureForTesting}

// TestOpenJoinAttach: the dialer's open reaches the host as an Incoming with a
// ticket; the ticket joins the same session once; both streams attach; the
// end of the session is forgotten and still reported to OnResult.
func TestOpenJoinAttach(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.Authorize = func(req OpenRequest, h HostInfo) (proto.AccessPolicy, error) {
			if h.HostID != "office" || h.Metadata["os"] != "linux" || req.DialerID != "laptop" {
				return proto.AccessPolicy{}, errors.New("unexpected request")
			}
			return proto.AccessPolicy{Targets: []string{"DB.internal:5432"}}, nil
		}
	})
	h, sig := r.register(t, "office")
	s, err := r.b.Open(OpenRequest{HostID: "office", DialerID: "laptop", Metadata: map[string]string{"user": "ann"}, ClientKey: "ip:1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	info := s.Info()
	if info.SessionID != s.ID() || info.HostID != "office" || info.DialerID != "laptop" ||
		info.HostMetadata["os"] != "linux" || info.DialerMetadata["user"] != "ann" ||
		len(info.Policy.Targets) != 1 || info.Policy.Targets[0] != "db.internal:5432" {
		t.Fatalf("info %+v", info)
	}
	info.HostMetadata["os"] = "changed"
	if s.Info().HostMetadata["os"] != "linux" {
		t.Fatal("Info shares its maps")
	}
	in := sig.last(t)
	if in.SessionID != s.ID() || in.Ticket == "" || in.DialerID != "laptop" || in.DialerMetadata["user"] != "ann" {
		t.Fatalf("incoming %+v", in)
	}
	if snap := r.b.Snapshot(); snap.Sessions != 1 || snap.Pending != 1 || len(snap.Hosts) != 1 || snap.Hosts[0].Sessions != 1 {
		t.Fatalf("snapshot %+v", snap)
	}
	if h.Info().Sessions != 1 || h.ID() != "office" || h.Credential() == "" {
		t.Fatalf("host %+v", h.Info())
	}

	if _, err := r.b.Join(s.ID(), in.Ticket+"x"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("wrong ticket: %v", err)
	}
	if _, err := r.b.Join("nope", in.Ticket); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown session: %v", err)
	}
	js, err := r.b.Join(s.ID(), in.Ticket)
	if err != nil || js != s {
		t.Fatalf("join: %v", err)
	}
	if _, err := r.b.Join(s.ID(), in.Ticket); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("second join: %v", err)
	}
	if snap := r.b.Snapshot(); snap.Pending != 0 {
		t.Fatalf("pending %d", snap.Pending)
	}

	dial, _ := link(t)
	host, _ := link(t)
	if err := s.Attach(protocol.RoleInitiator, dial, insecure); err != nil {
		t.Fatal(err)
	}
	if err := js.Attach(protocol.RoleResponder, host, insecure); err != nil {
		t.Fatal(err)
	}
	if snap := s.Coord().Snapshot(); !snap.Attached[0] || !snap.Attached[1] {
		t.Fatalf("coord %+v", snap)
	}
	s.Abort(protocol.ReasonCanceled, "test")
	res := r.result(t)
	if res.SessionID != s.ID() || res.Reason != protocol.ReasonCanceled || res.Labels["host_id"] != "office" || res.Labels["dialer_id"] != "laptop" {
		t.Fatalf("result %+v", res)
	}
	if snap := r.b.Snapshot(); snap.Sessions != 0 || snap.Hosts[0].Sessions != 0 {
		t.Fatalf("session not forgotten: %+v", snap)
	}
	if _, err := r.b.Join(s.ID(), in.Ticket); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("join after the end: %v", err)
	}
}

// TestAttachAfterClose: once the broker is closed, Attach refuses and still
// takes the stream: it is closed, never left to the caller.
func TestAttachAfterClose(t *testing.T) {
	r := newRig(t, nil)
	r.register(t, "office")
	s, err := r.b.Open(OpenRequest{HostID: "office"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.b.Close(); err != nil {
		t.Fatal(err)
	}
	if res := r.result(t); res.Reason != protocol.ReasonServerShutdown {
		t.Fatalf("result %+v", res)
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	if err := s.Attach(protocol.RoleInitiator, a, insecure); err == nil {
		t.Fatal("attach after close accepted")
	}
	assertClosed(t, b)
	if _, err := r.b.Open(OpenRequest{HostID: "office"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("open after close: %v", err)
	}
	if _, err := r.b.Register(Registration{HostID: "x"}, &signal{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("register after close: %v", err)
	}
}

// assertClosed checks that the far end of c was closed: a read fails at
// once.
func assertClosed(t *testing.T, far net.Conn) {
	t.Helper()
	_ = far.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := far.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("stream left open: %v", err)
	}
}

// TestAttachFailureAborts: a stream the coordinator refuses (here: not
// vouched for, insecure_control) is closed and the session aborted.
func TestAttachFailureAborts(t *testing.T) {
	r := newRig(t, nil)
	r.register(t, "office")
	s, err := r.b.Open(OpenRequest{HostID: "office"})
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	if err := s.Attach(protocol.RoleInitiator, a, coord.AttachOptions{}); !invalidArgument(err) {
		t.Fatalf("attach: %v", err)
	}
	assertClosed(t, b)
	if res := r.result(t); res.Reason != protocol.ReasonInvalidArgument || res.Detail != "attach_failed" {
		t.Fatalf("result %+v", res)
	}
	if err := s.Attach(protocol.RoleResponder, nil, insecure); err == nil {
		t.Fatal("nil conn attached")
	}
}

// TestTakeover: a live host ID is taken over only with its credential; the
// old registration is revoked and its unjoined sessions aborted, while a
// joined one runs on.
func TestTakeover(t *testing.T) {
	r := newRig(t, nil)
	old, oldSig := r.register(t, "office")
	joined, err := r.b.Open(OpenRequest{HostID: "office"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.b.Join(joined.ID(), oldSig.last(t).Ticket); err != nil {
		t.Fatal(err)
	}
	pending, err := r.b.Open(OpenRequest{HostID: "office"})
	if err != nil {
		t.Fatal(err)
	}

	for _, cred := range []string{"", "wrong", old.Credential() + "x"} {
		if _, err := r.b.Register(Registration{HostID: "office", Credential: cred}, &signal{}); !errors.Is(err, ErrHostExists) {
			t.Fatalf("credential %q: %v", cred, err)
		}
	}
	newSig := &signal{}
	nh, err := r.b.Register(Registration{HostID: "office", Credential: old.Credential()}, newSig)
	if err != nil {
		t.Fatal(err)
	}
	if nh.Credential() == old.Credential() {
		t.Fatal("credential not renewed")
	}
	if oldSig.revocations() != 1 {
		t.Fatal("old link not revoked")
	}
	res := r.result(t)
	if res.SessionID != pending.ID() || res.Reason != protocol.ReasonPeerOffline || res.Detail != "host_replaced" {
		t.Fatalf("pending session %+v", res)
	}
	if st := joined.Coord().Snapshot().State; st == coord.StateClosed {
		t.Fatal("joined session aborted")
	}
	old.Close() // the old link ends later: the new registration stays
	if snap := r.b.Snapshot(); len(snap.Hosts) != 1 || snap.Sessions != 1 {
		t.Fatalf("snapshot %+v", snap)
	}
	s, err := r.b.Open(OpenRequest{HostID: "office"})
	if err != nil {
		t.Fatal(err)
	}
	if newSig.last(t).SessionID != s.ID() {
		t.Fatal("open did not reach the new link")
	}
}

// TestHostClose: a host whose link ends is unregistered and its unjoined
// sessions are aborted at once rather than at the bind deadline.
func TestHostClose(t *testing.T) {
	r := newRig(t, nil)
	h, sig := r.register(t, "office")
	s, err := r.b.Open(OpenRequest{HostID: "office"})
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	h.Close()
	if res := r.result(t); res.SessionID != s.ID() || res.Reason != protocol.ReasonPeerOffline || res.Detail != "host_disconnected" {
		t.Fatalf("result %+v", res)
	}
	if _, err := r.b.Join(s.ID(), sig.last(t).Ticket); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("join after host close: %v", err)
	}
	if _, err := r.b.Open(OpenRequest{HostID: "office"}); !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("open: %v", err)
	}
	if sig.revocations() != 0 {
		t.Fatal("a host closed by its owner is not revoked")
	}
	// The ID is free again, without a credential.
	r.register(t, "office")
}

// TestNotifyFailure: a host that cannot be told fails the open and the
// session is aborted and forgotten.
func TestNotifyFailure(t *testing.T) {
	for name, sig := range map[string]*signal{
		"error":         {err: errors.New("link down")},
		"panic":         {panics: true},
		"panicky error": {err: panickyError{}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			if _, err := r.b.Register(Registration{HostID: "office"}, sig); err != nil {
				t.Fatal(err)
			}
			_, err := r.b.Open(OpenRequest{HostID: "office"})
			if !errors.Is(err, ErrHostNotFound) || life.IsPanic(err) != (name != "error") {
				t.Fatalf("open: %v", err)
			}
			if res := r.result(t); res.Reason != protocol.ReasonPeerOffline || res.Detail != "host_unreachable" {
				t.Fatalf("result %+v", res)
			}
			if snap := r.b.Snapshot(); snap.Sessions != 0 {
				t.Fatalf("snapshot %+v", snap)
			}
		})
	}
}

// panickyError is an error whose Error panics with itself: even fmt, which
// recovers one panic in Error, panics again on it.
type panickyError struct{}

func (e panickyError) Error() string { panic(e) }

func TestAuthorize(t *testing.T) {
	cases := []struct {
		name string
		fn   func(OpenRequest, HostInfo) (proto.AccessPolicy, error)
		want error
	}{
		{"refused", func(OpenRequest, HostInfo) (proto.AccessPolicy, error) { return proto.AccessPolicy{}, errors.New("no") }, ErrRefused},
		{"panic", func(OpenRequest, HostInfo) (proto.AccessPolicy, error) { panic("boom") }, ErrRefused},
		{"panicky error", func(OpenRequest, HostInfo) (proto.AccessPolicy, error) { return proto.AccessPolicy{}, panickyError{} }, ErrRefused},
		{"bad target", func(OpenRequest, HostInfo) (proto.AccessPolicy, error) {
			return proto.AccessPolicy{Targets: []string{"nope"}}, nil
		}, nil},
		{"too many", func(OpenRequest, HostInfo) (proto.AccessPolicy, error) {
			return proto.AccessPolicy{Targets: make([]string, proto.MaxTargets+1)}, nil
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, func(cfg *Config) { cfg.Authorize = c.fn })
			r.register(t, "office")
			_, err := r.b.Open(OpenRequest{HostID: "office"})
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("open: %v", err)
			}
			if snap := r.b.Snapshot(); snap.Sessions != 0 {
				t.Fatal("refused open left a session")
			}
		})
	}
	r := newRig(t, func(cfg *Config) {
		cfg.Authorize = func(OpenRequest, HostInfo) (proto.AccessPolicy, error) {
			return proto.AccessPolicy{Targets: []string{}}, nil
		}
	})
	r.register(t, "office")
	s, err := r.b.Open(OpenRequest{HostID: "office"})
	if err != nil || s.Info().Policy.Targets != nil {
		t.Fatalf("empty policy: %v %+v", err, s)
	}
}

func TestRequestValidation(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxHosts = 1 })
	if _, err := r.b.Register(Registration{HostID: "bad id"}, &signal{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad id: %v", err)
	}
	if _, err := r.b.Register(Registration{HostID: "h"}, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil signal: %v", err)
	}
	var nilSig *signal
	if _, err := r.b.Register(Registration{HostID: "h"}, nilSig); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("typed nil signal: %v", err)
	}
	r.register(t, "h1")
	if _, err := r.b.Register(Registration{HostID: "h2"}, &signal{}); !errors.Is(err, ErrRegistryFull) {
		t.Fatalf("full: %v", err)
	}
	for _, req := range []OpenRequest{{HostID: ""}, {HostID: "h1", DialerID: "bad id"}} {
		if _, err := r.b.Open(req); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("%+v: %v", req, err)
		}
	}
	if _, err := r.b.Open(OpenRequest{HostID: "h2"}); !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("unknown host: %v", err)
	}
}

// TestCoordLimits: the coordinator's refusals pass through Open.
func TestCoordLimits(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Coord.Limits.MaxPerResponderKey = 1 })
	r.register(t, "office")
	if _, err := r.b.Open(OpenRequest{HostID: "office"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.b.Open(OpenRequest{HostID: "office"}); !errors.Is(err, coord.ErrBusy) {
		t.Fatalf("second open: %v", err)
	}
}

func TestNew(t *testing.T) {
	if _, err := New(Config{MaxHosts: -1, Coord: coord.Config{NoObserver: true}}); err == nil {
		t.Fatal("negative MaxHosts accepted")
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("relay-only coordinator without NoObserver accepted")
	}
}

// TestCloseRevokesAndIsIdempotent: Close revokes every host link once and
// returns the same result to every caller.
func TestCloseRevokesAndIsIdempotent(t *testing.T) {
	r := newRig(t, nil)
	_, s1 := r.register(t, "a")
	h2, s2 := r.register(t, "b")
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.b.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if s1.revocations() != 1 || s2.revocations() != 1 {
		t.Fatalf("revocations %d %d", s1.revocations(), s2.revocations())
	}
	h2.Close()
	if snap := r.b.Snapshot(); len(snap.Hosts) != 0 {
		t.Fatalf("hosts after close: %+v", snap.Hosts)
	}
	if r.b.Coordinator() == nil {
		t.Fatal("no coordinator")
	}
}

func TestSnapshotSorted(t *testing.T) {
	r := newRig(t, nil)
	for _, id := range []string{"c", "a", "b"} {
		r.register(t, id)
	}
	snap := r.b.Snapshot()
	if len(snap.Hosts) != 3 || snap.Hosts[0].HostID != "a" || snap.Hosts[2].HostID != "c" {
		t.Fatalf("%+v", snap.Hosts)
	}
}

func TestSecret(t *testing.T) {
	text, sum := newSecret()
	other, _ := newSecret()
	if text == other || len(text) < 20 {
		t.Fatalf("secrets %q %q", text, other)
	}
	if !sum.matches(text) || sum.matches(other) || sum.matches("") || sum.matches(text+text) {
		t.Fatal("matches")
	}
}

// BenchmarkMatch: one dialer matched with a registered host, joined and
// ended — the broker's work per session, the coordinator's included.
func BenchmarkMatch(b *testing.B) {
	bk, err := New(Config{Coord: coord.Config{NoObserver: true, Limits: coord.Limits{
		NewSessions: coord.Rate{PerSec: -1}, InitiatorKeyRate: coord.Rate{PerSec: -1},
	}}})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = bk.Close() }()
	sig := &signal{}
	if _, err := bk.Register(Registration{HostID: "office"}, sig); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		s, err := bk.Open(OpenRequest{HostID: "office"})
		if err != nil {
			b.Fatal(err)
		}
		sig.mu.Lock()
		in := sig.incoming[len(sig.incoming)-1]
		sig.incoming = sig.incoming[:0]
		sig.mu.Unlock()
		if _, err := bk.Join(in.SessionID, in.Ticket); err != nil {
			b.Fatal(err)
		}
		s.Abort(protocol.ReasonCanceled, "bench")
		<-s.Coord().Done()
	}
}

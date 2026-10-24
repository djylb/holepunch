package holepunch

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// lockedBuffer is a log destination shared by the library's goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Options.Logger records the milestones of a session and its failure,
// never its token or route.
func TestOptionsLogger(t *testing.T) {
	w := newWorld(t)
	var logs [2]lockedBuffer
	ps := &pairScript{w: w, timeouts: testTimeouts()}
	pr := runPair(t, w, [2]*nattest.NATConfig{natCfg(nattest.PortRestricted()), natCfg(nattest.PortRestricted())}, ps, func(i int, o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(&logs[i], &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	defer pr.closeAll()
	token, _ := ps.sess.token.MarshalText()
	route, _ := ps.sess.wire.RouteID.MarshalText()
	for i, r := range pr.res {
		if r.err != nil {
			t.Fatalf("client %d: %v", i, r.err)
		}
		out := logs[i].String()
		for _, want := range []string{"holepunch: session started", "holepunch: phase", "stage=go_received", "stage=confirmed",
			"holepunch: session done", "session_id=" + ps.sess.sid} {
			if !strings.Contains(out, want) {
				t.Errorf("client %d: no %q in\n%s", i, want, out)
			}
		}
		for _, secret := range []string{string(token), string(route), hex.EncodeToString(ps.sess.wire.RouteID[:])} {
			if strings.Contains(out, secret) {
				t.Fatalf("client %d logged a secret:\n%s", i, out)
			}
		}
	}

	// A failure is logged at Warn with its reason; a panicking handler is
	// recovered.
	w = newWorld(t)
	var failed lockedBuffer
	ps = &pairScript{w: w, timeouts: testTimeouts(), mutateStart: func(i int, s *protocol.PunchStart) {
		if i == 1 {
			s.Probe.Observers, s.Probe.ExtraReply = nil, false
		}
	}}
	pr = runPair(t, w, [2]*nattest.NATConfig{nil, nil}, ps, func(i int, o *Options) {
		if i == 0 {
			o.Logger = slog.New(panicHandler{})
			return
		}
		o.Logger = slog.New(slog.NewTextHandler(&failed, nil))
	})
	defer pr.closeAll()
	if pr.res[1].err == nil {
		t.Fatal("the bad start was accepted")
	}
	if out := failed.String(); !strings.Contains(out, "level=WARN msg=\"holepunch: session failed\" reason=") {
		t.Fatalf("no failure in\n%s", out)
	}
}

type panicHandler struct{ slog.Handler }

func (panicHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (panicHandler) Handle(context.Context, slog.Record) error    { panic("handler") }

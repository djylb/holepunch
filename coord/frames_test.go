package coord

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/internal/wiretype"
	"github.com/djylb/holepunch/protocol"
)

// rawFrame is a frame header with an arbitrary major, type and length,
// followed by payload.
func rawFrame(major uint8, typ wiretype.Type, length uint32, payload []byte) []byte {
	b := make([]byte, controlwire.HeaderSize, controlwire.HeaderSize+len(payload))
	b[0], b[1], b[2], b[3] = 'h', 'p', major, byte(typ)
	binary.BigEndian.PutUint32(b[4:], length)
	return append(b, payload...)
}

// violates writes raw bytes on side i's link and expects the session to end
// with code and detail, failed by side i.
func violates(t *testing.T, raw []byte, code protocol.Reason, detail string) {
	t.Helper()
	r := newRig(t)
	p := r.noPongPair()
	nc, err := releaseIdle(t, p.cl[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nc.Close() }()
	go func() { _, _ = nc.Write(raw) }()
	if a := expectAbort(t, p.cl[1]); a.By != protocol.RoleInitiator || a.Reason != code {
		t.Fatalf("abort %+v", a)
	}
	res := r.wait(p.s)
	if res.Reason != code || res.FailedRole != protocol.RoleInitiator || (detail != "" && res.Detail != detail) {
		t.Fatalf("result %+v", res)
	}
}

// TestFrameLimitPerType: a frame one byte over its type's cap is a
// protocol violation (frame_too_large), decided from the header alone.
func TestFrameLimitPerType(t *testing.T) {
	for _, typ := range []wiretype.Type{wiretype.ProbeReport, wiretype.PunchReady, wiretype.Progress,
		wiretype.Assist, wiretype.Pong, wiretype.RoundResult, wiretype.PunchResult} {
		t.Run(typ.String(), func(t *testing.T) {
			violates(t, rawFrame(wiretype.Version, typ, uint32(typ.Cap()+1), nil), protocol.ReasonProtocolViolation, "frame_too_large")
		})
	}
}

// TestVersionMismatchRejected: a header major other than 1, or a report's
// control.version other than 1, is control_version_mismatch.
func TestVersionMismatchRejected(t *testing.T) {
	t.Run("header", func(t *testing.T) {
		violates(t, rawFrame(2, wiretype.Pong, 2, []byte("{}")), protocol.ReasonControlVersionMismatch, "")
	})
	t.Run("control.version", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		rep := simclient.Report(*p.starts[0], 1, "", fam(0, simclient.OpenTraits))
		rep.Control.Version = 2
		b, _ := json.Marshal(rep)
		if err := p.cl[0].SendFrame(ctx(t), wiretype.ProbeReport, b); err != nil {
			t.Fatal(err)
		}
		if a := expectAbort(t, p.cl[1]); a.Reason != protocol.ReasonControlVersionMismatch || a.By != protocol.RoleInitiator {
			t.Fatalf("abort %+v", a)
		}
		if res := r.wait(p.s); res.Reason != protocol.ReasonControlVersionMismatch {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("bad magic", func(t *testing.T) {
		violates(t, []byte("GET / HTTP/1.1\r\n"), protocol.ReasonProtocolViolation, "bad_magic")
	})
}

// TestUnknownTypeTolerated: reserved types and types sent the wrong way are
// read, dropped and counted; the 17th is a protocol violation.
func TestUnknownTypeTolerated(t *testing.T) {
	for _, typ := range []wiretype.Type{42, wiretype.PunchStart, wiretype.ProbeSummary,
		wiretype.PunchGo, wiretype.Abort, wiretype.Ping} {
		t.Run(typ.String(), func(t *testing.T) {
			r := newRig(t)
			p := r.noPongPair()
			nc, err := releaseIdle(t, p.cl[0])
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = nc.Close() }()
			go func() { _, _ = io.Copy(io.Discard, nc) }()
			payload := []byte("{" + strings.Repeat(" ", 1000) + "}")
			for range controlwire.MaxDiscarded {
				if _, err := nc.Write(rawFrame(wiretype.Version, typ, uint32(len(payload)), payload)); err != nil {
					t.Fatal(err)
				}
			}
			rep := simclient.Report(*p.starts[0], 1, "", fam(0, simclient.OpenTraits))
			f, _ := msgframe.Encode(&rep)
			if _, err := nc.Write(rawFrame(wiretype.Version, f.Type, uint32(len(f.Payload)), f.Payload)); err != nil {
				t.Fatal(err)
			}
			testkit.WaitFor(t, "report after unknown frames", func() bool { return p.s.Snapshot().Reported[0] })
			if _, err := nc.Write(rawFrame(wiretype.Version, typ, uint32(len(payload)), payload)); err != nil {
				t.Fatal(err)
			}
			res := r.wait(p.s)
			if res.Reason != protocol.ReasonProtocolViolation || res.Detail != "unknown_frames" || res.Counters.UnknownFrames < controlwire.MaxDiscarded {
				t.Fatalf("result %+v", res)
			}
		})
	}
}

// TestFrameQuota: the 513th frame of a link is control_flood.
func TestFrameQuota(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Limits.FrameRate = Rate{PerSec: -1}; c.Limits.ProgressPerLink = -1 })
	p := r.pair(SessionOptions{})
	pr := &protocol.Progress{SessionID: p.s.ID(), Role: protocol.RoleInitiator, Stage: "x"}
	go func() {
		for i := range 513 {
			pr.Seq = uint16(i)
			if p.cl[0].Send(ctx(t), pr) != nil {
				return
			}
		}
	}()
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonProtocolViolation || res.Detail != detailControlFlood {
		t.Fatalf("result %+v", res)
	}
	if res.Counters.ProgressDropped != 0 {
		t.Fatalf("progress dropped %d", res.Counters.ProgressDropped)
	}
}

// TestFrameRate: more than the frame bucket at once is control_flood.
func TestFrameRate(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Limits.FrameRate = Rate{PerSec: 1, Burst: 5} })
	p := r.pair(SessionOptions{})
	go func() {
		for i := range 10 {
			if p.cl[0].Send(ctx(t), &protocol.Pong{Seq: uint8(i%8 + 1)}) != nil {
				return
			}
		}
	}()
	if a := expectAbort(t, p.cl[0]); a.Reason != protocol.ReasonProtocolViolation || a.Detail != detailControlFlood {
		t.Fatalf("abort to the flooder %+v", a)
	}
	if res := r.wait(p.s); res.Detail != detailControlFlood || res.FailedRole != protocol.RoleInitiator {
		t.Fatalf("result %+v", res)
	}
}

// TestProgressQuota: progress beyond the per-link quota is dropped and
// counted, without ending the session.
func TestProgressQuota(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Limits.ProgressPerLink = 3; c.Limits.FrameRate = Rate{PerSec: -1} })
	p := r.pair(SessionOptions{})
	for i := range 5 {
		send(t, p.cl[0], &protocol.Progress{SessionID: p.s.ID(), Role: protocol.RoleInitiator, Seq: uint16(i), Stage: "probe_started"})
	}
	p.report(0)
	testkit.WaitFor(t, "report", func() bool { return p.s.Snapshot().Reported[0] })
	p.s.Abort(protocol.ReasonCanceled, "")
	res := r.wait(p.s)
	if res.Counters.ProgressDropped != 2 || len(res.Timeline) != 3 {
		t.Fatalf("dropped %d timeline %d", res.Counters.ProgressDropped, len(res.Timeline))
	}
}

// TestMessageViolations: messages that are malformed, from the wrong session
// or role, repeated or out of state end the session with protocol_violation
// and the given detail.
func TestMessageViolations(t *testing.T) {
	cases := []struct {
		name   string
		detail string
		do     func(t *testing.T, p *pair)
	}{
		{"bad json", "", func(t *testing.T, p *pair) {
			_ = p.cl[0].SendFrame(ctx(t), wiretype.ProbeReport, []byte("{not json"))
		}},
		{"session", "session_mismatch", func(t *testing.T, p *pair) {
			rep := simclient.Report(*p.starts[0], 1, "", fam(0, simclient.OpenTraits))
			rep.SessionID = "other"
			send(t, p.cl[0], &rep)
		}},
		{"role", "role_mismatch", func(t *testing.T, p *pair) {
			rep := simclient.Report(*p.starts[0], 1, "", fam(0, simclient.OpenTraits))
			rep.Role = protocol.RoleResponder
			send(t, p.cl[0], &rep)
		}},
		{"duplicate report", detailDuplicate, func(t *testing.T, p *pair) {
			p.report(0)
			p.report(0)
		}},
		{"early ready", detailUnexpected, func(t *testing.T, p *pair) {
			send(t, p.cl[0], &protocol.PunchReady{SessionID: p.s.ID(), Role: protocol.RoleInitiator,
				Families: []protocol.FamilyReady{{Family: protocol.FamilyUDP4, Sockets: 1}}})
		}},
		{"early round_result", detailUnexpected, func(t *testing.T, p *pair) {
			rr := simclient.RoundEnd(p.s.ID(), protocol.RoleInitiator, 1, protocol.RoundWindowEnd)
			send(t, p.cl[0], &rr)
		}},
		{"early success", detailUnexpected, func(t *testing.T, p *pair) {
			ok := simclient.Success(p.s.ID(), protocol.RoleInitiator, p.path(0, 1))
			send(t, p.cl[0], &ok)
		}},
		{"report after summary", detailUnexpected, func(t *testing.T, p *pair) {
			p.summaries()
			p.report(0)
		}},
		{"duplicate ready", detailDuplicate, func(t *testing.T, p *pair) {
			sums := p.summaries()
			send(t, p.cl[0], simclient.Ready(sums[0], protocol.RoleInitiator, 1))
			send(t, p.cl[0], simclient.Ready(sums[0], protocol.RoleInitiator, 1))
		}},
		{"future round", "round", func(t *testing.T, p *pair) {
			p.punching()
			rr := simclient.RoundEnd(p.s.ID(), protocol.RoleInitiator, 3, protocol.RoundWindowEnd)
			send(t, p.cl[0], &rr)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			p := r.pair(SessionOptions{})
			c.do(t, p)
			res := r.wait(p.s)
			if res.Reason != protocol.ReasonProtocolViolation || res.FailedRole != protocol.RoleInitiator ||
				(c.detail != "" && res.Detail != c.detail) {
				t.Fatalf("result %+v", res)
			}
		})
	}
}

// TestLateMessagesIgnored: a ready while punching, a report or round result
// while confirming, and the previous round's result are not violations.
func TestLateMessagesIgnored(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	sums := p.summaries()
	for i := range 2 {
		send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 1))
	}
	p.state(StatePunching)
	send(t, p.cl[0], simclient.Ready(sums[0], protocol.RoleInitiator, 1))
	p.windowEnd(0, 1, simclient.Outcome{})
	p.windowEnd(1, 1, simclient.Outcome{})
	testkit.WaitFor(t, "round 2", func() bool { return p.s.Snapshot().Round == 2 })
	p.windowEnd(0, 1, simclient.Outcome{}) // the previous round, late
	p.confirm(0, 2)
	p.state(StateConfirming)
	p.report(1)
	p.windowEnd(1, 2, simclient.Outcome{})
	send(t, p.cl[1], simclient.Ready(sums[1], protocol.RoleResponder, 1))
	p.confirm(1, 2)
	p.succeed(0, 2)
	p.succeed(1, 2)
	res := r.wait(p.s)
	if res.Outcome != OutcomeSucceeded || res.Winner.Round != 2 {
		t.Fatalf("result %+v", res)
	}
}

// TestFeatureNotEchoed: without both echoes of sandwich no round asks for a
// sandwich probe; an unknown feature in the echo is ignored.
func TestFeatureNotEchoed(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	if len(p.starts[0].Control.Features) != 0 {
		t.Fatalf("relay-only offers %v", p.starts[0].Control.Features)
	}
	rep := simclient.Report(*p.starts[0], 1, "", fam(0, simclient.OpenTraits))
	rep.Control.Features = []protocol.Feature{"future_thing"}
	send(t, p.cl[0], &rep)
	p.report(1)
	for i := range 2 {
		sum := expect[protocol.ProbeSummary](t, p.cl[i])
		if slices.ContainsFunc(sum.Plan.Round1.Sides, func(fs protocol.FamilySide) bool { return fs.Sandwich }) {
			t.Fatal("sandwich without echo")
		}
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

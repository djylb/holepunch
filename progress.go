package holepunch

import (
	"context"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/protocol"
)

// Progress stages the library emits (an open enumeration on the wire).
const (
	stageProbeStarted      = "probe_started"
	stageProbeDone         = "probe_done"
	stagePortmapReady      = "portmap_ready"
	stageSummaryReceived   = "summary_received"
	stageReadySent         = "ready_sent"
	stageGoReceived        = "go_received"
	stageFire              = "fire"
	stageFirstPeerPacket   = "first_peer_packet"
	stageNominated         = "nominated"
	stageAdopted           = "adopted"
	stageConfirmed         = "confirmed"
	stageHandoverDone      = "handover_done"
	stageRoundEnd          = "round_end"
	stageBudgetExhausted   = "budget_exhausted"
	stageDriftDetected     = "drift_detected"
	stageTraitsCorrected   = "traits_corrected"
	stageHairpinResult     = "hairpin_result"
	stageLowTTLUnsupported = "low_ttl_unsupported"
)

// Progress limits.
const (
	localProgressQueue = 256
	progressDrainLimit = 100 * time.Millisecond
	wireProgressRate   = 10 // frames per second
	wireProgressBurst  = 30
	maxProgressDetail  = 128
)

// Fault-injection point of local progress delivery.
const fiProgressDeliver = "progress.deliver"

// progressEvent is one progress report before it becomes a protocol.Progress.
type progressEvent struct {
	stage    string
	status   protocol.ProgressStatus
	detail   string
	round    uint8
	family   protocol.Family
	remote   netip.AddrPort // candidate_remote, local copy only
	counters map[string]uint32
}

// progressState numbers progress frames and limits the wire copies to
// 10/s with a burst of 30; controlwire's P3 queue then keeps the newest 64
// and merges frames of one stage.
type progressState struct {
	mu     sync.Mutex
	seq    uint16
	bucket bucket
}

// progress emits one event: a wire frame when the session is known and the
// rate allows, and a local copy for Options.OnProgress, enriched with
// family, session phase, round and candidate remote. Telemetry only: nothing
// in the session depends on it being delivered.
func (rt *runtime) progress(ev progressEvent) {
	now := rt.clk.Now()
	rt.prog.mu.Lock()
	rt.prog.seq++
	seq := rt.prog.seq
	wireOK := rt.prog.bucket.take(now, 0)
	rt.prog.mu.Unlock()

	sid, accepted := rt.ctl.session()
	p := protocol.Progress{
		SessionID: sid, Role: rt.role, Seq: seq, Stage: ev.stage, Status: ev.status, Round: ev.round,
		Detail: truncProgressDetail(ev.detail), Counters: ev.counters,
	}
	if !rt.startAt.IsZero() {
		p.AtMs = uint32(max(now.Sub(rt.startAt), 0) / time.Millisecond)
	}
	if rt.insecure {
		p.Meta = map[string]string{"insecure": "1"}
	}
	if accepted && wireOK {
		if fr, err := msgframe.Encode(p); err == nil {
			_ = rt.ctl.conn.SendCoalesced(fr, ev.stage)
		}
	} else if accepted {
		rt.cnt.progressDropped.Add(1)
	}
	if rt.sink == nil {
		return
	}
	local := p
	local.Meta = map[string]string{"session_phase": string(rt.phases.current())}
	if rt.insecure {
		local.Meta["insecure"] = "1"
	}
	if ev.family != "" {
		local.Meta["family"] = string(ev.family)
	}
	if ev.round > 0 {
		local.Meta["round"] = strconv.Itoa(int(ev.round))
	}
	if ev.remote.IsValid() {
		local.Meta["candidate_remote"] = ev.remote.String()
	}
	rt.sink.push(local)
}

func truncProgressDetail(s string) string {
	if len(s) <= maxProgressDetail {
		return s
	}
	return truncDetail(s[:maxProgressDetail])
}

// progressSink delivers local progress copies to Options.OnProgress on one
// goroutine, in order. The queue holds 256 events and drops the oldest when
// full. A panicking callback is recovered and counted; the session goes on.
// When the session ends, delivery continues for at most 100 ms and the rest
// is dropped, so the callback is never called after Punch returns.
// A callback that blocks past the join bound of the cleanup leaves the
// goroutine running when Punch returns; the sink is closed by then,
// and that goroutine calls the callback no more.
type progressSink struct {
	rt     *runtime
	fn     func(protocol.Progress)
	wake   chan struct{}
	closed atomic.Bool // set by finish once the session group is closed

	mu sync.Mutex
	q  []protocol.Progress
}

func newProgressSink(rt *runtime, fn func(protocol.Progress)) *progressSink {
	return &progressSink{rt: rt, fn: fn, wake: make(chan struct{}, 1)}
}

func (s *progressSink) push(p protocol.Progress) {
	s.mu.Lock()
	if len(s.q) >= localProgressQueue {
		copy(s.q, s.q[1:])
		s.q = s.q[:len(s.q)-1]
		s.rt.cnt.progressDropped.Add(1)
	}
	s.q = append(s.q, p)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *progressSink) pop() (protocol.Progress, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.q) == 0 {
		return protocol.Progress{}, false
	}
	p := s.q[0]
	s.q = s.q[1:]
	return p, true
}

// run is the delivery goroutine ("progress").
func (s *progressSink) run(ctx context.Context) {
	for {
		select {
		case <-s.wake:
			for {
				p, ok := s.pop()
				if !ok {
					break
				}
				s.deliver(p)
				if ctx.Err() != nil {
					break
				}
			}
		case <-ctx.Done():
			s.drain()
			return
		}
	}
}

// drain delivers what is queued for at most progressDrainLimit and drops
// the rest.
func (s *progressSink) drain() {
	deadline := time.Now().Add(progressDrainLimit)
	for time.Now().Before(deadline) {
		p, ok := s.pop()
		if !ok {
			return
		}
		s.deliver(p)
	}
	s.mu.Lock()
	s.rt.cnt.progressDropped.Add(int64(len(s.q)))
	s.q = nil
	s.mu.Unlock()
}

func (s *progressSink) deliver(p protocol.Progress) {
	if s.closed.Load() {
		s.rt.cnt.progressDropped.Add(1)
		return
	}
	if pe := life.Safe("onprogress", func() {
		if err := faultinject.Point(fiProgressDeliver); err != nil {
			panic(err)
		}
		s.fn(p)
	}); pe != nil {
		s.rt.cnt.callbackPanics.Add(1)
	}
}

// sendAssist queues a punch_assist (P2; when the queue is full the newest
// is dropped, which controlwire reports as ErrQueueFull).
func (rt *runtime) sendAssist(a protocol.Assist) {
	fr, err := msgframe.Encode(a)
	if err != nil {
		return
	}
	_ = rt.ctl.conn.Send(fr) // a full P2 queue drops the newest
}

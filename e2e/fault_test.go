package e2e

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/internal/wiretype"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// phase is a column of the client fault matrix: the point of the session at
// which the fault strikes.
type phase int

const (
	phStartWait     phase = iota // punch_start not read yet
	phProbing                    // probing
	phSummaryWait                // reported, waiting for the summary
	phPreparing                  // planned, preparing round 1
	phGoWait                     // ready, waiting for the go
	phRound1                     // punching, round 1
	phBetweenRounds              // between rounds 1 and 2
	phRound2                     // punching, round 2
	phConfirmed                  // the initiator confirmed, handover not finished
	phResponderDone              // the responder has returned
)

var phaseNames = [...]string{"start_wait", "probing", "summary_wait", "preparing", "go_wait", "round1", "between_rounds", "round2",
	"confirmed", "responder_done"}

func (p phase) String() string { return phaseNames[p] }

// Client progress stages (the open enumeration of punch_progress.stage the
// root package reports).
const (
	stageProbeStarted    = "probe_started"
	stageSummaryReceived = "summary_received"
	stageFire            = "fire"
	stageConfirmed       = "confirmed"
)

// silence is how the peers' UDP is blocked in a fault cell, so that the
// punching phases last and the later rounds happen: every packet from the
// peer is dropped at the receiving socket, as by two NATs that drop it.
type silence int

const (
	silenceNone   silence = iota
	silenceAll            // the whole session: no round can confirm
	silenceRound1         // until the second go: round 1 fails, round 2 may confirm
)

// Wait-point bounds of the e2e configuration.
const (
	boundStartWait  = 15 * time.Second       // StartWait, a library constant
	boundFrameWrite = 2 * time.Second        // client frame write
	boundSlack      = 300 * time.Millisecond // tolerance of every return bound
	boundQuick      = 100 * time.Millisecond
	boundQuick2     = 200 * time.Millisecond
	boundGap        = 500 * time.Millisecond
	boundConfirmEnd = 500 * time.Millisecond // the confirmation grace after a round
)

// observed is the side whose outcome the matrix states: the initiator (I).
const observed = 0

// faultExpect is what a cell of the matrix expects of the initiator.
type faultExpect struct {
	// reasons are the allowed outcomes; "" is success.
	reasons []protocol.Reason
	// bound returns the latest instant the initiator may return; nil: the
	// session cap only.
	bound func(fc *faultCell) time.Time
	quiet silence
	// warn must be in the initiator's Warn on success.
	warn protocol.Warning
	// phases are the Error.Phase values allowed on failure.
	phases []protocol.Phase
	// check adds an assertion of the cell.
	check func(fc *faultCell) error
	// pathLost: the fault broke the winning path after the handover, so the
	// winner check (a packet through each winning socket) does not apply.
	pathLost bool
}

// faultRow is a row of the matrix: a fault and its expectations by phase.
type faultRow struct {
	name string
	// victim builds the initiator's NAT (nil: PRC).
	victim func() nattest.NATConfig
	pipe   int // control pipe buffer in bytes (0: nattest's default)
	// peerTarget makes the responder the target in every phase (peer_crash);
	// otherwise the initiator is, and the responder in responder_done.
	peerTarget bool
	// dropHeld drops the frame a trigger held instead of delivering it
	// after the fault: a crashed peer or a closed server never sent it.
	dropHeld bool
	// probeAtStart strikes the probing phase just before punch_start reaches
	// the client, so that the whole probe runs under the fault: a UDP-level
	// fault injected at the probe_started report can come after a fast probe
	// has already finished.
	probeAtStart bool
	inject       func(fc *faultCell)
	expect       func(p phase) (faultExpect, bool)
}

// faultCell is one (row, phase) run.
type faultCell struct {
	row    *faultRow
	ph     phase
	target int // the side the fault hits
	w      *world
	sides  [2]*side
	r      *run
	exp    faultExpect

	injected atomic.Bool
	mu       sync.Mutex
	at       time.Time // injection instant
	// h runs the cell's goroutines next to the session: triggers, silences
	// and the faults that act on their own (a flood, a server shutdown).
	h *cellHelpers
}

// cellHelpers are the goroutines a fault cell runs next to its session. They
// end with stop, and end joins them before the cell is checked, so that
// nothing a fault does overlaps the assertions or outlives the cell.
type cellHelpers struct {
	mu    sync.Mutex
	wg    sync.WaitGroup
	stop  chan struct{}
	ended bool
}

func newCellHelpers() *cellHelpers { return &cellHelpers{stop: make(chan struct{})} }

// spawn runs f on a goroutine of its own, unless the cell has ended.
func (h *cellHelpers) spawn(f func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ended {
		return
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		f()
	}()
}

// end closes stop and waits up to d for the helpers to return; it reports
// whether they did.
func (h *cellHelpers) end(d time.Duration) bool {
	h.mu.Lock()
	if !h.ended {
		h.ended = true
		close(h.stop)
	}
	h.mu.Unlock()
	joined := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(joined)
	}()
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-joined:
		return true
	case <-tm.C:
		return false
	}
}

// helperJoin bounds the wait for a cell's helpers once the session ended.
const helperJoin = 5 * time.Second

// fire injects the fault once.
func (fc *faultCell) fire() {
	if !fc.injected.CompareAndSwap(false, true) {
		return
	}
	fc.mu.Lock()
	fc.at = time.Now()
	fc.mu.Unlock()
	fc.row.inject(fc)
}

func (fc *faultCell) injectedAt() time.Time {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.at
}

// after bounds a return to d after the injection, with the boundSlack
// tolerance.
func after(d time.Duration) func(*faultCell) time.Time {
	return func(fc *faultCell) time.Time { return fc.injectedAt().Add(scaled(d + boundSlack)) }
}

// afterRTT bounds a return to one control round trip plus d after the
// injection (a server notice relayed to the initiator).
func afterRTT(d time.Duration) func(*faultCell) time.Time {
	return func(fc *faultCell) time.Time {
		return fc.injectedAt().Add(scaled(fc.r.delay[0] + fc.r.delay[1] + d + boundSlack))
	}
}

// roundEnd bounds a return to the current round's end + 500 ms
// (+ boundSlack): the round's window counted from the injection, which
// happens at its fire.
func roundEnd(k uint8) func(*faultCell) time.Time {
	return func(fc *faultCell) time.Time {
		win := time.Duration(0)
		for _, p := range view(fc.r.taps[observed]).plans() {
			if p.Round == k {
				win = time.Duration(p.WindowMs) * time.Millisecond
			}
		}
		return fc.injectedAt().Add(scaled(win + boundConfirmEnd + boundSlack))
	}
}

// fromStart bounds a return relative to the initiator's Punch call:
// punch_start arrives one link delay later.
func fromStart(d func(fc *faultCell) time.Duration) func(*faultCell) time.Time {
	return func(fc *faultCell) time.Time {
		return fc.r.out[observed].start.Add(scaled(fc.r.delay[observed] + d(fc) + boundSlack))
	}
}

// summaryWait is the client's wait for the summary, from punch_start:
// summary_wait_ms + 2 s.
func summaryWait(fc *faultCell) time.Duration {
	v := view(fc.r.taps[observed])
	if v.start == nil {
		return 0
	}
	return time.Duration(v.start.Timeouts.SummaryWaitMs)*time.Millisecond + 2*time.Second
}

// goWait is the client's wait for a go: go_wait_ms + 2 s.
func goWait(fc *faultCell) time.Duration {
	return time.Duration(fc.w.cfg.timeouts.GoWaitMs)*time.Millisecond + 2*time.Second
}

// handshake bounds a return to the first go + handshake_timeout + the
// confirmation grace.
func handshake(fc *faultCell) time.Time {
	fg := fc.r.res.Timing.FirstGo
	if fg.IsZero() {
		fg = fc.injectedAt()
	}
	return fg.Add(scaled(time.Duration(fc.w.cfg.timeouts.HandshakeTimeoutMs)*time.Millisecond + boundConfirmEnd + fc.r.delay[observed] + boundSlack))
}

// prePunchPhases are the client phases (Error.Phase) allowed from start_wait
// to go_wait. In start_wait punch_start may already be on its way when the
// fault strikes (the server wrote it at Attach), so probing is allowed too.
var prePunchPhases = map[phase][]protocol.Phase{
	phStartWait:   {protocol.PhaseCreated, protocol.PhaseProbing},
	phProbing:     {protocol.PhaseProbing},
	phSummaryWait: {protocol.PhaseReported},
	phPreparing:   {protocol.PhasePlanned, protocol.PhaseReady},
	phGoWait:      {protocol.PhaseReady},
}

var punchPhases = []protocol.Phase{protocol.PhasePunching, protocol.PhaseNegotiating}

func reasons(r ...protocol.Reason) []protocol.Reason { return r }

// success is the expectation of a fault that must not change the outcome.
func success(quiet silence) faultExpect { return faultExpect{reasons: reasons(""), quiet: quiet} }

// silenceFor returns the silence of a punching phase for faults that end
// the session unless a round confirms: deterministic failures in round 1 and
// between rounds, a chance of success in round 2.
func silenceFor(p phase) silence {
	switch p {
	case phRound1, phBetweenRounds:
		return silenceAll
	case phRound2:
		return silenceRound1
	default:
		return silenceNone
	}
}

// roundOf is the round of a punching phase.
func roundOf(p phase) uint8 {
	if p == phRound2 {
		return 2
	}
	return 1
}

// expectLinkLoss is the expectation of a lost control link (the cut and
// server_restart rows) by phase; quick is the bound before punching, before
// the Reason then.
func expectLinkLoss(p phase, quick time.Duration, before ...protocol.Reason) (faultExpect, bool) {
	switch p {
	case phStartWait, phProbing, phSummaryWait, phPreparing, phGoWait:
		return faultExpect{reasons: before, bound: after(quick), phases: prePunchPhases[p]}, true
	case phRound1, phRound2:
		return faultExpect{reasons: reasons("", protocol.ReasonControlInterrupted), bound: roundEnd(roundOf(p)), quiet: silenceFor(p), phases: punchPhases}, true
	case phBetweenRounds:
		return faultExpect{reasons: reasons(protocol.ReasonControlInterrupted), bound: after(boundGap), quiet: silenceAll, phases: punchPhases}, true
	case phConfirmed:
		return faultExpect{reasons: reasons(""), warn: protocol.WarnControlLostAfterConfirm}, true
	case phResponderDone:
		return success(silenceNone), true
	}
	return faultExpect{}, false
}

// fatalUDP reports whether side i reported round_result{fatal,
// udp_blocked}: every socket write failed for a second.
func fatalUDP(fc *faultCell, i int) bool {
	for _, rr := range view(fc.r.taps[i]).rounds {
		if rr.Status == protocol.RoundFatal && rr.Reason == protocol.ReasonUDPBlocked {
			return true
		}
	}
	return false
}

// udpBlocked checks the udp_write_fail row while punching: a side that
// reported round_result{fatal, udp_blocked} ends with udp_blocked itself;
// the coordinator attributes the session udp_blocked only when both sides
// reported fatal, and candidate_timeout otherwise. mustFatal requires the
// initiator's report: its writes failed for the whole round.
func udpBlocked(mustFatal bool) func(fc *faultCell) error {
	return func(fc *faultCell) error {
		fatal := [2]bool{fatalUDP(fc, 0), fatalUDP(fc, 1)}
		var errs []error
		if mustFatal && !fatal[observed] {
			errs = append(errs, errors.New("no round_result{fatal, udp_blocked} after every write failed"))
		}
		for i := range 2 {
			if got := fc.r.out[i].reason(); fatal[i] && got != protocol.ReasonUDPBlocked {
				errs = append(errs, fmt.Errorf("%s reported fatal udp_blocked but ended with %q", roles[i], got))
			}
		}
		want := protocol.ReasonCandidateTimeout
		if fatal[0] && fatal[1] {
			want = protocol.ReasonUDPBlocked
		}
		if fc.r.resOK && fc.r.res.Reason != want {
			errs = append(errs, fmt.Errorf("coordinator attributed %q, want %q (fatal %v)", fc.r.res.Reason, want, fatal))
		}
		return errors.Join(errs...)
	}
}

// attributionCodes are the Reasons the coordinator attributes at a round's
// end from both sides' evidence (internal/plan Attribute and TerminalReason).
var attributionCodes = []protocol.Reason{protocol.ReasonUDPBlocked, protocol.ReasonOneWayUDPOnly, protocol.ReasonPacketBudgetExceeded,
	protocol.ReasonNotSynchronized, protocol.ReasonCandidateTimeout, protocol.ReasonHardSymmetricRandom}

// coordFirst checks the backpressure row while punching: the initiator ends
// with success, with its own control_interrupted, or with the coordinator's
// round-end attribution when that arrived first — then its Reason is the
// coordinator's code.
func coordFirst(fc *faultCell) error {
	got := fc.r.out[observed].reason()
	if got == "" || got == protocol.ReasonControlInterrupted {
		return nil
	}
	if !fc.r.resOK || got != fc.r.res.Reason || !slices.Contains(attributionCodes, got) {
		return fmt.Errorf("%s ended with %q, which is neither control_interrupted nor the coordinator's attribution %q", roles[observed], got, fc.r.res.Reason)
	}
	return nil
}

// faultRows is the client fault matrix without its injection-point row
// (TestFaultInject) and its user-code row (TestFaultUserCode).
func faultRows() []*faultRow {
	return []*faultRow{
		{name: "cut", inject: func(fc *faultCell) { fc.r.pipes[fc.target].Cut() },
			expect: func(p phase) (faultExpect, bool) {
				q := boundQuick2
				if p == phStartWait {
					q = boundQuick
				}
				return expectLinkLoss(p, q, protocol.ReasonControlInterrupted)
			}},
		{name: "blackhole", inject: func(fc *faultCell) { fc.r.pipes[fc.target].Blackhole() },
			expect: func(p phase) (faultExpect, bool) {
				switch p {
				case phStartWait:
					return faultExpect{reasons: reasons(protocol.ReasonControlTimeout), bound: fromStart(func(*faultCell) time.Duration { return boundStartWait }), phases: prePunchPhases[p]}, true
				case phProbing, phSummaryWait:
					return faultExpect{reasons: reasons(protocol.ReasonControlTimeout), bound: fromStart(summaryWait), phases: []protocol.Phase{protocol.PhaseReported}}, true
				case phPreparing, phGoWait:
					return faultExpect{reasons: reasons(protocol.ReasonControlTimeout), bound: func(fc *faultCell) time.Time {
						return fc.injectedAt().Add(scaled(goWait(fc) + boundSlack))
					}, phases: []protocol.Phase{protocol.PhaseReady}}, true
				case phRound1, phBetweenRounds:
					return faultExpect{reasons: reasons(protocol.ReasonCandidateTimeout), bound: handshake, quiet: silenceAll, phases: punchPhases}, true
				case phRound2:
					return faultExpect{reasons: reasons("", protocol.ReasonCandidateTimeout), bound: handshake, quiet: silenceRound1, phases: punchPhases}, true
				case phConfirmed, phResponderDone:
					return success(silenceNone), true
				}
				return faultExpect{}, false
			}},
		{name: "server_restart", dropHeld: true, inject: func(fc *faultCell) {
			fc.h.spawn(func() { _ = fc.w.co.Close() })
		}, expect: func(p phase) (faultExpect, bool) {
			// Before punching: punch_abort{server_shutdown}, or only EOF on a
			// link whose abort could not be written.
			e, ok := expectLinkLoss(p, boundQuick, protocol.ReasonServerShutdown, protocol.ReasonControlInterrupted)
			return e, ok
		}},
		{name: "peer_crash", peerTarget: true, dropHeld: true, inject: func(fc *faultCell) {
			fc.r.crashed[fc.target] = true
			fc.sides[fc.target].host.Crash()
		},
			expect: func(p phase) (faultExpect, bool) {
				switch p {
				case phProbing, phSummaryWait, phPreparing, phGoWait:
					return faultExpect{reasons: reasons(protocol.ReasonPeerOffline), bound: afterRTT(boundQuick), phases: prePunchPhases[p]}, true
				case phRound1, phRound2:
					return faultExpect{reasons: reasons("", protocol.ReasonPeerOffline), bound: roundEnd(roundOf(p)), quiet: silenceFor(p), phases: punchPhases}, true
				case phBetweenRounds:
					return faultExpect{reasons: reasons(protocol.ReasonPeerOffline), bound: afterRTT(boundGap), quiet: silenceAll, phases: punchPhases}, true
				case phConfirmed, phResponderDone:
					return success(silenceNone), true
				case phStartWait: // not a cell of this row
				}
				return faultExpect{}, false
			}},
		{name: "cancel", inject: func(fc *faultCell) { fc.r.cancel(fc.target) },
			expect: func(p phase) (faultExpect, bool) {
				switch p {
				case phResponderDone:
					return faultExpect{}, false
				case phConfirmed:
					return faultExpect{reasons: reasons(protocol.ReasonCanceled), bound: after(boundQuick)}, true
				default:
					e := faultExpect{reasons: reasons(protocol.ReasonCanceled), bound: after(boundQuick), quiet: silenceFor(p)}
					if p <= phGoWait {
						e.phases = prePunchPhases[p]
					}
					return e, true
				}
			}},
		{name: "udp_write_fail", probeAtStart: true, inject: func(fc *faultCell) { fc.sides[fc.target].host.FailWrites("", -1, nil) },
			expect: func(p phase) (faultExpect, bool) {
				switch p {
				case phProbing:
					return faultExpect{reasons: reasons(protocol.ReasonUDPBlocked), bound: fromStart(func(fc *faultCell) time.Duration {
						return time.Duration(fc.w.cfg.timeouts.ProbeTimeoutMs)*time.Millisecond + boundGap
					})}, true
				case phRound2:
					// The writes may fail for less than the 1 s of the fatal
					// rule before round 2 ends: then no fatal, and the
					// coordinator's candidate_timeout.
					return faultExpect{reasons: reasons(protocol.ReasonUDPBlocked, protocol.ReasonCandidateTimeout), bound: handshake,
						quiet: silenceRound1, check: udpBlocked(false)}, true
				case phSummaryWait, phGoWait, phRound1:
					return faultExpect{reasons: reasons(protocol.ReasonUDPBlocked), bound: handshake, quiet: silenceFor(p), check: udpBlocked(true)}, true
				case phConfirmed:
					return faultExpect{reasons: reasons("", protocol.ReasonHandoverTimeout), bound: after(time.Duration(e2eTimeouts().HandoverTimeoutMs) * time.Millisecond)}, true
				case phStartWait, phPreparing, phBetweenRounds, phResponderDone: // not cells of this row
				}
				return faultExpect{}, false
			}},
		{name: "bind_fail", probeAtStart: true, inject: func(fc *faultCell) { fc.sides[fc.target].host.FailBinds("", -1) },
			expect: func(p phase) (faultExpect, bool) {
				switch p {
				case phProbing:
					// Every bind of the probe fails: local_port_bind_failed at
					// once.
					return faultExpect{reasons: reasons(protocol.ReasonLocalPortBindFailed), bound: fromStart(func(*faultCell) time.Duration { return boundQuick })}, true
				case phPreparing, phRound1:
					return success(silenceNone), true
				case phRound2:
					return success(silenceRound1), true
				case phStartWait, phSummaryWait, phGoWait, phBetweenRounds, phConfirmed, phResponderDone: // no bind to fail
				}
				return faultExpect{}, false
			}},
		{name: "malformed_frame", inject: func(fc *faultCell) {
			_ = fc.r.taps[fc.target].inject([]byte{'x', 'x', wiretype.Version, byte(wiretype.PunchGo), 0, 0, 0, 0})
		}, expect: func(p phase) (faultExpect, bool) {
			switch p {
			case phResponderDone:
				return faultExpect{}, false
			case phConfirmed:
				return success(silenceNone), true
			default:
				e := faultExpect{reasons: reasons(protocol.ReasonProtocolViolation), bound: after(boundQuick), quiet: silenceFor(p)}
				if p <= phGoWait {
					e.phases = prePunchPhases[p]
				}
				return e, true
			}
		}},
		{name: "udp_flood", victim: nattest.FullCone, inject: func(fc *faultCell) { fc.h.spawn(fc.flood) },
			expect: func(p phase) (faultExpect, bool) {
				switch p {
				case phStartWait, phResponderDone:
					return faultExpect{}, false
				case phBetweenRounds, phRound2:
					return success(silenceRound1), true
				default:
					return success(silenceNone), true
				}
			}},
		{name: "nat_expire", inject: func(fc *faultCell) {
			for _, n := range fc.sides[fc.target].nats {
				n.ExpireAll()
			}
		}, expect: expectNAT},
		{name: "nat_rebind", inject: func(fc *faultCell) { fc.sides[fc.target].nats[0].Rebind(nil) }, expect: expectNAT},
		{name: "backpressure", pipe: backpressureBuffer, inject: func(fc *faultCell) { fc.r.taps[fc.target].stopReading() },
			expect: func(p phase) (faultExpect, bool) {
				switch p {
				case phProbing, phSummaryWait, phPreparing:
					// The next key frame (the report, or the ready that answers
					// the summary) blocks: the frame write bound from then.
					return faultExpect{reasons: reasons(protocol.ReasonControlInterrupted), bound: func(fc *faultCell) time.Time {
						from := fc.injectedAt()
						if v := view(fc.r.taps[observed]); v.summaryAt.After(from) {
							from = v.summaryAt
						}
						return from.Add(scaled(boundFrameWrite + fc.r.delay[observed] + boundQuick + boundSlack))
					}, phases: []protocol.Phase{protocol.PhaseProbing, protocol.PhaseReported, protocol.PhasePlanned, protocol.PhaseReady}}, true
				case phGoWait:
					// No key frame is due in go_wait; the session goes on and
					// may confirm over UDP before a write blocks for 2 s.
					return faultExpect{reasons: reasons("", protocol.ReasonControlInterrupted), bound: handshake}, true
				case phRound1, phRound2, phBetweenRounds:
					// Writes block for 2 s, unless the coordinator's round-end
					// attribution arrives first.
					return faultExpect{reasons: append(reasons("", protocol.ReasonControlInterrupted), attributionCodes...),
						bound: handshake, quiet: silenceFor(p), phases: punchPhases, check: coordFirst}, true
				case phConfirmed:
					return success(silenceNone), true
				case phStartWait, phResponderDone: // not cells of this row
				}
				return faultExpect{}, false
			}},
		{name: "udp_read_error", probeAtStart: true, inject: func(fc *faultCell) { fc.sides[fc.target].net.failReads.Store(true) },
			expect: func(p phase) (faultExpect, bool) {
				switch p {
				case phProbing:
					return faultExpect{reasons: reasons(protocol.ReasonProbeTimeout, protocol.ReasonUDPBlocked), bound: fromStart(func(fc *faultCell) time.Duration {
						return time.Duration(fc.w.cfg.timeouts.ProbeTimeoutMs)*time.Millisecond + boundGap
					})}, true
				case phRound1, phRound2:
					return faultExpect{reasons: reasons("", protocol.ReasonCandidateTimeout, protocol.ReasonOneWayUDPOnly), bound: handshake, quiet: silenceFor(p)}, true
				case phConfirmed:
					return faultExpect{reasons: reasons("", protocol.ReasonHandoverTimeout), bound: after(time.Duration(e2eTimeouts().HandoverTimeoutMs) * time.Millisecond)}, true
				case phStartWait, phSummaryWait, phPreparing, phGoWait, phBetweenRounds, phResponderDone: // not cells of this row
				}
				return faultExpect{}, false
			}},
	}
}

// backpressureBuffer is the control pipe's buffer in the backpressure row:
// smaller than any key frame, so a write blocks as soon as the coordinator
// stops reading.
const backpressureBuffer = 64

// expectNAT is the expectation of the nat_expire and nat_rebind rows: a NAT
// that forgets its mappings or changes its IP costs the round or is
// recovered; whatever the outcome, it is bounded.
func expectNAT(p phase) (faultExpect, bool) {
	if p == phStartWait {
		return faultExpect{}, false
	}
	q := silenceNone
	if p == phBetweenRounds || p == phRound2 {
		q = silenceRound1
	}
	return faultExpect{reasons: reasons("", protocol.ReasonCandidateTimeout, protocol.ReasonOneWayUDPOnly, protocol.ReasonHandoverTimeout,
		protocol.ReasonNotSynchronized), bound: handshake, quiet: q, pathLost: p >= phConfirmed}, true
}

// flood sends random datagrams from a host on the core to every external
// endpoint of the target's NAT until the cell ends (random routes and forged
// tokens, which the library drops before AEAD).
func (fc *faultCell) flood() {
	attacker := fc.w.n.PublicHost(netip.IPv4Unspecified())
	w, err := attacker.ListenUDP(context.Background(), "udp4", netip.AddrPort{}, "listen")
	if err != nil {
		return
	}
	defer func() { _ = w.Close() }()
	buf := make([]byte, 256)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-fc.h.stop:
			return
		case <-tick.C:
		}
		for _, m := range fc.sides[fc.target].nats[0].Mappings() {
			_, _ = rand.Read(buf)
			_, _ = w.WriteToUDPAddrPort(buf[:64+int(buf[0])%192], m.External)
		}
	}
}

// arm sets up the frame triggers of the cell's phase. The initiator's own
// protocol points: punch_start held before it reaches it. The points
// that must also hold the coordinator in the matching state: the
// responder's report (summary_wait: the coordinator is still probing), ready
// (go_wait: summarized) or first round_result (between_rounds: round 1 not
// evaluated) is held until the initiator has written its own, and the fault
// fires then.
func (fc *faultCell) arm(r *run) {
	switch {
	case fc.ph == phStartWait || fc.ph == phProbing && fc.row.probeAtStart:
		h := r.taps[observed].holdNext(toClient, wiretype.PunchStart, nil)
		fc.h.spawn(func() {
			select {
			case <-h.Reached():
				fc.fire()
				if fc.row.dropHeld {
					h.Drop()
				}
			case <-fc.h.stop:
			}
			h.Release()
		})
		return
	case fc.ph == phSummaryWait || fc.ph == phGoWait || fc.ph == phBetweenRounds:
	default:
		return
	}
	typ := map[phase]wiretype.Type{phSummaryWait: wiretype.ProbeReport, phGoWait: wiretype.PunchReady, phBetweenRounds: wiretype.RoundResult}[fc.ph]
	var pred func(protocol.Message) bool
	if fc.ph == phBetweenRounds {
		pred = func(m protocol.Message) bool { rr, ok := m.(*protocol.RoundResult); return ok && rr.Round == 1 }
	}
	peer := r.taps[1-observed].holdNext(toServer, typ, pred)
	own := r.taps[observed].when(toServer, typ, pred)
	fc.h.spawn(func() {
		select {
		case <-own:
			fc.fire()
			if fc.row.dropHeld {
				peer.Drop()
			}
		case <-fc.h.stop:
		}
		peer.Release()
	})
}

// progressTrigger returns the initiator's OnProgress: it fires the fault at
// the cell's stage.
func (fc *faultCell) progressTrigger() func(protocol.Progress) {
	return func(p protocol.Progress) {
		round, _ := strconv.Atoi(p.Meta["round"])
		switch {
		case fc.ph == phProbing && !fc.row.probeAtStart && p.Stage == stageProbeStarted,
			fc.ph == phPreparing && p.Stage == stageSummaryReceived,
			fc.ph == phRound1 && p.Stage == stageFire && round == 1,
			fc.ph == phRound2 && p.Stage == stageFire && round == 2,
			fc.ph == phConfirmed && p.Stage == stageConfirmed:
			fc.fire()
		}
	}
}

// applySilence installs the cell's UDP silence between the peers.
func (fc *faultCell) applySilence(r *run) { silencePeers(r, fc.sides, fc.exp.quiet, fc.h) }

// silencePeers drops every packet between the two sides, for the whole
// session or until the second go reaches each side; the goroutines that lift
// the silence are helpers of h.
func silencePeers(r *run, sides [2]*side, mode silence, h *cellHelpers) {
	if mode == silenceNone {
		return
	}
	for i := range 2 {
		peer := sides[1-i].publicIPs()
		sides[i].net.dropFrom(func(from netip.AddrPort) bool { return slices.Contains(peer, from.Addr().Unmap()) })
		if mode != silenceRound1 {
			continue
		}
		lift := r.taps[i].when(toClient, wiretype.PunchGo, func(m protocol.Message) bool {
			g, ok := m.(*protocol.PunchGo)
			return ok && g.Round == 2
		})
		net := sides[i].net
		h.spawn(func() {
			select {
			case <-lift:
				net.dropFrom(nil)
			case <-h.stop:
			}
		})
	}
}

// heal undoes the faults that outlive the session on the hosts, so that the
// resource checks see the sockets as the application would.
func (fc *faultCell) heal() {
	for _, s := range fc.sides {
		s.host.FailWrites("", 0, nil)
		s.host.FailBinds("", 0)
		s.net.failReads.Store(false)
		s.net.dropFrom(nil)
	}
}

// runFault runs one cell and returns its violations.
func runFault(t *testing.T, row *faultRow, ph phase, exp faultExpect, seed int64) []string {
	fc := &faultCell{row: row, ph: ph, exp: exp, h: newCellHelpers()}
	if row.peerTarget || ph == phResponderDone {
		fc.target = 1 - observed
	}
	fc.w = newWorld(t, worldConfig{seed: seed})
	cfgs := [2]nattest.NATConfig{profPRC(), profPRC()}
	if row.victim != nil {
		cfgs[observed] = row.victim()
	}
	for i := range 2 {
		fc.sides[i] = fc.w.behind([]nattest.NATConfig{cfgs[i]})
	}
	spec := sessionSpec{}
	spec.ctlBuffer[fc.target] = row.pipe
	spec.onProgress[observed] = fc.progressTrigger()
	if ph == phResponderDone {
		spec.onReturn[1-observed] = func(*run) { fc.fire() }
	}
	spec.prepare = func(r *run) {
		fc.r = r
		fc.arm(r)
		fc.applySilence(r)
	}
	r, err := newRun(fc.w, fc.sides, spec)
	if err != nil {
		return fc.w.abandon(err)
	}
	fc.r = r
	r.execute()
	var v []string
	if !fc.h.end(scaled(helperJoin)) {
		v = append(v, fmt.Sprintf("the cell's helper goroutines did not end within %v", scaled(helperJoin)))
	}
	v = append(v, fc.check()...)
	fc.heal()
	name := fmt.Sprintf("fault/%s/%s", row.name, ph)
	cr := &cellRun{c: &cell{name: name, class: classFail}, seed: seed, w: fc.w, sides: fc.sides, r: r}
	cr.measure()
	if exp.pathLost {
		r.skipWinnerCheck = true
	}
	v = append(v, cr.checkResources()...)
	if len(v) > 0 {
		v = append(v, cr.dumpNote(t, v, "fault"))
	}
	if err := fc.w.close(); err != nil {
		v = append(v, fmt.Sprintf("world close: %v", err))
	}
	return v
}

// check applies the cell's expectations to the initiator — outcome, return
// bound, Error.Phase and warning — and holds both sides to a clean control
// conn and no leaked goroutine; runFault adds the resource checks.
func (fc *faultCell) check() []string {
	var v []string
	add := func(format string, args ...any) { v = append(v, fmt.Sprintf(format, args...)) }
	r := fc.r
	if !fc.injected.Load() {
		add("the fault was never injected: phase %s not reached", fc.ph)
		return v
	}
	o := &r.out[observed]
	got := o.reason()
	if !slices.Contains(fc.exp.reasons, got) {
		add("%s: outcome %q (%v), want one of %q", roles[observed], got, o.err, fc.exp.reasons)
	}
	if o.end.Before(fc.injectedAt()) && got != "" {
		add("%s: returned %v before the fault was injected", roles[observed], fc.injectedAt().Sub(o.end))
	}
	if fc.exp.bound != nil {
		if b := fc.exp.bound(fc); o.end.After(b) {
			add("%s: returned %v after the injection, bound %v", roles[observed], o.end.Sub(fc.injectedAt()), b.Sub(fc.injectedAt()))
		}
	}
	if got != "" && len(fc.exp.phases) > 0 && o.herr != nil && !slices.Contains(fc.exp.phases, o.herr.Phase) {
		add("%s: Error.Phase %q, want one of %q", roles[observed], o.herr.Phase, fc.exp.phases)
	}
	if got == "" && fc.exp.warn != "" && !slices.Contains(o.diag.Warn, fc.exp.warn) {
		add("%s: warn %v lacks %s", roles[observed], o.diag.Warn, fc.exp.warn)
	}
	if fc.exp.check != nil {
		if err := fc.exp.check(fc); err != nil {
			add("%v", err)
		}
	}
	if !r.done {
		add("the coordinator's session did not end")
	}
	if r.resOK {
		if n := fc.w.resultCalls(r.res.SessionID); n != 1 {
			add("OnResult called %d times", n)
		}
	}
	for i := range 2 {
		oi := &r.out[i]
		if oi.inflight != 0 || (!oi.rdl.IsZero() || !oi.wdl.IsZero()) && !slices.Contains(oi.diag.Warn, protocol.WarnControlUnreturnable) {
			add("%s: control conn not returned clean: %d reads in flight, read deadline %v, write deadline %v",
				roles[i], oi.inflight, oi.rdl, oi.wdl)
		}
		if n := oi.diag.Counters.LeakedGoroutines; n != 0 {
			add("%s: %d leaked goroutines", roles[i], n)
		}
		if err := r.taps[i].logComplete(); err != nil {
			add("%s: %v", roles[i], err)
		}
	}
	return v
}

// TestFaultMatrix runs the client fault matrix: every row ×
// every applicable phase, one run each (nightly: three), with the common
// assertions.
func TestFaultMatrix(t *testing.T) {
	runs := 1
	if suite().level == levelNightly {
		runs = 3
	}
	t.Run("cells", func(t *testing.T) {
		for _, row := range faultRows() {
			for ph := phStartWait; ph <= phResponderDone; ph++ {
				exp, ok := row.expect(ph)
				if !ok {
					continue
				}
				name := fmt.Sprintf("%s/%s", row.name, ph)
				if !suite().selected("fault/" + name) {
					continue
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					release := acquireSlot()
					defer release()
					for i := range runs {
						seed := cellSeed("fault/"+name, i)
						for _, p := range runFault(t, row, ph, exp, seed) {
							t.Errorf("seed %d: %s", seed, p)
						}
					}
				})
			}
		}
	})
	goleak.VerifyNone(t)
}

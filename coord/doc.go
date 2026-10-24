// Package coord is holepunch's server-side coordinator:
// it takes over the control links of two clients that the caller has already
// authenticated, runs their NAT probing against natprobe, plans every round of
// the punch, aligns the two clients' start instants by their control-link
// round-trip times, relays what each client sees of the other while punching,
// and lets the session go as soon as the clients confirm a UDP path.
//
// # Usage
//
// A deployment shares one natprobe.Registry between its natprobe.Server and
// its Coordinator, then pairs two authenticated client connections in a
// session:
//
//	co, err := coord.New(coord.Config{Registry: reg, DefaultProbe: probe.ProbeSpec()})
//	...
//	sess, err := co.NewSession(coord.SessionOptions{})
//	err = sess.Attach(protocol.RoleInitiator, connA, coord.AttachOptions{})
//	err = sess.Attach(protocol.RoleResponder, connB, coord.AttachOptions{})
//	res, err := sess.Wait(ctx) // or Config.OnResult for every session
//
// A long-running server reads the probe spec afresh for every session
// instead — Config.Probe: ProbeFrom(natprobe.SpecSource{...}), with STUN
// servers and server addresses that natprobe keeps up to date — and gives
// a client's own addresses in AttachOptions.Probe.
//
// Once Attach returns nil the connection belongs to the session, which
// closes it when the session ends. A failed session's Result.Retry says
// whether to try again and in which mode; a client that should keep
// relaying and punch in the background gets SessionOptions.Mode
// protocol.ModeBackground.
//
// # Model
//
// A Coordinator creates sessions; a Session needs no connection to exist.
// NewSession pre-generates both punch_start messages, registers the probe
// route with the natprobe Registry and reserves the callers' quotas. Attach
// hands the session one client's control stream, in either order (the initiator
// typically probes before the responder has joined). From then on the session
// drives itself through created → binding → probing → summarized →
// punching(k) → confirming → closed, each state with its own deadline,
// and ends exactly once in finish, the single cleanup path shared by success,
// failure, abort, panic and shutdown. The Result is delivered to
// Config.OnResult exactly once, after every resource of the session is gone.
//
// The planning decisions are made by a plan.Planner (DefaultPlanner unless
// Config.Planner supplies one); the coordinator does not
// trust it: every decision is clamped to the per-round budget classes, the
// session and per-key budgets and the protocol limits, its targets pass
// admission (addresses natprobe verified with a return-path cookie;
// private addresses of a peer on the same LAN or behind the same upstream
// NAT; in an unverified family — NoObserver mode, or a family no observer
// covers — Direct stages to a few self-reported global addresses),
// and escalation is guarded (a round rises at most one budget class). The
// admission sets are the ones the clients build from their summaries, and
// the planner sees the views exactly as the clients receive them. Clamping
// keeps a grant within its limits but does not keep the planner's equality
// "MaxPackets = what the stages expand to". The peer_targets the
// coordinator pushes — with each go (upstream-LAN candidates every round,
// port mappings, drifted mappings) or within a round (sandwich windows,
// Inject) — are cut to what the side may still be charged and charged when
// sent, two packets a target, since the clients send them on a quota of
// their own; the audit pays a side's packets beyond its grant from that
// charge. The natprobe registration outlives the summary until the
// first confirmation: natprobe keeps observing the primary sockets, and a
// mapping that moved while punching is pushed to the peer as drift — on a
// new IP only once its client echoed the mapping's cookie in a round_result
// remap, the return-path check of the summary's endpoints. A
// round in which both clients refused every target and sent nothing ends
// the session (no_admissible_target). After every round the
// coordinator counts, per side and family, the new NAT mappings the side
// made — its grant's new (socket, destination) pairs cut to what its
// round_result reports, the peer_targets it was pushed, its sandwich,
// re-observation and anchor-refresh probes — into
// RoundOutcome.Families[].Mapped, by which the planner places the next
// seq_x_seq windows. Before the go of a round that aims at a SEQ
// side's next ports — every paired SEQ × SEQ round, others on noise
// evidence, never one natprobe found hopeless — the coordinator
// asks the side for an anchor refresh, two new mappings 60 ms apart that
// natprobe hands over, and plans the round again from them; it waits for
// a side's second probe at most refreshGap and one and a half UDP round
// trips after its first and plans with what came; round 1 asks
// with its summaries and its go carries the summary's plan re-aimed,
// predict anchors and spans only. Rounds share
// one handshake deadline, failures never escalate (the slow birthday's
// background class of a Background session — offered by SessionOptions.Mode,
// accepted by both clients — escapes the guard: wide in time, not in
// rate), and the strategy memory only promotes variants that succeeded
// before; a pair it saw connect only through the slow birthday is reported
// as background_only in the summaries and the Result.
//
// # Custom planners and memories
//
// Package plan holds the planner contract. A custom planner usually wraps
// DefaultPlanner, whose Round derives everything it needs from its input,
// and changes only what it means to:
//
//	type relayFirst struct{ plan.Planner }
//
//	// Classify sends the pairs classified rnd_x_rnd straight to the relay.
//	func (p relayFirst) Classify(in plan.ClassifyInput) plan.Classification {
//		cl := p.Planner.Classify(in)
//		if cl.PairClass == "rnd_x_rnd" {
//			cl.Reject = protocol.ReasonHardSymmetricRandom
//		}
//		return cl
//	}
//
//	co, err := coord.New(coord.Config{Planner: relayFirst{coord.DefaultPlanner()}, ...})
//
// A StrategyMemory of the caller's own gets the built-in memory's place in
// planning through its interface alone: Recommend orders the primary
// ladder, and Score says which variants proved themselves for the pair —
// which decides the memory hit, the promotion of a proven variant and
// background_only.
//
// # Concurrency
//
// Each attached control stream is framed by one reading and one writing
// goroutine. Accepted frames go into a small bounded channel per link. One session goroutine consumes both
// links' channels and their Done signals in a single select: every frame,
// every link failure and every planning step of a session runs on it, so the
// state machine sees one ordered stream of events. A session therefore has at
// most five goroutines (two per link plus the session goroutine) and none
// before its first Attach; an idle session blocks in reads and selects and is
// never woken.
//
// The session state is guarded by one mutex. Timers do not run user code: a
// session owns a single Clock timer, re-armed under the mutex to the nearest
// of its stage deadline, its next ping and pending sandwich events; the timer
// callback only changes state or wakes the session goroutine. User code — the
// Planner, StrategyMemory, natprobe.TraitsMemory, the natprobe merge, the Observer,
// OnResult, and the methods of the errors the caller's connections fail with
// — always runs outside the mutex, inside a recover boundary, and the
// result of an out-of-lock call is discarded when the session's generation
// changed meanwhile. A Planner that never returns keeps only the session
// goroutine; the stage deadline still ends the session and frees everything
// else, and Done waits for that goroutine. The Clock is not user code but
// infrastructure, injected for tests and simulation: it is called directly,
// under the mutex too, and must not panic.
//
// Frames are queued in decision order under the mutex: punch_start precedes
// ping#1, a summary precedes the first go, the two go frames of a round are
// queued in one critical section, and an abort is the last frame of a link.
//
// # Ownership
//
// A control connection belongs to the session once Attach returns nil and to
// the caller otherwise; the session closes it in finish. Attach returns an
// error only while it has not touched the stream; once the stream is wrapped
// it is the session's, and a failure from then on ends the session with
// internal. The natprobe registration, the quota reservations, the index entry, the
// timer, the session context and the parent-context registration are owned
// by the session and released by finish. finish closes the session before it
// works anything out, and runs every release step, and every link's close, in
// a recover boundary of its own, after the step's fault point rather than
// behind it: no failure, of another step or of its own point, keeps a
// resource. A session holds a reference for finish, for its goroutine, for
// each Attach in progress and for each timer call; each is dropped on every
// path, a panic included, and Done is closed by the last one, when finish has
// completed and every goroutine of the session has returned.
//
// Every entry point is a recover boundary: a panic in New, NewSession,
// Attach or Close becomes an error (Close's once the shutdown is complete),
// one in Abort or in a timer or context callback ends the session with
// internal, and none reaches a caller or a goroutine without one. A session
// that fails after it went live during NewSession is ended before NewSession
// returns the error.
//
// The Coordinator owns the housekeeping goroutine (quota table, strategy
// memory sweeping every 10 s) and, when an Observer is set, one
// event dispatcher with a bounded queue. Close ends every session with
// server_shutdown and joins them within 3 s; its steps have a recover
// boundary each, so a panic in one is counted and skips none of the others,
// and Close returns it as a *holepunch.PanicError. Every channel that
// signals an end — Close's, a session's quit, a link's quit — is closed in a
// defer, or before anything that could fail, on the path that ends.
//
// # Memory bounds
//
// Everything the coordinator keeps that grows with its input has a cap that
// cannot be removed: the session index (Limits.MaxSessions), the per-key
// quota table (Limits.MaxKeys, fixed-size entries; a new key in a full table
// evicts the entry idle the longest, and with every entry in use NewSession
// fails with ErrBusy), the event queue (Limits.ObserverQueue), the strategy
// memory (StrategyMemoryConfig.MaxEntries) and natprobe's own tables. Within
// a session every list is bounded by a constant or by the round count
// (at most 8): views (12 endpoints a family), admission sets, evidence,
// punch-time mappings (16 a side), queued peer_targets (4 port-mapping and
// 4 drift assists a side), upstream-LAN candidates (4 a side and family),
// drifted mappings, remap echoes (one a side and family), the Direct
// targets each side has sent (the targets of at most 8 rounds), sandwich
// events (8), warnings (8) and the timeline.
//
// coord depends on protocol, natprobe, clock and internal packages; it never
// links the client root package, the port mapper or golang.org/x/net.
package coord

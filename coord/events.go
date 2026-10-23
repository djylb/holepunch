package coord

import (
	"context"
	"net/netip"
	"time"

	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// EventKind is the kind of an Event.
type EventKind uint8

// Event kinds.
const (
	EvCreated        EventKind = iota + 1
	EvAttached                 // Role; Data: AttachedData
	EvReported                 // Role
	EvPlanned                  // Data: PlannedData
	EvGo                       // Round; Data: GoData
	EvRoundEnded               // Round; Data: RoundEndedData
	EvConfirmed                // Role, Round; Data: protocol.PathInfo
	EvPeerTargets              // Role (receiver), Round; Data: PeerTargetsData
	EvProgress                 // Role; Data: ProgressData (only with Config.ObserveProgress)
	EvRateLimited              // Data: RateLimitedData
	EvPlanClamped              // Round; Data: PlanClampedData
	EvTargetRejected           // Round; Data: TargetRejectedData
	EvInternalError            // Detail: location; Data: PanicInfo
	EvClosed                   // Result
)

var evNames = [...]string{"", "created", "attached", "reported", "planned", "go", "round_ended", "confirmed",
	"peer_targets", "progress", "rate_limited", "plan_clamped", "target_rejected", "internal_error", "closed"}

// String returns the event name.
func (k EventKind) String() string {
	if int(k) < len(evNames) && k != 0 {
		return evNames[k]
	}
	return "unknown"
}

// Event is an observation of a session. Events of one session are delivered
// in order; the queue drops events it cannot hold, so an Observer must not
// rely on seeing every one (the reliable end is Config.OnResult).
type Event struct {
	Kind      EventKind
	At        time.Time
	SessionID string
	Role      protocol.Role
	Round     int
	Reason    protocol.Reason
	Detail    string
	Labels    map[string]string // shared, read only
	Result    *Result           // EvClosed only
	Data      any               // the Kind's data type
}

// AttachedData is the data of EvAttached.
type AttachedData struct {
	ClientKey string
}

// PlannedData is the data of EvPlanned.
type PlannedData struct {
	PairClass string
	Variant   string // round 1
	Budget    protocol.BudgetClass
	MemoryHit bool
	Rejected  protocol.Reason
	Transport string
}

// GoData is the data of EvGo.
type GoData struct {
	Delay   [2]time.Duration
	RTT     [2]time.Duration
	Variant string
	Budget  protocol.BudgetClass
	Granted [2]int
	Rescue  bool
	// Sandwich are, by role, the families whose sandwich probe runs this
	// round.
	Sandwich [2][]protocol.Family
}

// RoundEndedData is the data of EvRoundEnded.
type RoundEndedData struct {
	Sent  [2]int
	Hit   [2]bool
	Class plan.RoundClass
}

// PeerTargetsData is the data of EvPeerTargets.
type PeerTargetsData struct {
	Source  protocol.TargetSource
	Targets []netip.AddrPort
	Window  *protocol.PortWindow
}

// ProgressData is the data of EvProgress.
type ProgressData struct {
	Stage  string
	Status protocol.ProgressStatus
	Round  int
}

// RateLimitedData is the data of EvRateLimited: the refused dimension and
// the client key it concerned ("" for global limits).
type RateLimitedData struct {
	Dimension string
	Key       string
}

// PlanClampedData is the data of EvPlanClamped: a plan field the coordinator
// changed (budget classes are given by rank).
type PlanClampedData struct {
	Field    string
	From, To int64
}

// TargetRejectedData is the data of EvTargetRejected: the admission rule and
// the refused address.
type TargetRejectedData struct {
	Rule string
	Addr netip.AddrPort
}

// PanicInfo is the data of EvInternalError. The stack is for local logs only;
// it never reaches a wire frame or a Result.
type PanicInfo struct {
	Value string
	Stack []byte
}

// dispatcher delivers events to Config.Observer from one goroutine.
type dispatcher struct {
	q       chan Event
	fn      func(Event)
	dropped func()
	panics  func()
}

// emit queues ev without blocking; a full queue drops it. It may be called
// with a session lock held.
func (d *dispatcher) emit(ev Event) {
	if d == nil {
		return
	}
	select {
	case d.q <- ev:
	default:
		d.dropped()
	}
}

// run delivers events until ctx ends, then delivers what is already queued.
func (d *dispatcher) run(ctx context.Context) {
	for {
		select {
		case ev := <-d.q:
			d.deliver(ev)
		case <-ctx.Done():
			for {
				select {
				case ev := <-d.q:
					d.deliver(ev)
				default:
					return
				}
			}
		}
	}
}

func (d *dispatcher) deliver(ev Event) {
	// Not Coordinator.callout: a panic of the observer is counted, never
	// reported to it as an event.
	if callout("coord.observer", fiCallback, func() { d.fn(ev) }) != nil {
		d.panics()
	}
}

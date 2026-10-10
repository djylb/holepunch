package nat

import (
	"net/netip"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Probe phases, the second byte of the SANDWICH TLV: the sandwich's two
// probes and the anchor refresh's two, each of the latter from a new
// socket of its own.
const (
	SandwichBefore uint8 = 0
	SandwichAfter  uint8 = 1
	RefreshFirst   uint8 = 2
	RefreshSecond  uint8 = 3
)

// SandwichEvent is an accepted sandwich probe as natprobe saw it, delivered
// to the coordinator.
type SandwichEvent struct {
	Role     protocol.Role  // sender role
	Round    uint8          // SANDWICH round
	Phase    uint8          // SandwichBefore, SandwichAfter, RefreshFirst or RefreshSecond
	Observed netip.AddrPort // the probe's source: the helper socket's new mapping
	At       time.Time      // natprobe receive time (Registry clock)
}

// AttachSandwichSink sets the sandwich event sink of a natprobe session; h
// must be a *natprobe.Handle and anything else is ignored. natprobe assigns
// the variable in its init and coord calls it; it stays nil in a
// binary without natprobe.
//
// A natprobe reader calls the sink after it has answered the probe, outside
// every lock and inside a recover boundary, at most one call at a time per
// session; events queued before the sink was attached are delivered by
// AttachSandwichSink itself, on the caller's goroutine, so the caller must
// not hold a lock the sink takes. The sink must not block (coord: bounded
// append and timer.Reset(0)).
var AttachSandwichSink func(h any, sink func(SandwichEvent))

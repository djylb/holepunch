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

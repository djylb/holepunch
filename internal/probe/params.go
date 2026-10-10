package probe

import "time"

// defaultTimeout is the default probing hard limit, timeouts.probe_timeout_ms.
const defaultTimeout = 2000 * time.Millisecond

// Timing parameters.
const (
	minTimeout = 500 * time.Millisecond // probe_timeout_ms range
	maxTimeout = 10 * time.Second

	defaultRTT = 100 * time.Millisecond // RTT0 without rtt_hint_ms
	maxRTTHint = 5 * time.Second        // a larger hint is a coordinator bug, not a link

	minT1, maxT1   = 80 * time.Millisecond, 400 * time.Millisecond // T1 = clamp(1.5·RTT + 20 ms)
	t1Base         = 20 * time.Millisecond
	minExtraWait   = 80 * time.Millisecond // extraWait = clamp(RTT/2 + 60 ms)
	maxExtraWait   = 250 * time.Millisecond
	extraWaitBase  = 60 * time.Millisecond
	stashTTL       = 250 * time.Millisecond // an extra that arrives before its ack waits this long
	stunGrace      = 150 * time.Millisecond // STUN may hold DONE back this long after mappingDone
	hairpinGap     = 100 * time.Millisecond // between the two hairpin packets
	hairpinWindow  = 250 * time.Millisecond // from the first hairpin packet
	mappingRounds  = 3                      // mappingDone: ≥ 2 answers and 3·T1 since the first send
	settleRounds   = 2                      // second socket, alt and top-up settle after 2·T1
	blockedStreaks = 2                      // rounds of failed sends or ICMP before udp_blocked
)

// Packet budgets.
const (
	maxPrimarySends = 4  // per main observer: the first send and 3 retransmissions
	maxOtherSends   = 2  // second socket, sibling, alt, STUN: the first send and 1 retransmission
	maxSiblings     = 2  // sibling sockets probed
	maxSTUNServers  = 2  // STUN servers used
	serverBudget    = 25 // probes to the server per family: primary 13 + second 6 + alt 2 + siblings 4
	stunBudget      = 4  // STUN requests per family
)

// Inbox and stash bounds.
const (
	inboxCap = 64 // delivered replies waiting for the prober goroutine
	maxStash = 16 // extras waiting for their ack
)

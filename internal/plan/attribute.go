package plan

import (
	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

// icmpUnreachThreshold is the per-round aggregate at which ICMP soft-signals
// mark a blocked path.
const icmpUnreachThreshold = 50

// Attribute returns the failure Reason for a finished, unconfirmed punch from
// the accumulated Evidence. It is
// the pure function the client and the coordinator share; the coordinator
// feeds it both sides' evidence, so it can tell the direction of a one-way
// result. The pair-class specific refinement (hard_symmetric_random only when
// both sides are RND) is applied by the caller via TerminalReason, so Attribute
// never hard-codes a terminal code.
func Attribute(ev api.Evidence) protocol.Reason {
	r, _ := AttributeDetail(ev)
	return r
}

// AttributeDetail returns the Reason and the detail string (the one-way
// direction, icmp_unreachable, ...). Evidence is indexed by role
// (0 = initiator, 1 = responder).
func AttributeDetail(ev api.Evidence) (protocol.Reason, string) {
	// Both sides report a blocked UDP path (local write failures).
	if ev.Fatal[0] == protocol.ReasonUDPBlocked && ev.Fatal[1] == protocol.ReasonUDPBlocked {
		return protocol.ReasonUDPBlocked, ""
	}

	// A direction works when the receiving side got a packet, or the server
	// relayed a peer_seen proving it. PeerSeenUs[0] means a peer_seen about the
	// initiator arrived (the responder saw the initiator -> initiator->responder
	// works); PeerSeenUs[1] is the reverse. Reading PeerSeenUs lets the client
	// reach the one-way conclusion from its own evidence alone.
	seenI := ev.Hit[0] || len(ev.SeenFrom[0]) > 0 // initiator received (responder->initiator works)
	seenR := ev.Hit[1] || len(ev.SeenFrom[1]) > 0 // responder received (initiator->responder works)
	toInit := seenI || ev.PeerSeenUs[1]           // responder->initiator path works
	toResp := seenR || ev.PeerSeenUs[0]           // initiator->responder path works

	switch {
	case toInit && !toResp:
		if seenI {
			return protocol.ReasonOneWayUDPOnly, "initiator_hears_responder"
		}
		return protocol.ReasonOneWayUDPOnly, "we_hear_peer"
	case toResp && !toInit:
		if seenR {
			return protocol.ReasonOneWayUDPOnly, "responder_hears_initiator"
		}
		return protocol.ReasonOneWayUDPOnly, "peer_hears_us"
	}

	if !toInit {
		// Past the one-way cases toResp equals toInit: nothing reached
		// either way (RxVerified == 0).
		if ev.BudgetHit[0] || ev.BudgetHit[1] {
			return protocol.ReasonPacketBudgetExceeded, ""
		}
		// Neither side emitted an active packet, or a side never fired.
		if (ev.Sent[0] == 0 && ev.Sent[1] == 0) || !ev.Fired[0] || !ev.Fired[1] {
			return protocol.ReasonNotSynchronized, ""
		}
		if ev.ICMPUnreach[0] >= icmpUnreachThreshold || ev.ICMPUnreach[1] >= icmpUnreachThreshold {
			return protocol.ReasonCandidateTimeout, "icmp_unreachable"
		}
		return protocol.ReasonCandidateTimeout, ""
	}

	// Both directions carried traffic but no confirmation.
	return protocol.ReasonCandidateTimeout, ""
}

// TerminalReason is the stop reason once a ladder is exhausted: Attribute
// from the evidence, except that the plain
// candidate_timeout becomes hard_symmetric_random only when both sides are RND.
func TerminalReason(ev api.Evidence, bothRND bool) protocol.Reason {
	r, detail := AttributeDetail(ev)
	if r == protocol.ReasonCandidateTimeout && detail == "" && bothRND {
		return protocol.ReasonHardSymmetricRandom
	}
	return r
}

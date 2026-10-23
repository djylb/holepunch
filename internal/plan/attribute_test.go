package plan

import (
	"net/netip"
	"testing"

	api "github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestAttributeTable(t *testing.T) {
	src := []netip.AddrPort{ap("203.0.113.9:40000")}
	cases := []struct {
		name   string
		ev     api.Evidence
		reason protocol.Reason
		detail string
	}{
		{"both_blocked", api.Evidence{Fatal: [2]protocol.Reason{protocol.ReasonUDPBlocked, protocol.ReasonUDPBlocked}}, protocol.ReasonUDPBlocked, ""},
		{"one_way_init_hears", api.Evidence{Hit: [2]bool{true, false}, SeenFrom: [2][]netip.AddrPort{src, nil}}, protocol.ReasonOneWayUDPOnly, "initiator_hears_responder"},
		{"one_way_resp_hears", api.Evidence{Hit: [2]bool{false, true}, SeenFrom: [2][]netip.AddrPort{nil, src}}, protocol.ReasonOneWayUDPOnly, "responder_hears_initiator"},
		{"budget", api.Evidence{BudgetHit: [2]bool{true, false}, Fired: [2]bool{true, true}, Sent: [2]uint32{40, 40}}, protocol.ReasonPacketBudgetExceeded, ""},
		{"not_sync_no_send", api.Evidence{Fired: [2]bool{true, true}}, protocol.ReasonNotSynchronized, ""},
		{"not_sync_no_fire", api.Evidence{Sent: [2]uint32{40, 40}, Fired: [2]bool{true, false}}, protocol.ReasonNotSynchronized, ""},
		{"icmp", api.Evidence{Sent: [2]uint32{40, 40}, Fired: [2]bool{true, true}, ICMPUnreach: [2]uint16{80, 0}}, protocol.ReasonCandidateTimeout, "icmp_unreachable"},
		{"candidate_default", api.Evidence{Sent: [2]uint32{40, 40}, Fired: [2]bool{true, true}}, protocol.ReasonCandidateTimeout, ""},
		{"both_seen", api.Evidence{Hit: [2]bool{true, true}, SeenFrom: [2][]netip.AddrPort{src, src}}, protocol.ReasonCandidateTimeout, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, d := AttributeDetail(c.ev)
			if r != c.reason || d != c.detail {
				t.Fatalf("Attribute = %s/%q, want %s/%q", r, d, c.reason, c.detail)
			}
		})
	}
}

// Attribute reads PeerSeenUs, so a client whose packets reached the peer
// (but received nothing) reports one_way_udp_only(peer_hears_us), not
// candidate_timeout.
func TestAttributePeerSeenUs(t *testing.T) {
	ev := api.Evidence{Sent: [2]uint32{40, 0}, Fired: [2]bool{true, true}, PeerSeenUs: [2]bool{true, false}}
	r, d := AttributeDetail(ev)
	if r != protocol.ReasonOneWayUDPOnly || d != "peer_hears_us" {
		t.Fatalf("got %s/%q, want one_way_udp_only/peer_hears_us", r, d)
	}
	// PeerSeenUs[1]: a peer_seen about the responder arrived (initiator saw it),
	// but nothing was received locally -> responder->initiator one-way,
	// detail we_hear_peer.
	ev2 := api.Evidence{Fired: [2]bool{true, true}, PeerSeenUs: [2]bool{false, true}}
	if r, d := AttributeDetail(ev2); r != protocol.ReasonOneWayUDPOnly || d != "we_hear_peer" {
		t.Fatalf("got %s/%q, want one_way_udp_only/we_hear_peer", r, d)
	}
}

// hard_symmetric_random only when both sides are RND; otherwise
// candidate_timeout.
func TestTerminalReasonBothRND(t *testing.T) {
	ev := api.Evidence{Sent: [2]uint32{40, 40}, Fired: [2]bool{true, true}}
	if r := TerminalReason(ev, true); r != protocol.ReasonHardSymmetricRandom {
		t.Errorf("both RND -> %s, want hard_symmetric_random", r)
	}
	if r := TerminalReason(ev, false); r != protocol.ReasonCandidateTimeout {
		t.Errorf("not both RND -> %s, want candidate_timeout", r)
	}
	// an evidence-driven reason is never overwritten by the RND refinement.
	oneWay := api.Evidence{Hit: [2]bool{true, false}, SeenFrom: [2][]netip.AddrPort{{ap("203.0.113.9:1")}, nil}}
	if r := TerminalReason(oneWay, true); r != protocol.ReasonOneWayUDPOnly {
		t.Errorf("one-way with bothRND -> %s, want one_way_udp_only", r)
	}
}

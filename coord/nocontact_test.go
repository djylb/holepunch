package coord

import (
	"net/netip"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// TestFamilyNoContact checks what the coordinator tells the planner about a
// family's round (FamilyRound.NoContact): no contact only when both
// results show neither a hit nor a peer source, nor a blocked path or a
// fatal write failure, in that family.
func TestFamilyNoContact(t *testing.T) {
	quiet := func() *protocol.RoundResult {
		return &protocol.RoundResult{Status: protocol.RoundWindowEnd, Families: []protocol.FamilyOutcome{
			{Family: protocol.FamilyUDP4}, {Family: protocol.FamilyUDP6}}}
	}
	if !familyNoContact([2]*protocol.RoundResult{quiet(), quiet()}, protocol.FamilyUDP4) {
		t.Fatal("two silent results")
	}
	if familyNoContact([2]*protocol.RoundResult{quiet(), nil}, protocol.FamilyUDP4) {
		t.Fatal("a missing result")
	}
	seen := quiet()
	seen.Families[1].SeenFrom = []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:4000")}
	if familyNoContact([2]*protocol.RoundResult{quiet(), seen}, protocol.FamilyUDP6) ||
		!familyNoContact([2]*protocol.RoundResult{quiet(), seen}, protocol.FamilyUDP4) {
		t.Fatal("contact in one family is that family's")
	}
	hit := quiet()
	hit.Families[0].Hit = true
	blocked := quiet()
	blocked.Families[0].ICMPUnreach = icmpBlocked
	fatal := quiet()
	fatal.Status, fatal.Reason = protocol.RoundFatal, protocol.ReasonUDPBlocked
	for name, r := range map[string]*protocol.RoundResult{"hit": hit, "blocked": blocked, "fatal": fatal} {
		if familyNoContact([2]*protocol.RoundResult{r, quiet()}, protocol.FamilyUDP4) {
			t.Errorf("%s counted as no contact", name)
		}
	}
	// Who heard whom, per family (FamilyRound.Heard).
	if h := familyHeard([2]*protocol.RoundResult{hit, seen}, protocol.FamilyUDP4); h != [2]bool{true, false} {
		t.Errorf("udp4 heard %v", h)
	}
	if h := familyHeard([2]*protocol.RoundResult{hit, seen}, protocol.FamilyUDP6); h != [2]bool{false, true} {
		t.Errorf("udp6 heard %v", h)
	}
	if h := familyHeard([2]*protocol.RoundResult{nil, quiet()}, protocol.FamilyUDP4); h != [2]bool{} {
		t.Errorf("silent heard %v", h)
	}
}

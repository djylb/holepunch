package protocol_test

import (
	"testing"

	"github.com/djylb/holepunch/internal/clonetest"
	"github.com/djylb/holepunch/protocol"
)

// TestCloneDeep fills every field of each cloned type, rewrites the
// original through its pointers, slices and maps after Clone, and checks
// that the copy kept its values.
func TestCloneDeep(t *testing.T) {
	clonetest.Check(t, protocol.Policy.Clone)
	clonetest.Check(t, protocol.PortMappingPolicy.Clone)
	clonetest.Check(t, protocol.ControlSpec.Clone)
	clonetest.Check(t, protocol.ProbeSpec.Clone)
	clonetest.Check(t, protocol.PunchStart.Clone)
	clonetest.Check(t, protocol.PeerView.Clone)
	clonetest.Check(t, protocol.FamilyView.Clone)
	clonetest.Check(t, protocol.PairFacts.Clone)
	clonetest.Check(t, protocol.PlanSpec.Clone)
	clonetest.Check(t, protocol.RoundPlan.Clone)
	clonetest.Check(t, protocol.FamilySide.Clone)
	clonetest.Check(t, protocol.Stage.Clone)
}

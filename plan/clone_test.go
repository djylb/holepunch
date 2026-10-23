package plan

import (
	"testing"

	"github.com/djylb/holepunch/internal/clonetest"
)

// TestCloneDeep fills every field of each cloned type, rewrites the original
// through its pointers, slices and maps after Clone, and checks that the
// copy kept its values.
func TestCloneDeep(t *testing.T) {
	clonetest.Check(t, ClassifyInput.Clone)
	clonetest.Check(t, Classification.Clone)
	clonetest.Check(t, Evidence.Clone)
	clonetest.Check(t, RoundOutcome.Clone)
	clonetest.Check(t, RoundInput.Clone)
	clonetest.Check(t, RoundDecision.Clone)
}

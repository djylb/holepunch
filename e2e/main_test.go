package e2e

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain checks that no goroutine outlives the suite.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

package e2e

import (
	"fmt"
	"os"
	"testing"

	"github.com/djylb/holepunch/internal/goroutines"
)

// TestMain refuses an invalid suite configuration and checks that no
// goroutine outlives the suite.
func TestMain(m *testing.M) {
	if _, err := loadSuite(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "e2e:", err)
		os.Exit(2)
	}
	goroutines.VerifyTestMain(m)
}

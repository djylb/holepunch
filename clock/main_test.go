package clock_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/djylb/holepunch/internal/goroutines"
)

func TestMain(m *testing.M) {
	goroutines.VerifyTestMain(m)
}

// recorder is a Reporter that keeps the failures instead of failing the test,
// so tests can assert on what the Fake reports.
type recorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

func (r *recorder) messages() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.msgs...)
}

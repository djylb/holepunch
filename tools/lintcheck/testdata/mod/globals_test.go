package mod

import (
	"testing"
	"time"
)

// Test files are not reported, but their writes make a variable mutable.
func TestHook(t *testing.T) {
	old := hook
	hook = func() {}
	defer func() { hook = old }()
	go func() {}()
	time.Sleep(time.Millisecond)
}

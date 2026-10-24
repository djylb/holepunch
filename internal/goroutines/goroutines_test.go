package goroutines

import (
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) { VerifyTestMain(m) }

// TestFind: a goroutine started after IgnoreCurrent is reported with its
// stack while it runs, and no longer once it ended.
func TestFind(t *testing.T) {
	base := IgnoreCurrent()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		parkedForTest(stop)
	}()
	err := Find(base, func(o *findOptions) { o.wait = 50 * time.Millisecond })
	if err == nil || !strings.Contains(err.Error(), "parkedForTest") {
		t.Fatalf("a running goroutine: %v", err)
	}
	close(stop)
	<-done
	if err := Find(base); err != nil {
		t.Fatal(err)
	}
}

func parkedForTest(stop chan struct{}) { <-stop }

// TestParse: the id and the running function, without its arguments.
func TestParse(t *testing.T) {
	g, ok := parseGoroutine("goroutine 42 [chan receive]:\ntesting.(*T).Run(0xc000102000, {0x1, 0x2}, 0x3)\n\t/go/src/testing/testing.go:1\n")
	if !ok || g.id != 42 || g.top != "testing.(*T).Run" || !g.expected() {
		t.Fatalf("%+v %v", g, ok)
	}
	if _, ok := parseGoroutine("garbage"); ok {
		t.Fatal("parsed garbage")
	}
}

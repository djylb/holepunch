package standalone

import (
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// TestOSNetwork: ListenTCP and DialTCP reach each other on loopback.
func TestOSNetwork(t *testing.T) {
	l, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback TCP:", err)
	}
	defer func() { _ = l.Close() }()
	accepted := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			_, err = io.WriteString(c, "hi")
			_ = c.Close()
		}
		accepted <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialTCP(ctx, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "hi" {
		t.Fatalf("%q %v", b, err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

// TestDependencies guards the module's dependency rules: the client side
// never links the server side, proto stays on the standard library and
// internal/life, and the broker and server never link the client runtime.
func TestDependencies(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list")
	}
	const mod = "github.com/djylb/holepunch"
	deps := func(pkg string) []string {
		t.Helper()
		out, err := exec.Command("go", "list", "-deps", "-json=ImportPath,Standard", "./"+pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		var list []string
		dec := json.NewDecoder(strings.NewReader(string(out)))
		for dec.More() {
			var p struct {
				ImportPath string
				Standard   bool
			}
			if err := dec.Decode(&p); err != nil {
				t.Fatal(err)
			}
			if !p.Standard {
				list = append(list, p.ImportPath)
			}
		}
		return list
	}
	forbid := func(pkg string, bad ...string) {
		t.Helper()
		for _, d := range deps(pkg) {
			for _, b := range bad {
				if d == b || strings.HasPrefix(d, b+"/") {
					t.Errorf("%s links %s", pkg, d)
				}
			}
		}
	}
	server := []string{mod + "/coord", mod + "/natprobe", mod + "/standalone/broker", mod + "/standalone/server"}
	for _, pkg := range []string{"client", "quicforward", "cmd/holepunch", "cmd/holepunch-diag"} {
		forbid(pkg, server...)
	}
	forbid("broker", mod+"/standalone/client", mod+"/standalone/server", "github.com/quic-go")
	forbid("server", mod+"/standalone/client", "github.com/quic-go")
	for _, d := range deps("proto") {
		if d != mod+"/standalone/proto" && d != mod+"/internal/life" {
			t.Errorf("proto links %s", d)
		}
	}
	for _, d := range deps("cmd/holepunchd") {
		if d == mod || strings.HasPrefix(d, "github.com/quic-go") || d == mod+"/standalone/client" {
			t.Errorf("holepunchd links %s", d)
		}
	}
}

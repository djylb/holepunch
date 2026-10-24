package clientcfg

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/standalone/internal/tlsid"
)

func TestMain(m *testing.M) { goroutines.VerifyTestMain(m) }

func parse(t *testing.T, args ...string) *Flags {
	t.Helper()
	var f Flags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Register(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return &f
}

func TestConfig(t *testing.T) {
	_, pin, err := tlsid.New("x", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := parse(t, "-server", "hp.example:4343", "-pin", pin, "-auth-token", "tok", "-local-ip", "192.0.2.1", "-local-interface", "en0", "-portmap", "-exclude-overlay")
	cfg, cleanup, err := f.Config(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if cfg.Server != "hp.example:4343" || cfg.AuthToken != "tok" || cfg.Session.LocalAddr.String() != "192.0.2.1" ||
		cfg.Session.PortMapper == nil || cfg.Session.LocalInterface != "en0" || !cfg.Session.ExcludeOverlay || !cfg.TLS.InsecureSkipVerify || cfg.TLS.VerifyConnection == nil {
		t.Fatalf("config %+v", cfg)
	}

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("no certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{},
		{"-server", "h:1", "-pin", "zz"},
		{"-server", "h:1", "-pin", pin, "-ca", empty},
		{"-server", "h:1", "-ca", empty},
		{"-server", "h:1", "-ca", filepath.Join(dir, "missing.pem")},
		{"-server", "h:1", "-local-ip", "nope"},
	} {
		if _, cleanup, err := parse(t, args...).Config(nil); err == nil {
			t.Errorf("%v accepted", args)
		} else {
			cleanup()
		}
	}
	cfg, cleanup2, err := parse(t, "-server", "h:1").Config(nil)
	if err != nil {
		t.Fatalf("system roots: %v", err)
	}
	cleanup2()
	if cfg.TLS.InsecureSkipVerify || cfg.Session.PortMapper != nil {
		t.Fatalf("system roots: %+v", cfg.TLS)
	}
}

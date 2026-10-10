package tlsid

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/nattest"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func TestNewAndPin(t *testing.T) {
	cert, pin, err := New("example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "example.test" || leaf.NotAfter.Before(time.Now().Add(50*time.Minute)) || leaf.NotBefore.After(time.Now()) {
		t.Fatalf("certificate %v %v..%v", leaf.Subject, leaf.NotBefore, leaf.NotAfter)
	}
	if pin != Pin(cert.Certificate[0]) || len(pin) != 64 {
		t.Fatalf("pin %q", pin)
	}
	_, other, _ := New("example.test", time.Hour)
	if other == pin {
		t.Fatal("two identities share a pin")
	}
}

func TestParsePin(t *testing.T) {
	_, pin, _ := New("x", time.Hour)
	colons := strings.ToUpper(pin[:2]) + ":" + pin[2:]
	for _, in := range []string{pin, " " + strings.ToUpper(pin) + " ", colons} {
		if got, err := ParsePin(in); err != nil || got != pin {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "zz", pin[:62], pin + "00"} {
		if _, err := ParsePin(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// TestVerifyPin: a TLS handshake succeeds only against the pinned
// certificate.
func TestVerifyPin(t *testing.T) {
	cert, pin, err := New("server.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPin, _ := New("server.test", time.Hour)
	// TLS needs buffered streams: over net.Pipe the client's change cipher
	// spec and the server's first flight would wait for each other.
	n := nattest.NewNetwork()
	defer func() { _ = n.Close() }()
	for want, ok := range map[string]bool{pin: true, otherPin: false} {
		a, b := n.Pipe(nattest.PipeConfig{})
		srv := tls.Server(b, &tls.Config{Certificates: []tls.Certificate{cert}})
		done := make(chan error, 1)
		go func() { done <- srv.Handshake() }()
		cl := tls.Client(a, &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: VerifyPin(want)})
		err := cl.Handshake()
		_ = a.Close()
		_ = b.Close()
		<-done
		if (err == nil) != ok {
			t.Fatalf("pin match %v: %v", ok, err)
		}
		if !ok && !errors.Is(err, ErrPin) {
			t.Fatalf("error %v", err)
		}
	}
	if err := VerifyPin(pin)(nil, nil); !errors.Is(err, ErrPin) {
		t.Fatal("no certificate accepted")
	}
}

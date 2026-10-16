package tlsid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// New returns a fresh self-signed ECDSA P-256 certificate for name, valid
// from an hour ago (clock skew) for validity, and its pin.
func New(name string, validity time.Duration) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, Pin(der), nil
}

// Pin returns the pin of a DER certificate.
func Pin(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ErrPin is the error of a peer whose certificate does not have the
// expected pin.
var ErrPin = errors.New("tlsid: peer certificate does not match the pin")

// ParsePin normalises a pin: 64 hex digits, colons and case ignored.
func ParsePin(s string) (string, error) {
	p := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if b, err := hex.DecodeString(p); err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("tlsid: pin %q is not a hex SHA-256", s)
	}
	return p, nil
}

// VerifyPin returns a tls.Config.VerifyConnection that accepts a peer only
// if its leaf certificate has the pin want (ParsePin form). It is meant for
// configurations whose chain verification is off (InsecureSkipVerify, or a
// server with tls.RequireAnyClientCert): the pin replaces it.
//
// It is a VerifyConnection, not a VerifyPeerCertificate: crypto/tls skips
// VerifyPeerCertificate when it resumes a session, which would accept a
// ticket from a connection to another peer without any pin check.
// VerifyConnection runs on every handshake, resumed ones included, and sees
// the certificate a resumed session carries over.
func VerifyPin(want string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return ErrPin
		}
		got := Pin(cs.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return ErrPin
		}
		return nil
	}
}

// Package tlsid makes the self-signed TLS identities of the standalone
// deployment and pins them: a certificate is identified by the SHA-256 of its
// DER encoding, written in lower-case hex, and a peer is accepted only if its
// leaf certificate has the expected pin.
//
// The package is stateless and starts no goroutine.
package tlsid

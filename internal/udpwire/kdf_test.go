package udpwire

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// rfc5869 is an independent, general HKDF-SHA256 written from RFC 5869, section 2
// (any output length, empty salt as HashLen zeros). The production code uses
// a single-block specialization; the tests hold both to the same vectors.
func rfc5869(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)
	var okm, t []byte
	for i := byte(1); len(okm) < length; i++ {
		mac = hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{i})
		t = mac.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:length]
}

func unhex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestRFC5869Reference(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	cases := []struct {
		name       string
		salt, info []byte
		okm        string
	}{
		{"A.1", unhex(t, "000102030405060708090a0b0c"), unhex(t, "f0f1f2f3f4f5f6f7f8f9"),
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
		{"A.3", nil, nil,
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(rfc5869(ikm, c.salt, c.info, 42)); got != c.okm {
			t.Errorf("RFC 5869 %s: got %s want %s", c.name, got, c.okm)
		}
	}
	// The single-block production HKDF agrees with the general one and with
	// crypto/hkdf on arbitrary inputs.
	r := newRand(1)
	for range 200 {
		tok, route := randomSession(r)
		info := make([]byte, r.IntN(64))
		for i := range info {
			info[i] = byte(r.Uint32())
		}
		got := hkdf32(tok, route, info)
		if want := rfc5869(tok[:], route[:], info, 32); !bytes.Equal(got[:], want) {
			t.Fatalf("hkdf32 = %x, RFC 5869 reference = %x", got, want)
		}
		std, err := hkdf.Key(sha256.New, tok[:], route[:], string(info), 32)
		if err != nil || !bytes.Equal(got[:], std) {
			t.Fatalf("hkdf32 = %x, crypto/hkdf = %x (%v)", got, std, err)
		}
	}
}

type kdfVector struct {
	Token     string `json:"token"`
	Route     string `json:"route"`
	Nonce     string `json:"nonce"`
	Role      string `json:"role"`
	Round     uint8  `json:"round"`
	Seed      uint32 `json:"seed"`
	KeyInfo   string `json:"key_info"`
	Key       string `json:"key"`
	MaskInput string `json:"mask_input"`
	Mask      string `json:"mask"`
	PacerInfo string `json:"pacer_info"`
	Pacer     string `json:"pacer"`
	SprayInfo string `json:"spray_info"`
	Spray     string `json:"spray"`
}

// TestKDFVectors checks key, mask, pacer and spray for token 0x00..0x1f,
// route 0x20..0x2f, nonce 0x30..0x3b, role 1, round 1, seed 0x01020304
// against testdata/kdf.json, which an independent Python implementation
// (testdata/gen_vectors.py, hmac/hashlib) produced.
func TestKDFVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "kdf.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v kdfVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	tok, route, nonce := [32]byte(unhex(t, v.Token)), [RouteSize]byte(unhex(t, v.Route)), unhex(t, v.Nonce)
	if tok != testToken() || route != testRoute() || hex.EncodeToString(nonce) != "303132333435363738393a3b" ||
		roleByName(t, v.Role) != RoleInitiator || v.Round != 1 || v.Seed != 0x01020304 {
		t.Fatalf("kdf.json inputs differ from the vector inputs: %+v", v)
	}

	// The info strings, written out here from the protocol text.
	keyInfo := []byte("holepunch/1 udp aead")
	pacerInfo := append([]byte("holepunch/1 pacer"), byte(RoleInitiator))
	sprayInfo := binary.BigEndian.AppendUint32(append([]byte("holepunch/1 spray"), byte(RoleInitiator), v.Round), v.Seed)
	maskInput := append([]byte("holepunch/1 route mask"), nonce...)
	for _, c := range []struct {
		name string
		want []byte
		got  string
	}{{"key_info", keyInfo, v.KeyInfo}, {"pacer_info", pacerInfo, v.PacerInfo}, {"spray_info", sprayInfo, v.SprayInfo}, {"mask_input", maskInput, v.MaskInput}} {
		if hex.EncodeToString(c.want) != c.got {
			t.Errorf("%s = %s, want %x", c.name, c.got, c.want)
		}
	}

	key := aeadKey(tok, route)
	pacer := PacerSeed(tok, route, RoleInitiator)
	spray := SpraySeed(tok, route, RoleInitiator, v.Round, v.Seed)
	mask := routeMask(nonce)
	sum := sha256.Sum256(maskInput)
	for _, c := range []struct {
		name      string
		prod, ref []byte
		want      string
	}{
		{"key", key[:], rfc5869(tok[:], route[:], keyInfo, 32), v.Key},
		{"pacer", pacer[:], rfc5869(tok[:], route[:], pacerInfo, 32), v.Pacer},
		{"spray", spray[:], rfc5869(tok[:], route[:], sprayInfo, 32)[:8], v.Spray},
		{"mask", mask[:RouteSize], sum[:RouteSize], v.Mask},
	} {
		if got := hex.EncodeToString(c.prod); got != c.want {
			t.Errorf("%s: udpwire %s, kdf.json %s", c.name, got, c.want)
		}
		if got := hex.EncodeToString(c.ref); got != c.want {
			t.Errorf("%s: reference %s, kdf.json %s", c.name, got, c.want)
		}
	}
}

// TestSeedSeparation checks that every derivation input changes the output:
// roles never share a pacer stream, and spray seeds differ per session, role,
// round and plan seed.
func TestSeedSeparation(t *testing.T) {
	tok, route := testToken(), testRoute()
	tok2, route2 := tok, route
	tok2[0] ^= 1
	route2[0] ^= 1

	seen := map[[32]byte]string{}
	add := func(name string, v [32]byte) {
		t.Helper()
		if prev, dup := seen[v]; dup {
			t.Errorf("%s collides with %s", name, prev)
		}
		seen[v] = name
	}
	add("key", aeadKey(tok, route))
	add("key/token", aeadKey(tok2, route))
	add("key/route", aeadKey(tok, route2))
	for _, role := range []Role{RoleInitiator, RoleResponder, RoleServer} {
		add(fmt.Sprint("pacer/", role), PacerSeed(tok, route, role))
	}
	add("pacer/token", PacerSeed(tok2, route, RoleInitiator))
	add("pacer/route", PacerSeed(tok, route2, RoleInitiator))

	base := SpraySeed(tok, route, RoleInitiator, 1, 7)
	for name, s := range map[string][8]byte{
		"token": SpraySeed(tok2, route, RoleInitiator, 1, 7),
		"route": SpraySeed(tok, route2, RoleInitiator, 1, 7),
		"role":  SpraySeed(tok, route, RoleResponder, 1, 7),
		"round": SpraySeed(tok, route, RoleInitiator, 2, 7),
		"seed":  SpraySeed(tok, route, RoleInitiator, 1, 8),
	} {
		if s == base {
			t.Errorf("spray seed ignores %s", name)
		}
	}
	if SpraySeed(tok, route, RoleInitiator, 1, 7) != base {
		t.Error("spray seed is not deterministic")
	}
}

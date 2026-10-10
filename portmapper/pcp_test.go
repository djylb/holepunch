package portmapper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

var testNonce = [12]byte{'p', 'c', 'p', 'n', 'o', 'n', 'c', 'e', '1', '2', '3', '4'}

func TestBuildPCPMap(t *testing.T) {
	client := netip.MustParseAddr("192.168.1.10")
	pkt := buildPCPMap(client, testNonce, 12345, netip.MustParseAddrPort("203.0.113.20:54321"), 7200)
	if len(pkt) != pcpMapMsgLen {
		t.Fatalf("len = %d, want %d", len(pkt), pcpMapMsgLen)
	}
	if pkt[0] != pcpVersion || pkt[1] != pcpOpMap {
		t.Fatalf("version/opcode = %d/%d", pkt[0], pkt[1])
	}
	if got := binary.BigEndian.Uint32(pkt[4:8]); got != 7200 {
		t.Fatalf("lifetime = %d", got)
	}
	if got := netip.AddrFrom16([16]byte(pkt[8:24])).Unmap(); got != client {
		t.Fatalf("client = %s", got)
	}
	if !bytes.Equal(pkt[24:36], testNonce[:]) || pkt[36] != pcpProtoUDP {
		t.Fatal("nonce / protocol not encoded")
	}
	if binary.BigEndian.Uint16(pkt[40:42]) != 12345 || binary.BigEndian.Uint16(pkt[42:44]) != 54321 {
		t.Fatal("ports not encoded")
	}
	if got := netip.AddrFrom16([16]byte(pkt[44:60])); got.Unmap() != netip.MustParseAddr("203.0.113.20") {
		t.Fatalf("suggested external = %s", got)
	}

	// No suggestion: IPv4 "no preference" is ::ffff:0.0.0.0 (RFC 6887, section 11.1).
	pkt = buildPCPMap(client, testNonce, 1, netip.AddrPort{}, 0)
	if got := netip.AddrFrom16([16]byte(pkt[44:60])); !got.Is4In6() || !got.Unmap().IsUnspecified() {
		t.Fatalf("no-preference external = %s, want ::ffff:0.0.0.0", got)
	}
}

func pcpReply(code pcpResultCode, nonce [12]byte, internal, ext uint16, extIP string, lifetime uint32) []byte {
	b := make([]byte, pcpMapMsgLen)
	b[0], b[1], b[3] = pcpVersion, pcpOpMap|pcpOpReply, byte(code)
	binary.BigEndian.PutUint32(b[4:8], lifetime)
	binary.BigEndian.PutUint32(b[8:12], 42)
	copy(b[24:36], nonce[:])
	b[36] = pcpProtoUDP
	binary.BigEndian.PutUint16(b[40:42], internal)
	binary.BigEndian.PutUint16(b[42:44], ext)
	ip := netip.MustParseAddr(extIP).As16()
	copy(b[44:60], ip[:])
	return b
}

func TestParsePCPMap(t *testing.T) {
	resp, ok, err := parsePCPMap(pcpReply(pcpSuccess, testNonce, 1000, 54321, "198.51.100.25", 3600), testNonce, 1000)
	if err != nil || !ok {
		t.Fatalf("parse = %v, %v", ok, err)
	}
	if resp.lifetime != 3600 || resp.external != netip.MustParseAddrPort("198.51.100.25:54321") {
		t.Fatalf("resp = %+v", resp)
	}

	other := testNonce
	other[0] ^= 1
	for name, b := range map[string][]byte{
		"other nonce":         pcpReply(pcpSuccess, other, 1000, 1, "198.51.100.25", 1),
		"other internal port": pcpReply(pcpSuccess, testNonce, 1001, 1, "198.51.100.25", 1),
		"short":               {pcpVersion, pcpOpMap | pcpOpReply},
		"request":             buildPCPMap(netip.MustParseAddr("10.0.0.1"), testNonce, 1000, netip.AddrPort{}, 1),
		"other opcode":        append([]byte{pcpVersion, pcpOpReply}, make([]byte, 58)...),
	} {
		if _, ok, err := parsePCPMap(b, testNonce, 1000); ok || err != nil {
			t.Errorf("%s: ok=%v err=%v, want ignored", name, ok, err)
		}
	}

	if _, _, err := parsePCPMap(pcpReply(pcpNotAuthorized, testNonce, 1000, 0, "0.0.0.0", 0), testNonce, 1000); err == nil || !strings.Contains(err.Error(), "NOT_AUTHORIZED") {
		t.Fatalf("NOT_AUTHORIZED: err = %v", err)
	}
	if _, _, err := parsePCPMap(pcpReply(pcpAddressMismatch, other, 1000, 0, "0.0.0.0", 0), testNonce, 1000); err != nil {
		t.Fatalf("an error answer to another request must be ignored, got %v", err)
	}
	// Header-only error answer.
	hdr := pcpReply(pcpAddressMismatch, testNonce, 1000, 0, "0.0.0.0", 0)[:pcpHeaderLen]
	if _, _, err := parsePCPMap(hdr, testNonce, 1000); err == nil || !strings.Contains(err.Error(), "ADDRESS_MISMATCH") {
		t.Fatalf("header-only error: err = %v", err)
	}
	// A NAT-PMP-only server answers version 0.
	if _, _, err := parsePCPMap([]byte{0, 0x81, 0, 1, 0, 0, 0, 0}, testNonce, 1000); !errors.Is(err, errPCPUnsupported) {
		t.Fatalf("NAT-PMP answer: err = %v, want errPCPUnsupported", err)
	}
	if _, _, err := parsePCPMap(pcpReply(pcpUnsuppVersion, testNonce, 1000, 0, "0.0.0.0", 0), testNonce, 1000); !errors.Is(err, errPCPUnsupported) {
		t.Fatalf("UNSUPP_VERSION: err = %v", err)
	}
	if got := pcpResultCode(200).String(); got != "result(200)" {
		t.Fatalf("String() = %q", got)
	}
}

func TestValidMapping(t *testing.T) {
	for _, tc := range []struct {
		ext      string
		lifetime uint32
		ok       bool
	}{
		{"198.51.100.1:5000", 60, true},
		{"10.0.0.1:5000", 60, true}, // private external addresses are reported, callers decide
		{"0.0.0.0:5000", 60, false},
		{"198.51.100.1:0", 60, false},
		{"[2001:db8::1]:5000", 60, false},
		{"198.51.100.1:5000", 0, false},
	} {
		if err := validMapping(netip.MustParseAddrPort(tc.ext), tc.lifetime); (err == nil) != tc.ok {
			t.Errorf("validMapping(%s, %d) = %v", tc.ext, tc.lifetime, err)
		}
	}
}

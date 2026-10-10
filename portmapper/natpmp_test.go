package portmapper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestNATPMPCodec(t *testing.T) {
	if got := buildNATPMPExternal(); !bytes.Equal(got, []byte{0, 0}) {
		t.Fatalf("external request = %v", got)
	}
	ext := []byte{0, 128, 0, 0, 0, 0, 0, 9, 203, 0, 113, 7}
	if a, ok, err := parseNATPMPExternal(ext); err != nil || !ok || a != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("parse external = %v %v %v", a, ok, err)
	}
	if _, _, err := parseNATPMPExternal([]byte{0, 128, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0}); err == nil || !strings.Contains(err.Error(), "network failure") {
		t.Fatalf("result 3: err = %v", err)
	}
	if _, ok, err := parseNATPMPExternal([]byte{0, 129, 0, 0}); ok || err != nil {
		t.Fatalf("other opcode: ok=%v err=%v", ok, err)
	}
	// A PCP-only server answers in PCP format.
	if _, _, err := parseNATPMPExternal(append([]byte{2, 0x80, 0, 1}, make([]byte, 20)...)); !errors.Is(err, errNATPMPUnsupported) {
		t.Fatalf("PCP answer: err = %v", err)
	}

	req := buildNATPMPMap(4000, 4001, 7200)
	if req[0] != 0 || req[1] != natpmpOpMapUDP || binary.BigEndian.Uint16(req[4:6]) != 4000 ||
		binary.BigEndian.Uint16(req[6:8]) != 4001 || binary.BigEndian.Uint32(req[8:12]) != 7200 {
		t.Fatalf("map request = %v", req)
	}
	resp := make([]byte, natpmpMapRespLen)
	resp[1] = natpmpOpReply + natpmpOpMapUDP
	binary.BigEndian.PutUint16(resp[8:10], 4000)
	binary.BigEndian.PutUint16(resp[10:12], 5000)
	binary.BigEndian.PutUint32(resp[12:16], 3600)
	if e, l, ok, err := parseNATPMPMap(resp, 4000); err != nil || !ok || e != 5000 || l != 3600 {
		t.Fatalf("parse map = %d %d %v %v", e, l, ok, err)
	}
	if _, _, ok, err := parseNATPMPMap(resp, 4001); ok || err != nil {
		t.Fatalf("other internal port: ok=%v err=%v", ok, err)
	}
	if _, _, ok, err := parseNATPMPMap(resp[:12], 4000); ok || err != nil {
		t.Fatalf("short: ok=%v err=%v", ok, err)
	}
	binary.BigEndian.PutUint16(resp[2:4], 2)
	if _, _, _, err := parseNATPMPMap(resp, 4000); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("result 2: err = %v", err)
	}
	binary.BigEndian.PutUint16(resp[2:4], 1)
	if _, _, _, err := parseNATPMPMap(resp, 4000); !errors.Is(err, errNATPMPUnsupported) {
		t.Fatalf("result 1: err = %v", err)
	}
}

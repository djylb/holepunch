package probe

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestSTUNCodec(t *testing.T) {
	txid := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	req := appendSTUNRequest(nil, txid)
	if len(req) != stunHeaderSize || !IsSTUN(req) || binary.BigEndian.Uint16(req) != stunBindingRequest {
		t.Fatalf("request % x", req)
	}
	v4 := netip.MustParseAddrPort("203.0.113.5:40000")
	v6 := netip.MustParseAddrPort("[2001:db8::7]:5000")
	cases := []struct {
		name string
		msg  []byte
		want netip.AddrPort
	}{
		{"xor v4", stunMsg(stunBindingSuccess, txid, stunAttr(attrXORMapped, addrValue(v4, true, txid))), v4},
		{"xor v6", stunMsg(stunBindingSuccess, txid, stunAttr(attrXORMapped, addrValue(v6, true, txid))), v6},
		{"mapped only", stunMsg(stunBindingSuccess, txid, stunAttr(0x8022, []byte("soft")), stunAttr(attrMappedAddress, addrValue(v4, false, txid))), v4},
		{"xor preferred", stunMsg(stunBindingSuccess, txid, stunAttr(attrMappedAddress, addrValue(v6, false, txid)), stunAttr(attrXORMapped, addrValue(v4, true, txid))), v4},
		{"first mapped kept", stunMsg(stunBindingSuccess, txid, stunAttr(attrMappedAddress, addrValue(v4, false, txid)), stunAttr(attrMappedAddress, addrValue(v6, false, txid))), v4},
	}
	for _, c := range cases {
		id, got, ok := parseSTUN(c.msg)
		if !ok || got != c.want || id != txid {
			t.Errorf("%s: %v %v %v", c.name, id, got, ok)
		}
	}
	bad := map[string][]byte{
		"request":       stunMsg(stunBindingRequest, txid, stunAttr(attrXORMapped, addrValue(v4, true, txid))),
		"no address":    stunMsg(stunBindingSuccess, txid),
		"short":         stunMsg(stunBindingSuccess, txid)[:19],
		"length beyond": append(stunMsg(stunBindingSuccess, txid, stunAttr(attrXORMapped, addrValue(v4, true, txid)))[:20], 0, 0, 0, 0),
		"attr overrun": func() []byte {
			m := stunMsg(stunBindingSuccess, txid, stunAttr(attrXORMapped, addrValue(v4, true, txid)))
			m[23] = 40
			return m
		}(),
		"bad family":  stunMsg(stunBindingSuccess, txid, stunAttr(attrXORMapped, []byte{0, 3, 0, 1, 1, 2, 3, 4})),
		"short value": stunMsg(stunBindingSuccess, txid, stunAttr(attrXORMapped, []byte{0, 1})),
		"port zero":   stunMsg(stunBindingSuccess, txid, stunAttr(attrMappedAddress, []byte{0, 1, 0, 0, 1, 2, 3, 4})),
		"unspecified": stunMsg(stunBindingSuccess, txid, stunAttr(attrMappedAddress, []byte{0, 1, 0, 9, 0, 0, 0, 0})),
		"v4-mapped unspecified": stunMsg(stunBindingSuccess, txid, stunAttr(attrMappedAddress,
			[]byte{0, 2, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0})),
		"holepunch b0": append([]byte{0x05}, make([]byte, 40)...),
		"odd length": func() []byte {
			m := stunMsg(stunBindingSuccess, txid)
			binary.BigEndian.PutUint16(m[2:], 3)
			return append(m, 1, 2, 3)
		}(),
		"too long": func() []byte {
			m := stunMsg(stunBindingSuccess, txid, make([]byte, 1600))
			return m
		}(),
	}
	for name, m := range bad {
		if _, _, ok := parseSTUN(m); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzSTUN(f *testing.F) {
	txid := [12]byte{9}
	f.Add(stunMsg(stunBindingSuccess, txid, stunAttr(attrXORMapped, addrValue(netip.MustParseAddrPort("1.2.3.4:5"), true, txid))))
	f.Add(stunMsg(stunBindingSuccess, txid, stunAttr(attrMappedAddress, addrValue(netip.MustParseAddrPort("[2001:db8::1]:5"), false, txid))))
	f.Add([]byte{1, 1, 0, 4, 0x21, 0x12, 0xA4, 0x42})
	f.Fuzz(func(t *testing.T, b []byte) {
		id, a, ok := parseSTUN(b)
		if ok && (!a.IsValid() || a.Port() == 0 || a.Addr().IsUnspecified() || a.Addr().Is4In6() || id != [12]byte(b[8:20])) {
			t.Fatalf("bad parse %v %v", id, a)
		}
		if ok != (ok && IsSTUN(b)) {
			t.Fatal("parsed a non-STUN message")
		}
	})
}

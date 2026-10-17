package stun

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestSTUNCodec(t *testing.T) {
	txid := TransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	req := AppendBindingRequest(nil, txid)
	if len(req) != HeaderSize || !IsMessage(req) || binary.BigEndian.Uint16(req) != typeBindingRequest {
		t.Fatalf("request % x", req)
	}
	v4 := netip.MustParseAddrPort("203.0.113.5:40000")
	v6 := netip.MustParseAddrPort("[2001:db8::7]:5000")
	cases := []struct {
		name string
		msg  []byte
		want netip.AddrPort
	}{
		{"xor v4", stunMsg(typeBindingSuccess, txid, stunAttr(attrXORMapped, addrValue(v4, true, txid))), v4},
		{"xor v6", stunMsg(typeBindingSuccess, txid, stunAttr(attrXORMapped, addrValue(v6, true, txid))), v6},
		{"mapped only", stunMsg(typeBindingSuccess, txid, stunAttr(0x8022, []byte("soft")), stunAttr(attrMappedAddress, addrValue(v4, false, txid))), v4},
		{"xor preferred", stunMsg(typeBindingSuccess, txid, stunAttr(attrMappedAddress, addrValue(v6, false, txid)), stunAttr(attrXORMapped, addrValue(v4, true, txid))), v4},
		{"first mapped kept", stunMsg(typeBindingSuccess, txid, stunAttr(attrMappedAddress, addrValue(v4, false, txid)), stunAttr(attrMappedAddress, addrValue(v6, false, txid))), v4},
	}
	for _, c := range cases {
		id, got, ok := ParseBindingResponse(c.msg)
		if !ok || got != c.want || id != txid {
			t.Errorf("%s: %v %v %v", c.name, id, got, ok)
		}
	}
	bad := map[string][]byte{
		"request":       stunMsg(typeBindingRequest, txid, stunAttr(attrXORMapped, addrValue(v4, true, txid))),
		"no address":    stunMsg(typeBindingSuccess, txid),
		"short":         stunMsg(typeBindingSuccess, txid)[:19],
		"length beyond": append(stunMsg(typeBindingSuccess, txid, stunAttr(attrXORMapped, addrValue(v4, true, txid)))[:20], 0, 0, 0, 0),
		"attr overrun": func() []byte {
			m := stunMsg(typeBindingSuccess, txid, stunAttr(attrXORMapped, addrValue(v4, true, txid)))
			m[23] = 40
			return m
		}(),
		"bad family":  stunMsg(typeBindingSuccess, txid, stunAttr(attrXORMapped, []byte{0, 3, 0, 1, 1, 2, 3, 4})),
		"short value": stunMsg(typeBindingSuccess, txid, stunAttr(attrXORMapped, []byte{0, 1})),
		"port zero":   stunMsg(typeBindingSuccess, txid, stunAttr(attrMappedAddress, []byte{0, 1, 0, 0, 1, 2, 3, 4})),
		"unspecified": stunMsg(typeBindingSuccess, txid, stunAttr(attrMappedAddress, []byte{0, 1, 0, 9, 0, 0, 0, 0})),
		"v4-mapped unspecified": stunMsg(typeBindingSuccess, txid, stunAttr(attrMappedAddress,
			[]byte{0, 2, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0})),
		"holepunch b0": append([]byte{0x05}, make([]byte, 40)...),
		"odd length": func() []byte {
			m := stunMsg(typeBindingSuccess, txid)
			binary.BigEndian.PutUint16(m[2:], 3)
			return append(m, 1, 2, 3)
		}(),
		"too long": func() []byte {
			m := stunMsg(typeBindingSuccess, txid, make([]byte, 1600))
			return m
		}(),
	}
	for name, m := range bad {
		if _, _, ok := ParseBindingResponse(m); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzParseBindingResponse(f *testing.F) {
	txid := TransactionID{9}
	f.Add(stunMsg(typeBindingSuccess, txid, stunAttr(attrXORMapped, addrValue(netip.MustParseAddrPort("1.2.3.4:5"), true, txid))))
	f.Add(stunMsg(typeBindingSuccess, txid, stunAttr(attrMappedAddress, addrValue(netip.MustParseAddrPort("[2001:db8::1]:5"), false, txid))))
	f.Add([]byte{1, 1, 0, 4, 0x21, 0x12, 0xA4, 0x42})
	f.Fuzz(func(t *testing.T, b []byte) {
		id, a, ok := ParseBindingResponse(b)
		if ok && (!a.IsValid() || a.Port() == 0 || a.Addr().IsUnspecified() || a.Addr().Is4In6() || id != TransactionID(b[8:20])) {
			t.Fatalf("bad parse %v %v", id, a)
		}
		if ok && (len(b) < HeaderSize || b[0] > 3) {
			t.Fatal("parsed a non-STUN message")
		}
	})
}

// STUN message builders of the codec tests.

func stunMsg(typ uint16, txid TransactionID, attrs ...[]byte) []byte {
	var body []byte
	for _, a := range attrs {
		body = append(body, a...)
	}
	m := make([]byte, HeaderSize, HeaderSize+len(body))
	binary.BigEndian.PutUint16(m[0:], typ)
	binary.BigEndian.PutUint16(m[2:], uint16(len(body)))
	binary.BigEndian.PutUint32(m[4:], MagicCookie)
	copy(m[8:], txid[:])
	return append(m, body...)
}

func stunAttr(typ uint16, v []byte) []byte {
	a := make([]byte, 4, 4+len(v)+3)
	binary.BigEndian.PutUint16(a[0:], typ)
	binary.BigEndian.PutUint16(a[2:], uint16(len(v)))
	a = append(a, v...)
	for len(a)%4 != 0 {
		a = append(a, 0)
	}
	return a
}

func addrValue(a netip.AddrPort, xor bool, txid TransactionID) []byte {
	var key [16]byte
	binary.BigEndian.PutUint32(key[:], MagicCookie)
	copy(key[4:], txid[:])
	port := a.Port()
	if xor {
		port ^= uint16(MagicCookie >> 16)
	}
	var ip []byte
	fam := byte(familyV4)
	if a.Addr().Is4() {
		b := a.Addr().As4()
		ip = b[:]
	} else {
		b := a.Addr().As16()
		ip, fam = b[:], familyV6
	}
	if xor {
		for i := range ip {
			ip[i] ^= key[i]
		}
	}
	v := []byte{0, fam, byte(port >> 8), byte(port)}
	return append(v, ip...)
}

// requestOf returns a Binding Request of n attribute bytes (a multiple of
// four).
func requestOf(n int) []byte {
	b := make([]byte, 20+n)
	binary.BigEndian.PutUint16(b, typeBindingRequest)
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	binary.BigEndian.PutUint32(b[4:], MagicCookie)
	return b
}

func TestIsMessage(t *testing.T) {
	bad := requestOf(8)
	bad[7] ^= 1
	short := requestOf(8)[:24]
	odd := requestOf(8)
	binary.BigEndian.PutUint16(odd[2:], 6)
	top := requestOf(8)
	top[0] = 0x40 // a QUIC short header's fixed bit
	for _, c := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"binding request", requestOf(8), true},
		{"empty attributes", requestOf(0), true},
		{"bad cookie", bad, false},
		{"length beyond the datagram", short, false},
		{"length not in words", odd, false},
		{"top bits set", top, false},
		{"random", []byte("0123456789012345678901234567"), false},
		{"short", requestOf(0)[:19], false},
	} {
		if got := IsMessage(c.b); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

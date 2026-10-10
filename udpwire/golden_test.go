package udpwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// typeByName and roleByName map the protocol names used in testdata to the
// package constants, so neither the vectors nor the tests spell type codes.
func typeByName(tb testing.TB, name string) Type {
	tb.Helper()
	t, ok := map[string]Type{
		"probe": TProbe, "probe_ack": TProbeAck, "probe_extra": TProbeExtra, "probe_alt": TProbeAlt,
		"hairpin": THairpin, "punch": TPunch, "success": TSuccess, "nominate": TNominate,
		"accept": TAccept, "ready": TReady, "handover_ack": THandoverAck,
	}[name]
	if !ok {
		tb.Fatalf("unknown type name %q", name)
	}
	return t
}

func roleByName(tb testing.TB, name string) Role {
	tb.Helper()
	r, ok := map[string]Role{"initiator": RoleInitiator, "responder": RoleResponder, "server": RoleServer}[name]
	if !ok {
		tb.Fatalf("unknown role name %q", name)
	}
	return r
}

type wireVector struct {
	Name     string `json:"name"`
	Token    string `json:"token"`
	Route    string `json:"route"`
	B0       byte   `json:"b0"`
	Nonce    string `json:"nonce"`
	PlainLen int    `json:"plain_len"`
	Header   struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		LowTTL  bool   `json:"low_ttl"`
		Retx    bool   `json:"retx"`
		FA      bool   `json:"fa"`
		FB      bool   `json:"fb"`
		FC      bool   `json:"fc"`
		Round   uint8  `json:"round"`
		Sock    uint8  `json:"sock"`
		Cand    uint16 `json:"cand"`
		Aux     uint16 `json:"aux"`
		Seq     uint32 `json:"seq"`
		TS      uint32 `json:"ts"`
		EchoSeq uint32 `json:"echo_seq"`
		EchoTS  uint32 `json:"echo_ts"`
	} `json:"header"`
	TLVs struct {
		Observed  string `json:"observed"`
		ExtraPort uint16 `json:"extra_port"`
		Cookie    uint32 `json:"cookie"`
		Sandwich  *struct {
			Round uint8 `json:"round"`
			Phase uint8 `json:"phase"`
		} `json:"sandwich"`
		RxCount *uint32 `json:"rx_count"`
		Slot    *uint8  `json:"slot"`
		Paths   *uint8  `json:"paths"`
	} `json:"tlvs"`
	Plaintext string `json:"plaintext"`
	Wire      string `json:"wire"`
}

func (v *wireVector) header(tb testing.TB) Header {
	x := v.Header
	return Header{
		Type: typeByName(tb, x.Type), Role: roleByName(tb, x.Role),
		LowTTL: x.LowTTL, Retx: x.Retx, FA: x.FA, FB: x.FB, FC: x.FC,
		Round: x.Round, Sock: x.Sock, Cand: x.Cand, Aux: x.Aux,
		Seq: x.Seq, TS: x.TS, EchoSeq: x.EchoSeq, EchoTS: x.EchoTS,
	}
}

func (v *wireVector) tlvs() TLVs {
	var t TLVs
	if v.TLVs.Observed != "" {
		t.Observed = netip.MustParseAddrPort(v.TLVs.Observed)
	}
	t.ExtraPort, t.Cookie = v.TLVs.ExtraPort, v.TLVs.Cookie
	if s := v.TLVs.Sandwich; s != nil {
		t.Sandwich.Round, t.Sandwich.Phase, t.Sandwich.Set = s.Round, s.Phase, true
	}
	if v.TLVs.RxCount != nil {
		t.RxCount, t.HasRx = *v.TLVs.RxCount, true
	}
	if v.TLVs.Slot != nil {
		t.Slot = *v.TLVs.Slot
	}
	if v.TLVs.Paths != nil {
		t.Paths = *v.TLVs.Paths
	}
	return t
}

func loadWireVectors(t *testing.T) []wireVector {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "wire", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no wire vectors: %v", err)
	}
	var all []wireVector
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var vs []wireVector
		if err := dec.Decode(&vs); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		all = append(all, vs...)
	}
	return all
}

// TestGoldenWire checks that Seal reproduces, byte for byte, the vectors that
// testdata/gen_vectors.py built independently (its own header/TLV encoder and
// AES-256-GCM), and Open/OpenProbe return every field. The vectors cover both
// envelopes, all 11 types, all 7 TLVs and the 53/69/1053/1069 length bounds.
func TestGoldenWire(t *testing.T) {
	vectors := loadWireVectors(t)
	types := map[Type]bool{}
	var tlvSeen tlvSet
	sizes := map[int]bool{}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			tok, route := [32]byte(unhex(t, v.Token)), [RouteSize]byte(unhex(t, v.Route))
			nonce := [NonceSize]byte(unhex(t, v.Nonce))
			want, plain := unhex(t, v.Wire), unhex(t, v.Plaintext)
			h, tl := v.header(t), v.tlvs()
			probe := h.Type == TProbe

			// Independent outer check: the vector's ciphertext opens under a
			// key derived by the reference HKDF with AAD b0 ‖ route, and the
			// probe's mroute is route ⊕ SHA-256(label ‖ nonce).
			outer := PeerOuterSize
			if probe {
				outer = ProbeOuterSize
				sum := sha256.Sum256(append([]byte("holepunch/1 route mask"), nonce[:]...))
				for i := range RouteSize {
					if want[PeerOuterSize+i] != route[i]^sum[i] {
						t.Fatalf("mroute byte %d", i)
					}
				}
			}
			ref := gcmFor(t, rfc5869(tok[:], route[:], []byte("holepunch/1 udp aead"), 32))
			got, err := ref.Open(nil, want[1:PeerOuterSize], want[outer:], append([]byte{v.B0}, route[:]...))
			if err != nil || !bytes.Equal(got, plain) || want[0] != v.B0 || !bytes.Equal(want[1:PeerOuterSize], nonce[:]) {
				t.Fatalf("vector is not self-consistent: %v", err)
			}

			c := newSessionCodec(t, tok, route, h.Role, testPad)
			r, err := c.check(&h, &tl)
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			// A dirty buffer shows that padding is written, not inherited.
			dirty := bytes.Repeat([]byte{0xEE}, maxProbePacket)[:0]
			sealed := c.sealWith(dirty, &h, &tl, r, v.B0, &nonce, v.PlainLen)
			if !bytes.Equal(sealed, want) {
				t.Fatalf("Seal\n got %x\nwant %x", sealed, want)
			}

			var gh Header
			var gt TLVs
			if e := open(c, bytes.Clone(want), probe, &gh, &gt); e != OK {
				t.Fatalf("open: %v", e)
			}
			if gh != h || gt != tl {
				t.Fatalf("open fields\n got %+v %+v\nwant %+v %+v", gh, gt, h, tl)
			}

			// The public Seal with the same length differs only in b0 and nonce.
			pub, err := c.Seal(nil, &h, &tl, v.PlainLen)
			if err != nil || len(pub) != len(want) {
				t.Fatalf("Seal: %d bytes, %v", len(pub), err)
			}
			if e := open(c, pub, probe, &gh, &gt); e != OK || gh != h || gt != tl {
				t.Fatalf("open(Seal): %v %+v %+v", e, gh, gt)
			}

			types[h.Type] = true
			tlvSeen |= r.tlvs
			sizes[len(want)] = true
		})
	}
	for _, typ := range allTypes() {
		if !types[typ] {
			t.Errorf("no vector for type %d", typ)
		}
	}
	if all := carriesObserved | carriesExtraPort | carriesCookie | carriesSandwich | carriesRxCount | carriesPathSlot | carriesPaths; tlvSeen != all {
		t.Errorf("TLV coverage %08b, want %08b", tlvSeen, all)
	}
	for _, n := range []int{MinPeerPacket, MinProbePacket, maxPeerPacket, maxProbePacket} {
		if !sizes[n] {
			t.Errorf("no vector of %d bytes", n)
		}
	}
}

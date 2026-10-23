package nat

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// FuzzClassify: any sequence of table operations classifies
// without panicking, keeps the table bounds and yields valid enumerations;
// the snapshot with the traits always passes protocol validation, and so do
// the endpoints in a summary.
func FuzzClassify(f *testing.F) {
	f.Add([]byte{0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	f.Add([]byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16"))
	f.Add([]byte{0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 2, 1, 0, 0, 1, 1, 2, 1, 0, 0, 2, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		fam := protocol.FamilyUDP4
		if len(data) > 0 && data[0]&1 == 1 {
			fam = protocol.FamilyUDP6
		}
		// addr maps three bytes onto a few public, private and odd addresses
		// of the family (and occasionally of the other one), so that the
		// operations collide often.
		addr := func(b []byte) netip.AddrPort {
			if len(b) < 3 {
				return netip.AddrPort{}
			}
			var a netip.Addr
			switch {
			case b[1]%7 == 6:
				a = netip.MustParseAddr("2001:db8::99") // wrong family for udp4
			case fam == protocol.FamilyUDP4:
				a = netip.AddrFrom4([4]byte{b[0] % 4 * 64, b[1] % 3, 0, b[2] % 5})
			default:
				a = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: b[1] % 4})
			}
			return netip.AddrPortFrom(a, binary.BigEndian.Uint16([]byte{b[2] % 3, b[0]}))
		}
		socks := []SocketMeta{
			{ID: SocketID(fam, IndexPrimary), Kind: protocol.SocketPrimary, Local: addr([]byte{1, 1, 1})},
			{ID: SocketID(fam, IndexSecond), Kind: protocol.SocketSecond, Local: addr([]byte{1, 1, 2})},
			{ID: SocketID(fam, IndexSibling), Kind: protocol.SocketSibling, Local: addr([]byte{2, 1, 1})},
		}
		var obs []Observer
		for i := range 6 {
			obs = append(obs, Observer{ID: uint8(i), Addr: addr([]byte{byte(i * 64), byte(i), byte(i)}), Group: uint8(i / 3), Alt: i == 5})
		}
		tb := NewTable(fam, socks, obs)
		for len(data) >= 6 {
			op, a, b, c := data[0], data[1], data[2], data[3:6]
			data = data[6:]
			sock := socks[int(a)%len(socks)].ID
			src := Source(1 + int(b)%5)
			k := PointKey{Socket: sock, Source: src, Observer: c[0] % 8}
			if src == SourcePeer {
				k.Peer = addr(c)
			}
			switch op % 6 {
			case 0:
				tb.NoteSent(k, uint32(c[1]), time.Duration(c[2])*time.Millisecond)
			case 1:
				tb.Record(k, addr(c), time.Duration(c[1])*time.Millisecond, time.Duration(c[2])*time.Millisecond, uint32(a))
			case 2:
				tb.RecordServer(Row{Key: k, Observed: addr(c), FirstSeq: uint32(a), Changes: b % 2, Verified: c[1]&1 == 1, FirstSent: -1})
			case 3:
				tb.AddFilter(FilterEvidence{Socket: sock, Observer: c[0] % 8, ExtraDeclared: a % 3, ExtraSeen: b % 2, AltDeclared: c[1] % 2, AltSeen: c[2] % 2})
			case 4:
				tb.NoteUnsolicitedInbound(sock, addr(c).Addr())
			case 5:
				tb.SetHairpin(protocol.Tri(a % 4))
			}
		}
		tr := tb.Classify()
		if !tr.Mapping.Valid() || !tr.Filtering.Valid() || !tr.PortAlloc.Valid() || !tr.MappingConf.Valid() ||
			!tr.FilteringConf.Valid() || !tr.PortAllocConf.Valid() || !tr.NoNAT.Valid() || !tr.CGNAT.Valid() {
			t.Fatalf("invalid traits %+v", tr)
		}
		if tr.PortRangeHi != 0 && tr.PortRangeLo > tr.PortRangeHi {
			t.Fatalf("bad pool %+v", tr)
		}
		eps := tb.Endpoints()
		if len(tb.rows) > maxRows || len(eps) > protocol.MaxEndpoints {
			t.Fatal("bounds")
		}
		_ = DisplayName(tr)
		if ClassBits(tr)>>19 != 0 {
			t.Fatal("class bits")
		}
		fr := tb.Snapshot()
		fr.Traits = tr
		if err := validReport(fr); err != nil {
			t.Fatalf("snapshot invalid: %v", err)
		}
		view := protocol.PeerView{Families: []protocol.FamilyView{{Family: fam, Traits: tr, Endpoints: eps}}}
		if err := validView(fam, view); err != nil {
			t.Fatalf("endpoints invalid: %v", err)
		}
	})
}

package udpwire

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/testkit"
)

// loopConn serves the same datagram forever without allocating.
type loopConn struct {
	queueConn
	pkt  []byte
	from net.Addr
}

func (c *loopConn) ReadFrom(p []byte) (int, net.Addr, error) { return copy(p, c.pkt), c.from, nil }

// TestZeroAllocs checks 0 allocs/op on every hot path, including
// garbage input and the DropResidual wrapper inside its window.
func TestZeroAllocs(t *testing.T) {
	if testkit.RaceEnabled {
		t.Skip("the race detector changes allocation counts")
	}
	ini, srv := newCodec(t, RoleInitiator), newCodec(t, RoleServer)
	dst := make([]byte, 0, maxProbePacket)
	scratch := make([]byte, MaxPlaintext)
	punch, probe, success := headerFor(ini, TPunch), headerFor(ini, TProbe), headerFor(ini, TSuccess)
	ack, ackTLVs := headerFor(srv, TProbeAck), tlvsFor(TProbeAck)
	successTLVs := tlvsFor(TSuccess)
	peerPkt := mustSeal(t, ini, &punch, nil)
	probePkt := mustSeal(t, ini, &probe, nil)
	var h Header
	var tl TLVs
	var w SeqWindow
	seq := uint32(0)

	clk := clock.NewFake(t, clockStart)
	resp, err := NewCodec(testToken(), testRoute(), RoleResponder, testPad, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	from := udpAddr("192.0.2.1:7")
	resp.BindPeers(from.AddrPort())
	upper := bytes.Repeat([]byte{0x09, 0x33}, 90) // b0 in range: costs a trial open
	inWindow := DropResidual(&loopConn{pkt: upper, from: from}, resp, time.Minute)
	readBuf := make([]byte, 2048)

	for name, f := range map[string]func(){
		"Seal S":                func() { _, _ = ini.Seal(dst[:0], &punch, nil, 0) },
		"Seal S with TLVs":      func() { _, _ = ini.Seal(dst[:0], &success, &successTLVs, 0) },
		"Seal P":                func() { _, _ = ini.Seal(dst[:0], &probe, nil, 0) },
		"Seal ack":              func() { _, _ = srv.Seal(dst[:0], &ack, &ackTLVs, MinAckPlaintext) },
		"Open":                  func() { _ = srv.Open(peerPkt, scratch, &h, &tl) },
		"Open nil outputs":      func() { _ = srv.Open(peerPkt, scratch, nil, nil) },
		"OpenProbe":             func() { _ = srv.OpenProbe(probePkt, scratch, &h, &tl) },
		"UnmaskRoute":           func() { _, _ = UnmaskRoute(probePkt) },
		"Precheck":              func() { _ = Precheck(peerPkt, MinPeerPacket) },
		"SeqWindow.Accept":      func() { seq++; w.Accept(seq) },
		"CheckRole":             func() { _ = ini.CheckRole(&punch) },
		"NextSeq and Now":       func() { _, _ = ini.NextSeq(), ini.Now() },
		"DropResidual (window)": func() { _, _, _ = inWindow.ReadFrom(readBuf) },
	} {
		if a := testing.AllocsPerRun(200, f); a != 0 {
			t.Errorf("%s: %.1f allocs/op", name, a)
		}
	}

	r := newRand(13)
	junk := make([]byte, maxProbePacket+16)
	if a := testing.AllocsPerRun(1000, func() {
		n := r.IntN(len(junk))
		for i := range n {
			junk[i] = byte(r.Uint32())
		}
		junk[0] = B0Min + byte(r.IntN(b0Count))
		_ = srv.Open(junk[:n], scratch, &h, &tl)
		_ = srv.OpenProbe(junk[:n], scratch, &h, &tl)
	}); a != 0 {
		t.Errorf("garbage input: %.1f allocs/op", a)
	}
}

// TestConcurrentCodec exercises the documented concurrency safety under
// -race: shared codecs sealing and opening from many goroutines, with
// BindPeers/Peers in between, never repeat a nonce or a seq.
func TestConcurrentCodec(t *testing.T) {
	ini, resp, srv := newCodec(t, RoleInitiator), newCodec(t, RoleResponder), newCodec(t, RoleServer)
	const workers, each = 8, 1000
	type sent struct {
		seq   uint32
		nonce [NonceSize]byte
	}
	results := make([][]sent, workers)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			dst := make([]byte, 0, maxProbePacket)
			for i := range each {
				typ, c := TPunch, resp
				if i%3 == 0 {
					typ, c = TProbe, srv
				}
				h := headerFor(ini, typ)
				pkt, err := ini.Seal(dst[:0], &h, nil, 0)
				if err != nil {
					t.Error(err)
					return
				}
				var gh Header
				if e := open(c, pkt, typ == TProbe, &gh, nil); e != OK || gh.Seq != h.Seq {
					t.Errorf("open: %v", e)
					return
				}
				results[w] = append(results[w], sent{h.Seq, [NonceSize]byte(pkt[1:PeerOuterSize])})
				if i == each/2 {
					resp.BindPeers(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(w)}), 1))
					_ = resp.Peers()
				}
			}
		})
	}
	wg.Wait()
	seqs, nonces := map[uint32]bool{}, map[[NonceSize]byte]bool{}
	for _, rs := range results {
		for _, s := range rs {
			if seqs[s.seq] || nonces[s.nonce] {
				t.Fatalf("seq %d or nonce %x repeated", s.seq, s.nonce)
			}
			seqs[s.seq], nonces[s.nonce] = true, true
		}
	}
	if len(seqs) != workers*each {
		t.Fatalf("%d packets, want %d", len(seqs), workers*each)
	}
}

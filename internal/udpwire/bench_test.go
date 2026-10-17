package udpwire

import (
	"testing"
	"time"
)

// Budgets: Seal S ≤ 400 ns, Seal P ≤ 700 ns,
// Open ≤ 100 ns, SeqWindow.Accept ≤ 5 ns, UnmaskRoute ≤ 300 ns, 0 allocs/op;
// natprobe ≥ 150 k probe/s per core and ≥ 1.5 M unknown-route drops/s.

func benchSeal(b *testing.B, c *Codec, h Header, t *TLVs, plainLen int) {
	dst := make([]byte, 0, maxProbePacket)
	b.ReportAllocs()
	for b.Loop() {
		var err error
		if dst, err = c.Seal(dst[:0], &h, t, plainLen); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	ini, srv := newCodec(b, RoleInitiator), newCodec(b, RoleServer)
	ack := tlvsFor(TProbeAck)
	b.Run("S/punch", func(b *testing.B) { benchSeal(b, ini, headerFor(ini, TPunch), nil, 0) })
	b.Run("P/probe", func(b *testing.B) { benchSeal(b, ini, headerFor(ini, TProbe), nil, 0) })
	b.Run("S/probe_ack", func(b *testing.B) { benchSeal(b, srv, headerFor(srv, TProbeAck), &ack, 100) })
}

// BenchmarkSealParallel: "sessions" gives every goroutine its own codec (a
// busy natprobe or client host), measuring cross-session contention;
// "one codec" shares a single session's codec (its mutex is the limit).
func BenchmarkSealParallel(b *testing.B) {
	b.Run("sessions", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			tok, route := randomSession(newRand(uint64(time.Now().UnixNano())))
			c := newSessionCodec(b, tok, route, RoleInitiator, testPad)
			h := headerFor(c, TPunch)
			dst := make([]byte, 0, maxProbePacket)
			for pb.Next() {
				dst, _ = c.Seal(dst[:0], &h, nil, 0)
			}
		})
	})
	b.Run("one codec", func(b *testing.B) {
		c := newCodec(b, RoleInitiator)
		h := headerFor(c, TPunch)
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			dst := make([]byte, 0, maxProbePacket)
			for pb.Next() {
				dst, _ = c.Seal(dst[:0], &h, nil, 0)
			}
		})
	})
}

func BenchmarkOpen(b *testing.B) {
	ini, resp := newCodec(b, RoleInitiator), newCodec(b, RoleResponder)
	punch := headerFor(ini, TPunch)
	pkt, _ := ini.Seal(nil, &punch, nil, 150) // 179 B on the wire, near the mean of the session length interval
	other, _ := newSessionCodec(b, testToken(), [RouteSize]byte{1}, RoleInitiator, testPad).Seal(nil, &punch, nil, 150)
	scratch := make([]byte, MaxPlaintext)
	var h Header
	var t TLVs
	b.Run("ok", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(pkt)))
		for b.Loop() {
			if resp.Open(pkt, scratch, &h, &t) != OK {
				b.Fatal("open")
			}
		}
	})
	b.Run("auth failure", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if resp.Open(other, scratch, &h, &t) != ErrAuth {
				b.Fatal("open")
			}
		}
	})
}

func BenchmarkOpenProbe(b *testing.B) {
	ini, srv := newCodec(b, RoleInitiator), newCodec(b, RoleServer)
	probe := headerFor(ini, TProbe)
	pkt, _ := ini.Seal(nil, &probe, nil, 120)
	scratch := make([]byte, MaxPlaintext)
	var h Header
	var t TLVs
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for b.Loop() {
		if srv.OpenProbe(pkt, scratch, &h, &t) != OK {
			b.Fatal("open")
		}
	}
}

// BenchmarkNatprobePath is natprobe's receive path for a registered route
// (UnmaskRoute, registry lookup, OpenProbe, CheckRole, SeqWindow) and for an
// unknown one (dropped after UnmaskRoute, never decrypted).
func BenchmarkNatprobePath(b *testing.B) {
	ini, srv := newCodec(b, RoleInitiator), newCodec(b, RoleServer)
	registry := map[[RouteSize]byte]*Codec{testRoute(): srv}
	probe := headerFor(ini, TProbe)
	pkt, _ := ini.Seal(nil, &probe, nil, 120)
	unknown, _ := newSessionCodec(b, testToken(), [RouteSize]byte{7}, RoleInitiator, testPad).Seal(nil, &probe, nil, 120)
	scratch := make([]byte, MaxPlaintext)
	var h Header
	var t TLVs
	var w SeqWindow
	b.Run("registered", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			route, e := UnmaskRoute(pkt)
			c := registry[route]
			if e != OK || c == nil || c.OpenProbe(pkt, scratch, &h, &t) != OK || c.CheckRole(&h) != OK {
				b.Fatal("path")
			}
			w.Accept(h.Seq)
		}
	})
	b.Run("unknown route", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if route, e := UnmaskRoute(unknown); e != OK || registry[route] != nil {
				b.Fatal("path")
			}
		}
	})
}

func BenchmarkUnmaskRoute(b *testing.B) {
	ini := newCodec(b, RoleInitiator)
	probe := headerFor(ini, TProbe)
	pkt, _ := ini.Seal(nil, &probe, nil, 120)
	b.ReportAllocs()
	for b.Loop() {
		if _, e := UnmaskRoute(pkt); e != OK {
			b.Fatal("unmask")
		}
	}
}

func BenchmarkPrecheck(b *testing.B) {
	pkt := make([]byte, 180)
	pkt[0] = B0Min + 3
	for b.Loop() {
		if Precheck(pkt, MinPeerPacket) != OK {
			b.Fatal("precheck")
		}
	}
}

func BenchmarkSeqWindow(b *testing.B) {
	b.Run("in order", func(b *testing.B) {
		var w SeqWindow
		seq := uint32(0)
		b.ReportAllocs()
		for b.Loop() {
			seq++
			w.Accept(seq)
		}
	})
	b.Run("reordered", func(b *testing.B) {
		var w SeqWindow
		seq := uint32(100)
		b.ReportAllocs()
		for b.Loop() {
			seq += 2
			w.Accept(seq)
			w.Accept(seq - 3) // a late packet inside the window
		}
	})
	b.Run("jump", func(b *testing.B) {
		var w SeqWindow
		seq := uint32(0)
		b.ReportAllocs()
		for b.Loop() {
			seq += 700 // clears many words
			w.Accept(seq)
		}
	})
}

// BenchmarkDropResidual: inside the window an upper-layer datagram whose first
// byte is in range costs one trial AEAD; afterwards only an atomic load.
func BenchmarkDropResidual(b *testing.B) {
	clk := newManualClock()
	resp, err := NewCodec(testToken(), testRoute(), RoleResponder, testPad, clk.Now)
	if err != nil {
		b.Fatal(err)
	}
	from := udpAddr("192.0.2.1:7")
	resp.BindPeers(from.AddrPort())
	upper := make([]byte, 180)
	for i := range upper {
		upper[i] = byte(i * 7)
	}
	upper[0] = B0Min + 5
	pc := DropResidual(&loopConn{pkt: upper, from: from}, resp, time.Second)
	buf := make([]byte, 2048)
	b.Run("in window", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _, _ = pc.ReadFrom(buf)
		}
	})
	clk.Advance(time.Second)
	b.Run("after window", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _, _ = pc.ReadFrom(buf)
		}
	})
}

func BenchmarkNewCodec(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := NewCodec(testToken(), testRoute(), RoleInitiator, testPad, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSpraySeed(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		SpraySeed(testToken(), testRoute(), RoleInitiator, 1, 0x01020304)
	}
}

package coord

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/protocol"
)

// fuzzOps is the number of script steps a fuzz input may run.
const fuzzOps = 48

// FuzzCoordFrames drives a session with an arbitrary script of both
// clients' frames, interleaved with clock steps and disconnects: no
// panic, OnResult exactly once, everything released at the end.
func FuzzCoordFrames(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})               // report, report, ready, ready, ...
	f.Add([]byte{0, 1, 2, 3, 12, 13, 14, 15, 16, 17, 18, 19}) // to the confirmation
	f.Add([]byte{0, 1, 2, 3, 20, 21, 30, 31, 40, 41, 50})
	f.Add([]byte{60, 61, 62, 63, 64, 65, 66, 67})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 255, 254, 22, 23})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		cx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done := make(chan struct{}, 2)
		for i := range 2 {
			go func() {
				defer func() { done <- struct{}{} }()
				for {
					if _, _, err := p.cl[i].Next(cx); err != nil {
						return
					}
				}
			}()
		}
		for n, b := range data {
			if n >= fuzzOps {
				break
			}
			i := int(b & 1)
			arg := byte(0)
			if n+1 < len(data) {
				arg = data[n+1]
			}
			fuzzStep(cx, r, p, i, b>>1, arg, data[n:])
		}
		p.s.Abort(protocol.ReasonCanceled, "fuzz end")
		res := r.wait(p.s)
		if res.SessionID != p.s.ID() || r.c.Len() != 0 || r.c.Stats().ActiveByKey != 0 {
			t.Fatalf("result %+v", res)
		}
		select {
		case <-r.results:
		case <-time.After(waitLimit):
			t.Fatal("no OnResult")
		}
		select {
		case <-r.results:
			t.Fatal("second OnResult")
		default:
		}
		_ = p.cl[0].Close()
		_ = p.cl[1].Close()
		<-done
		<-done
	})
}

// fuzzStep runs one scripted action of side i; errors are ignored, since
// the session may already have ended.
func fuzzStep(cx context.Context, r *rig, p *pair, i int, op, arg byte, rest []byte) {
	c := p.cl[i]
	id, role := p.s.ID(), roleOf(i)
	sendM := func(m protocol.Message) { _ = c.Send(cx, m) }
	round := arg%3 + 1
	switch op % 16 {
	case 0:
		rep := simclient.Report(*p.starts[i], uint32(arg), "quic", fam(i, simclient.OpenTraits))
		sendM(&rep)
	case 1:
		sendM(&protocol.PunchReady{SessionID: id, Role: role, ElapsedMs: uint32(arg),
			Families: []protocol.FamilyReady{{Family: protocol.FamilyUDP4, Sockets: 1}}})
	case 2:
		rr := simclient.RoundEnd(id, role, round, protocol.RoundWindowEnd, fired(uint32(arg)))
		sendM(&rr)
	case 3:
		m := simclient.Confirmed(id, role, round, p.path(i, round))
		sendM(&m)
	case 4:
		m := simclient.Success(id, role, p.path(i, round))
		sendM(&m)
	case 5:
		m := simclient.Failure(id, role, protocol.Reasons()[int(arg)%len(protocol.Reasons())], protocol.PhaseProbing)
		sendM(&m)
	case 6:
		sendM(&protocol.Progress{SessionID: id, Role: role, Stage: "fire", Round: round})
	case 7:
		sendM(&protocol.Pong{Seq: arg%8 + 1, HoldUs: uint32(arg) * 1000})
	case 8:
		sendM(peerSeen(p, i, round, netip.AddrPortFrom(pubR.Addr(), uint16(arg)+1)))
	case 9:
		types := []controlwire.Type{controlwire.TypeProbeReport, controlwire.TypePunchReady, controlwire.TypeProgress,
			controlwire.TypeAssist, controlwire.TypePong, controlwire.TypeRoundResult, controlwire.TypePunchResult}
		payload := rest
		if len(payload) > 200 {
			payload = payload[:200]
		}
		_ = c.SendFrame(cx, types[int(arg)%len(types)], payload)
	case 10:
		r.clk.Advance(time.Duration(arg) * 50 * time.Millisecond)
	case 11:
		if arg%8 == 0 {
			_ = c.Close()
		}
	case 12:
		rr := simclient.RoundEnd(id, role, round, protocol.RoundFatal, fired(1))
		rr.Code = protocol.ReasonUDPBlocked
		sendM(&rr)
	case 13:
		_ = p.s.Inject(roleOf(1-i), protocol.Assist{Family: protocol.FamilyUDP4, Targets: []netip.AddrPort{pubR, pubI}})
	case 14:
		p.s.Snapshot()
	default:
		r.clk.Advance(0)
	}
}

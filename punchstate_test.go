package holepunch

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// The read loops start with the probing sockets and read the punching state
// and the nomination goroutine's mailbox for every undecodable datagram;
// the summary must not replace either under them. A flood of foreign
// datagrams keeps every read loop busy from the probe_report to past
// punch_ready, so that -race sees any unsynchronised write of the summary
// against those reads.
func TestPunchStateStableUnderReadLoops(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	so.start(to)
	_, self := so.report()
	var targets []netip.AddrPort
	for _, f := range self.Families {
		for _, e := range f.Endpoints {
			targets = append(targets, e.Addr)
		}
	}
	if len(targets) == 0 {
		t.Fatal("no endpoint in the report")
	}
	fl := w.host(nil)
	conn, err := fl.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(fl.Addrs()[0], 0), "flood")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		short, foreign := []byte{0x01}, make([]byte, 64) // ErrShort, ErrForeign
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			pkt := short
			if i%2 == 1 {
				pkt = foreign
			}
			_, _ = conn.WriteTo(pkt, net.UDPAddrFromAddrPort(targets[i%len(targets)]))
			if i%4 == 3 {
				time.Sleep(200 * time.Microsecond)
			}
		}
	}()
	so.summary(self, fakePeer("203.0.113.99:4000"), to)
	_, ready := so.link.next(5*time.Second, protocol.MsgPunchReady)
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
	if !ready {
		t.Fatal("no punch_ready")
	}
	so.link.send(protocol.Abort{SessionID: so.s.sid, By: protocol.RoleServer, Reason: protocol.ReasonCanceled})
	so.wantFailure(so.result(5*time.Second), protocol.ReasonCanceled)
}

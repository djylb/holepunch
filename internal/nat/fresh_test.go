package nat

import (
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// A fresh socket keeping its local port for its first mapping: both sockets
// show it → PreserveFresh/High, one → Medium; a lost first probe or a
// sequential allocator are no such evidence.
func TestPreserveFresh(t *testing.T) {
	both := func() protocol.Traits {
		f := newFixture("192.168.1.10:40000", secondSocket())
		f.primary("203.0.113.5:40000", "203.0.113.5:51234", "203.0.113.5:9876")
		f.probe(v4S, 0, "203.0.113.5:40001")
		f.probe(v4S, 1, "203.0.113.5:33333")
		f.probe(v4S, 2, "203.0.113.5:61111")
		return f.t.Classify()
	}
	tr := both()
	wantMapping(t, tr, protocol.MapAPDM, protocol.ConfHigh)
	wantAlloc(t, tr, protocol.AllocPreserveFresh, protocol.ConfHigh)
	if !tr.FirstPreserved || tr.Predictable() || tr.PortRangeLo != 0 {
		t.Fatalf("traits %+v", tr)
	}
	if fp := Fingerprint(tr); fp != "v4|APDM|PDF|FRESH" && fp != "v4|APDM|UNK|FRESH" {
		t.Errorf("fingerprint %q", fp)
	}

	// The second socket's first mapping took another port: one socket of
	// evidence.
	f := newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:40000", "203.0.113.5:51234", "203.0.113.5:9876")
	f.probe(v4S, 0, "203.0.113.5:22222")
	f.probe(v4S, 1, "203.0.113.5:33333")
	f.probe(v4S, 2, "203.0.113.5:61111")
	wantAlloc(t, f.t.Classify(), protocol.AllocPreserveFresh, protocol.ConfMedium)

	// The primary's first probe was lost: its first sample is not the
	// socket's first mapping, whatever its port.
	f = newFixture("192.168.1.10:40000", secondSocket())
	f.primary("", "203.0.113.5:40000", "203.0.113.5:9876")
	f.probe(v4S, 0, "203.0.113.5:22222")
	f.probe(v4S, 1, "203.0.113.5:33333")
	f.probe(v4S, 2, "203.0.113.5:61111")
	if tr := f.t.Classify(); tr.PortAlloc == protocol.AllocPreserveFresh {
		t.Fatalf("lost first probe read as fresh evidence: %+v", tr)
	}

	// A sequential allocator that started at the local port stays
	// sequential.
	f = newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:40000", "203.0.113.5:40001", "203.0.113.5:40002")
	f.probe(v4S, 0, "203.0.113.5:40003")
	f.probe(v4S, 1, "203.0.113.5:40004")
	if tr := f.t.Classify(); tr.PortAlloc != protocol.AllocSequential || !tr.FirstPreserved {
		t.Fatalf("sequential from the local port: %+v", tr)
	}
}

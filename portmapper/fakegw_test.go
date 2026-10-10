package portmapper

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// fakeGW is a PCP and NAT-PMP gateway: one UDP socket on 127.0.0.1 that
// answers both protocols, like a real gateway's port 5351. It keeps the
// mapping tables and counts creates, renewals and deletes.

type serveMode int

const (
	serveOK          serveMode = iota
	serveSilent                // read and drop
	serveUnsupported           // answer with UNSUPP_VERSION
	serveNoReply               // act on the request, never answer (lost reply)
)

// heldRequest is a PCP request the gateway answers later (fakeGW.holdPCP).
type heldRequest struct {
	b   []byte
	src netip.AddrPort
}

type pcpEntry struct {
	nonce [12]byte
	ext   uint16
}

type fakeGW struct {
	conn *net.UDPConn
	port uint16
	ext  netip.Addr
	done chan struct{}

	mu            sync.Mutex
	pcpMode       serveMode
	natMode       serveMode
	dropDeletes   bool
	holdPCP       bool          // PCP requests wait for the first NAT-PMP external-address query
	held          []heldRequest // PCP requests held by holdPCP
	grant         uint32        // maximum granted lifetime, seconds
	nextExt       uint16
	pcpActive     map[uint16]pcpEntry
	natActive     map[uint16]uint16
	pcpCreates    int
	pcpRenews     int
	pcpDeletes    int
	pcpRejects    int
	natCreates    int
	natRenews     int
	natDeletes    int
	natExtQueries int
	received      int // datagrams of either protocol
}

func newFakeGW(t testing.TB) *fakeGW {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGW{
		conn:      c,
		port:      uint16(c.LocalAddr().(*net.UDPAddr).Port),
		ext:       netip.MustParseAddr("203.0.113.7"),
		done:      make(chan struct{}),
		grant:     3600,
		nextExt:   40000,
		pcpActive: map[uint16]pcpEntry{},
		natActive: map[uint16]uint16{},
	}
	go f.serve()
	t.Cleanup(func() {
		_ = c.Close()
		<-f.done
	})
	return f
}

func (f *fakeGW) set(fn func(*fakeGW)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type gwCounts struct {
	pcpCreates, pcpRenews, pcpDeletes, pcpRejects    int
	natCreates, natRenews, natDeletes, natExtQueries int
	received                                         int
}

func (f *fakeGW) counts() gwCounts {
	f.mu.Lock()
	defer f.mu.Unlock()
	return gwCounts{
		pcpCreates: f.pcpCreates, pcpRenews: f.pcpRenews, pcpDeletes: f.pcpDeletes, pcpRejects: f.pcpRejects,
		natCreates: f.natCreates, natRenews: f.natRenews, natDeletes: f.natDeletes, natExtQueries: f.natExtQueries,
		received: f.received,
	}
}

func (f *fakeGW) active() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pcpActive) + len(f.natActive)
}

func (f *fakeGW) serve() {
	defer close(f.done)
	buf := make([]byte, 1500)
	for {
		n, src, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if f.hold(buf[:n], src) {
			continue
		}
		if resp := f.handle(buf[:n]); resp != nil {
			_, _ = f.conn.WriteToUDPAddrPort(resp, src)
		}
		for _, h := range f.release() {
			if resp := f.handle(h.b); resp != nil {
				_, _ = f.conn.WriteToUDPAddrPort(resp, h.src)
			}
		}
	}
}

// hold keeps a copy of a PCP request while holdPCP waits for a NAT-PMP
// probe; it reports whether it did.
func (f *fakeGW) hold(b []byte, src netip.AddrPort) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.holdPCP || f.natExtQueries > 0 || len(b) == 0 || b[0] != pcpVersion {
		return false
	}
	f.held = append(f.held, heldRequest{b: append([]byte(nil), b...), src: src})
	return true
}

// release returns the held PCP requests once a NAT-PMP probe has arrived.
func (f *fakeGW) release() []heldRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.natExtQueries == 0 {
		return nil
	}
	h := f.held
	f.held = nil
	return h
}

func (f *fakeGW) handle(b []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.received++
	if len(b) < 2 {
		return nil
	}
	switch b[0] {
	case pcpVersion:
		return f.handlePCP(b)
	case natpmpVersion:
		return f.handleNATPMP(b)
	}
	return nil
}

func (f *fakeGW) allocExt(suggested uint16) uint16 {
	if suggested != 0 {
		return suggested
	}
	f.nextExt++
	return f.nextExt
}

func (f *fakeGW) handlePCP(b []byte) []byte {
	switch f.pcpMode {
	case serveSilent:
		return nil
	case serveUnsupported:
		// A NAT-PMP-only server: version 0, result 1 (unsupported version).
		return []byte{natpmpVersion, natpmpOpReply + b[1]&0x7f, 0, 1, 0, 0, 0, 0}
	case serveOK, serveNoReply: // handled below
	}
	if len(b) < pcpMapMsgLen || b[1] != pcpOpMap {
		return nil
	}
	lifetime := binary.BigEndian.Uint32(b[4:8])
	op := b[pcpHeaderLen:]
	var nonce [12]byte
	copy(nonce[:], op[:12])
	internal := binary.BigEndian.Uint16(op[16:18])
	suggested := binary.BigEndian.Uint16(op[18:20])

	resp := make([]byte, pcpMapMsgLen)
	resp[0] = pcpVersion
	resp[1] = pcpOpMap | pcpOpReply
	binary.BigEndian.PutUint32(resp[8:12], 1234)
	copy(resp[pcpHeaderLen:], op[:20])
	ext16 := f.ext.As16()
	copy(resp[pcpHeaderLen+20:], ext16[:])

	e, exists := f.pcpActive[internal]
	if exists && e.nonce != nonce {
		f.pcpRejects++
		resp[3] = byte(pcpNotAuthorized)
		return resp
	}
	if lifetime == 0 {
		if f.dropDeletes {
			return nil
		}
		if exists {
			delete(f.pcpActive, internal)
			f.pcpDeletes++
		}
		binary.BigEndian.PutUint16(resp[pcpHeaderLen+18:], e.ext)
		return resp
	}
	if exists {
		f.pcpRenews++
	} else {
		e = pcpEntry{nonce: nonce, ext: f.allocExt(suggested)}
		f.pcpActive[internal] = e
		f.pcpCreates++
	}
	binary.BigEndian.PutUint32(resp[4:8], min(lifetime, f.grant))
	binary.BigEndian.PutUint16(resp[pcpHeaderLen+18:], e.ext)
	if f.pcpMode == serveNoReply {
		return nil
	}
	return resp
}

func (f *fakeGW) handleNATPMP(b []byte) []byte {
	switch f.natMode {
	case serveSilent:
		return nil
	case serveUnsupported:
		// A PCP-only server: PCP header with UNSUPP_VERSION.
		resp := make([]byte, pcpHeaderLen)
		resp[0], resp[1], resp[3] = pcpVersion, pcpOpReply|b[1], byte(pcpUnsuppVersion)
		return resp
	case serveOK, serveNoReply: // handled below
	}
	switch b[1] {
	case natpmpOpExternal:
		f.natExtQueries++
		resp := make([]byte, natpmpExtRespLen)
		resp[1] = natpmpOpReply
		binary.BigEndian.PutUint32(resp[4:8], 1234)
		ext4 := f.ext.As4()
		copy(resp[8:12], ext4[:])
		return resp
	case natpmpOpMapUDP:
		if len(b) < 12 {
			return nil
		}
		internal := binary.BigEndian.Uint16(b[4:6])
		suggested := binary.BigEndian.Uint16(b[6:8])
		lifetime := binary.BigEndian.Uint32(b[8:12])
		resp := make([]byte, natpmpMapRespLen)
		resp[1] = natpmpOpReply + natpmpOpMapUDP
		binary.BigEndian.PutUint32(resp[4:8], 1234)
		binary.BigEndian.PutUint16(resp[8:10], internal)
		ext, exists := f.natActive[internal]
		if lifetime == 0 {
			if f.dropDeletes {
				return nil
			}
			if exists {
				delete(f.natActive, internal)
				f.natDeletes++
			}
			return resp
		}
		if exists {
			f.natRenews++
		} else {
			ext = f.allocExt(suggested)
			f.natActive[internal] = ext
			f.natCreates++
		}
		binary.BigEndian.PutUint16(resp[10:12], ext)
		binary.BigEndian.PutUint32(resp[12:16], min(lifetime, f.grant))
		if f.natMode == serveNoReply {
			return nil
		}
		return resp
	}
	return nil
}

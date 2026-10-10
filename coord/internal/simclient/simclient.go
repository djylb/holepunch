// Package simclient is a scripted holepunch client for coord's tests: it
// speaks the holepunch control protocol over one connection,
// answers pings by itself (unless told not to) and leaves every other step to
// the test, which reads what the coordinator writes and sends what the script
// says.
//
// A Client owns a client-side controlwire.Conn (one reading and one writing
// goroutine) until Close or Release; the builders (Report, Ready, Result, ...)
// are pure functions. Nothing here touches UDP.
package simclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
)

// Options configures a Client.
type Options struct {
	// Now is the client's clock (pong hold times); nil means time.Now.
	Now func() time.Time
	// NoPong leaves pings unanswered.
	NoPong bool
}

// Client is one scripted client on a control link.
type Client struct {
	Role   protocol.Role
	nc     net.Conn
	conn   *controlwire.Conn
	noPong atomic.Bool
	pings  atomic.Int64
}

// New wraps the client end of a control link.
func New(nc net.Conn, role protocol.Role, o Options) (*Client, error) {
	c := &Client{Role: role, nc: nc}
	c.noPong.Store(o.NoPong)
	cw, err := controlwire.NewConn(nc, controlwire.ConnOptions{Side: controlwire.SideClient, Now: o.Now, Intercept: c.intercept})
	if err != nil {
		return nil, err
	}
	c.conn = cw
	return c, nil
}

// intercept answers pings at once, the way the client runtime does.
func (c *Client) intercept(cw *controlwire.Conn, f controlwire.Frame) bool {
	if f.Type != controlwire.TypePing {
		return false
	}
	c.pings.Add(1)
	if c.noPong.Load() {
		return true
	}
	p, err := protocol.Unmarshal[protocol.Ping](f)
	if err != nil {
		return true
	}
	at := f.At
	_ = cw.SendFunc(controlwire.TypePong, func(now time.Time) ([]byte, error) {
		fr, err := protocol.Marshal(protocol.PongFor(p, at, now))
		return fr.Payload, err
	})
	return true
}

// SetNoPong switches ping answers off or on.
func (c *Client) SetNoPong(v bool) { c.noPong.Store(v) }

// Pings returns how many pings arrived.
func (c *Client) Pings() int { return int(c.pings.Load()) }

// Next returns the next message the coordinator wrote (pings excluded) and
// the instant it was read.
func (c *Client) Next(ctx context.Context) (protocol.Message, time.Time, error) {
	f, err := c.conn.ReadFrame(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	m, err := protocol.Decode(f)
	return m, f.At, err
}

// ErrUnexpected is returned when the next message is not of the expected type.
var ErrUnexpected = errors.New("simclient: unexpected message")

// Expect reads the next message and requires it to be a *T.
func Expect[T any](ctx context.Context, c *Client) (*T, error) {
	m, _, err := c.Next(ctx)
	if err != nil {
		return nil, err
	}
	t, ok := any(m).(*T)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrUnexpected, m)
	}
	return t, nil
}

// Send writes m and waits until it is written.
func (c *Client) Send(ctx context.Context, m protocol.Message) error {
	f, err := protocol.Marshal(m)
	if err != nil {
		return err
	}
	return c.conn.WriteFrame(ctx, f)
}

// SendFrame writes a frame as is (any type, any payload within the type's
// cap).
func (c *Client) SendFrame(ctx context.Context, t controlwire.Type, payload []byte) error {
	return c.conn.WriteFrame(ctx, controlwire.Frame{Type: t, Payload: payload})
}

// Release stops the Client and returns the raw connection, for tests that
// write malformed bytes or stop reading altogether.
func (c *Client) Release() (net.Conn, error) {
	if err := c.conn.Release(); err != nil {
		return nil, err
	}
	return c.nc, nil
}

// Close closes the link.
func (c *Client) Close() error { return c.conn.Close() }

// Done is closed when the link stops (the coordinator closed it, or Close).
func (c *Client) Done() <-chan struct{} { return c.conn.Done() }

// Family is one family of a scripted probe report.
type Family struct {
	Family     protocol.Family
	Local      netip.AddrPort   // the primary socket
	Observed   []netip.AddrPort // the ack value of each observer row (observer = index)
	Cookies    []uint32         // the echoed cookies, by row (0: none)
	Traits     protocol.Traits
	PortMap    *protocol.PortMapReport
	LocalAddrs []netip.Addr
	Overlay    []netip.Addr // the host's overlay addresses
}

// Report builds the probe_report a client of start would send.
func Report(start protocol.PunchStart, elapsedMs uint32, mode string, fams ...Family) protocol.ProbeReport {
	rep := protocol.ProbeReport{
		SessionID: start.SessionID,
		Role:      start.Role,
		Control: protocol.ControlSpec{Version: controlwire.Version,
			Features: protocol.AcceptFeatures(start.Control.Features, protocol.SupportedFeatures())},
		Caps:      protocol.ClientCaps{Impl: "simclient", MaxSockets: 64},
		ElapsedMs: elapsedMs,
		Transport: protocol.Transport{Mode: mode},
	}
	for _, f := range fams {
		rep.Caps.Families = append(rep.Caps.Families, protocol.FamilyCaps{Family: f.Family, LowTTL: true})
		sock := protocol.SocketReport{ID: nat.SocketID(f.Family, nat.IndexPrimary), Kind: protocol.SocketPrimary, Local: f.Local}
		for i, o := range f.Observed {
			row := protocol.RowReport{Observer: uint8(i), Observed: o, FirstSeq: uint32(i + 1), RTTMs: 10}
			if i < len(f.Cookies) {
				row.Cookie = f.Cookies[i]
			}
			sock.Rows = append(sock.Rows, row)
		}
		tr := f.Traits
		tr.Family = ""
		rep.Families = append(rep.Families, protocol.FamilyReport{Family: f.Family, Sockets: []protocol.SocketReport{sock},
			Traits: tr, PortMap: f.PortMap, LocalAddrs: f.LocalAddrs, Overlay: f.Overlay})
	}
	return rep
}

// OpenTraits are the traits of an endpoint-independent, unfiltered NAT seen
// at public.
func OpenTraits(public netip.AddrPort) protocol.Traits {
	return protocol.Traits{Mapping: protocol.MapEIM, MappingConf: protocol.ConfHigh, Filtering: protocol.FiltEIF,
		FilteringConf: protocol.ConfHigh, PortAlloc: protocol.AllocPreserving, PortAllocConf: protocol.ConfHigh,
		PublicIP: public.Addr(), Observed: public, Samples: 3, CrossIP: true}
}

// PDFTraits are the traits of an endpoint-independent, port-filtering NAT.
func PDFTraits(public netip.AddrPort) protocol.Traits {
	t := OpenTraits(public)
	t.Filtering = protocol.FiltPDF
	return t
}

// SeqTraits are the traits of an address-and-port-dependent NAT with a
// sequential port allocation of step 1.
func SeqTraits(public netip.AddrPort) protocol.Traits {
	t := PDFTraits(public)
	t.Mapping, t.PortAlloc, t.PortAllocConf, t.PortStep = protocol.MapAPDM, protocol.AllocSequential, protocol.ConfHigh, 1
	t.PortAnchor = public.Port()
	return t
}

// Ready builds a punch_ready for the families of a summary.
func Ready(sum *protocol.ProbeSummary, role protocol.Role, elapsedMs uint32) protocol.PunchReady {
	r := protocol.PunchReady{SessionID: sum.SessionID, Role: role, ElapsedMs: elapsedMs}
	for _, s := range sum.Plan.Round1.Sides {
		r.Families = append(r.Families, protocol.FamilyReady{Family: s.Family, Sockets: s.Sockets})
	}
	return r
}

// Outcome is one family of a scripted round result.
type Outcome = protocol.FamilyOutcome

// RoundEnd builds a round_result with the given status.
func RoundEnd(sessionID string, role protocol.Role, round uint8, status protocol.RoundStatus, fams ...Outcome) protocol.RoundResult {
	return protocol.RoundResult{SessionID: sessionID, Role: role, Round: round, ElapsedMs: 1, Status: status, Families: fams}
}

// Path builds a confirmed path.
func Path(fam protocol.Family, local, remote netip.AddrPort, round uint8) *protocol.PathInfo {
	return &protocol.PathInfo{Family: fam, Local: local, Remote: remote, Round: round, Epoch: 1,
		CandKind: protocol.CandDirect, Kind: protocol.PathPublic, RTTMs: 10}
}

// Confirmed builds round_result{confirmed}.
func Confirmed(sessionID string, role protocol.Role, round uint8, p *protocol.PathInfo) protocol.RoundResult {
	rr := RoundEnd(sessionID, role, round, protocol.RoundConfirmed, Outcome{Family: p.Family, Hit: true, Sent: 1, Recv: 1})
	rr.Path = p
	return rr
}

// Success builds punch_result{ok: true}.
func Success(sessionID string, role protocol.Role, p *protocol.PathInfo) protocol.PunchResult {
	q := *p
	q.ConfirmedBy = protocol.ConfirmedByAck
	return protocol.PunchResult{SessionID: sessionID, Role: role, OK: true, Phase: protocol.PhaseDone, Path: &q}
}

// Failure builds punch_result{ok: false, code}.
func Failure(sessionID string, role protocol.Role, code protocol.Reason, phase protocol.Phase) protocol.PunchResult {
	return protocol.PunchResult{SessionID: sessionID, Role: role, Code: code, Phase: phase}
}

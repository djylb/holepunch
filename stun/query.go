package stun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// ErrNoResponse is the error of a Query that sent every retransmission and
// heard no answer.
var ErrNoResponse = errors.New("stun: no response")

// Retransmission schedule (RFC 8489, section 6.2.1): RTO 500 ms, doubled
// after each request, Rc = 7 requests, and Rm × RTO = 8 s after the last.
const (
	initialRTO = 500 * time.Millisecond
	requests   = 7
	lastWait   = 16 * initialRTO
	// maxSoftErrors bounds the read errors other than a timeout — ICMP
	// reports of earlier datagrams, mostly — that Query reads past.
	maxSoftErrors = 16
)

// Query asks the STUN server at server for the public mapping of conn — the
// address and port the server sees conn's datagrams come from — and returns
// it.
//
// It sends a Binding Request from conn and retransmits it after 500 ms,
// then at doubling intervals, seven requests in all, so an unanswered query
// returns ErrNoResponse after 39.5 s; it returns ctx's cause first when ctx
// ends. Only a response from server with the request's transaction id
// counts.
//
// Query reads conn, so nobody else may read it meanwhile; the datagrams it
// reads that are not the answer are lost. It sets conn's read deadline and
// clears it before returning.
func Query(ctx context.Context, conn net.PacketConn, server netip.AddrPort) (netip.AddrPort, error) {
	if !server.IsValid() {
		return netip.AddrPort{}, errors.New("stun: invalid server address")
	}
	server = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())
	from := netip.AddrPortFrom(server.Addr().WithZone(""), server.Port()) // sources carry no zone
	id := NewTransactionID()
	req := AppendBindingRequest(nil, id)
	to := net.UDPAddrFromAddrPort(server)

	// ctx's end interrupts a blocked read; the deadline is cleared only
	// once that callback can no longer run.
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		_ = conn.SetReadDeadline(time.Unix(1, 0))
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
		_ = conn.SetReadDeadline(time.Time{})
	}()

	buf := make([]byte, maxMessage)
	rto, soft := initialRTO, 0
	for i := range requests {
		if _, err := conn.WriteTo(req, to); err != nil {
			if ctx.Err() != nil {
				return netip.AddrPort{}, context.Cause(ctx)
			}
			return netip.AddrPort{}, err
		}
		wait := rto
		if i == requests-1 {
			wait = lastWait
		}
		deadline := time.Now().Add(wait)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return netip.AddrPort{}, err
		}
		if ctx.Err() != nil { // ended before the deadline was set
			return netip.AddrPort{}, context.Cause(ctx)
		}
		for {
			n, src, err := conn.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				switch {
				case ctx.Err() != nil:
					return netip.AddrPort{}, context.Cause(ctx)
				case errors.As(err, &ne) && ne.Timeout():
					if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
						// The read hit ctx's deadline before ctx's own timer.
						<-ctx.Done()
						return netip.AddrPort{}, context.Cause(ctx)
					}
				case errors.Is(err, net.ErrClosed) || soft >= maxSoftErrors:
					return netip.AddrPort{}, err
				default:
					soft++
					continue
				}
				break
			}
			if !sameAddr(src, from) {
				continue
			}
			if got, mapped, ok := ParseBindingResponse(buf[:n]); ok && got == id {
				return mapped, nil
			}
		}
		rto *= 2
	}
	return netip.AddrPort{}, ErrNoResponse
}

// sameAddr reports whether from is server.
func sameAddr(from net.Addr, server netip.AddrPort) bool {
	ap, ok := addrPort(from)
	return ok && netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) == server
}

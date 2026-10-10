package portmapper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Retransmission schedule shared by PCP, NAT-PMP and SSDP (RFC 6886, section 3.1:
// start at 250 ms and double). It is capped because every exchange is bounded
// by a context of a few seconds at most.
const (
	retransmitInitial = 250 * time.Millisecond
	retransmitMax     = 2 * time.Second
)

// maxGatewayResponse is the read buffer for PCP and NAT-PMP answers; PCP
// messages are at most 1100 bytes (RFC 6887, section 7).
const maxGatewayResponse = 1100

// outcome tells the caller of exchange what the gateway may have done.
type outcome int

const (
	notSent    outcome = iota // the request never left: the gateway did nothing
	unanswered                // sent but not answered: the gateway may have acted on it
	answered                  // the gateway answered, positively or not
)

// exchange sends req to server and retransmits it until accept takes an
// answer from server, the socket fails or ctx ends. accept returns
// (false, nil) for datagrams that do not answer this request (stale answers,
// another client's nonce) and an error for a definitive negative answer;
// datagrams from anyone but server are ignored.
func (c *reqConn) exchange(ctx context.Context, server netip.AddrPort, req []byte, accept func([]byte) (bool, error)) (outcome, error) {
	dst := net.UDPAddrFromAddrPort(server)
	buf := make([]byte, maxGatewayResponse)
	out := notSent
	for interval := retransmitInitial; ; interval = min(interval*2, retransmitMax) {
		if ctx.Err() != nil {
			return out, noAnswer(ctx, out)
		}
		if _, err := c.pc.WriteTo(req, dst); err != nil {
			if ctx.Err() != nil {
				return out, noAnswer(ctx, out)
			}
			return out, err
		}
		out = unanswered
		isAnswer := false
		_, err := c.readRound(ctx, time.Now().Add(interval), buf, func(b []byte, from netip.AddrPort) (bool, error) {
			if from != server {
				return false, nil
			}
			ok, err := accept(b)
			isAnswer = ok || err != nil
			return isAnswer, err
		})
		if isAnswer {
			return answered, err
		}
		if err != nil {
			return out, err
		}
	}
}

// noAnswer is the error of an exchange whose context ended.
func noAnswer(ctx context.Context, out outcome) error {
	if out == unanswered {
		return fmt.Errorf("%w: %w", errNoResponse, context.Cause(ctx))
	}
	return context.Cause(ctx)
}

// readRound reads datagrams until match is done or fails, the socket fails,
// the deadline passes or ctx ends; the last two return (false, nil).
func (c *reqConn) readRound(ctx context.Context, deadline time.Time, buf []byte, match func([]byte, netip.AddrPort) (bool, error)) (bool, error) {
	if err := c.pc.SetReadDeadline(deadline); err != nil {
		if ctx.Err() != nil {
			return false, nil
		}
		return false, err
	}
	for {
		n, addr, err := c.pc.ReadFrom(buf)
		if err != nil {
			// The end of ctx closed the socket, or the deadline passed.
			var ne net.Error
			if ctx.Err() != nil || errors.As(err, &ne) && ne.Timeout() {
				return false, nil
			}
			return false, err
		}
		if done, err := match(buf[:n], addrPortOf(addr)); done || err != nil {
			return done, err
		}
	}
}

// addrPortOf returns the address of a datagram's sender, with an
// IPv4-mapped address unmapped.
func addrPortOf(a net.Addr) netip.AddrPort {
	var ap netip.AddrPort
	if u, ok := a.(*net.UDPAddr); ok && u != nil {
		ap = u.AddrPort()
	} else if a != nil {
		ap, _ = netip.ParseAddrPort(a.String())
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

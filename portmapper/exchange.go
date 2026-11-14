package portmapper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/djylb/holepunch/internal/netaddr"
)

// Retransmission schedule shared by PCP, NAT-PMP and SSDP (RFC 6886, section 3.1:
// start at 250 ms and double). It is capped because every exchange is bounded
// by a context of a few seconds at most.
const (
	retransmitInitial = 250 * time.Millisecond
	retransmitMax     = 2 * time.Second
)

// readBufSize is the read buffer of a request socket: room for any UDP
// datagram, so that none is cut short. Answers are far smaller (a PCP
// message is at most 1100 bytes, RFC 6887, section 7), but Windows fails a
// read whose datagram does not fit instead of truncating it, and a stray
// oversized datagram would then end the request.
const readBufSize = 64 << 10

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
	buf := make([]byte, readBufSize)
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
		err := c.readRound(ctx, time.Now().Add(interval), buf, func(b []byte, from netip.AddrPort) (bool, error) {
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
// the deadline passes or ctx ends; the last two are not failures and
// return nil, as does a done match.
func (c *reqConn) readRound(ctx context.Context, deadline time.Time, buf []byte, match func([]byte, netip.AddrPort) (bool, error)) error {
	err := c.pc.SetReadDeadline(deadline)
	if roundEnded(ctx, err, false) {
		return nil
	}
	if err != nil {
		return err
	}
	for {
		n, addr, err := c.pc.ReadFrom(buf)
		if roundEnded(ctx, err, true) {
			return nil
		}
		if err != nil {
			return err
		}
		if done, merr := match(buf[:n], netaddr.Unmap(netaddr.AddrPortOf(addr))); done || merr != nil {
			return merr
		}
	}
}

// roundEnded reports whether the socket error err is no failure of the
// socket but the end of the round: ctx ended and closed the socket or, when
// timeout is set, the read deadline passed. The caller then retransmits or
// reports the end of ctx. A nil err is no end.
func roundEnded(ctx context.Context, err error, timeout bool) bool {
	return err != nil && (ctx.Err() != nil || timeout && isTimeout(err))
}

// isTimeout reports whether err is a network timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

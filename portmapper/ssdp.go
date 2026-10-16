package portmapper

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// SSDP (UPnP device architecture, section 1.3). Discovery is implemented here
// so that it returns on the first answer, is bounded by the attempt's context
// and uses a socket from Config.Network; goupnp's discovery opens its own
// sockets, always waits for its whole search window and logs through the
// standard logger.

var ssdpMulticastAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{239, 255, 255, 250}), ssdpPort)

var ssdpSearchTargets = [...]string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
}

// ssdpSearch sends M-SEARCH requests for an InternetGatewayDevice from local
// to the gateway (unicast, when gw is known) and to the SSDP multicast group
// (when multicast is set), and returns the description URL of the first
// usable answer. When the gateway is known only its answers count. The URL
// must name the address that answered, so a host on the LAN cannot point the
// client elsewhere.
func ssdpSearch(ctx context.Context, open opener, local, gw netip.Addr, gwPort uint16, multicast bool) (*url.URL, error) {
	var targets []*net.UDPAddr
	if gw.IsValid() {
		targets = append(targets, net.UDPAddrFromAddrPort(netip.AddrPortFrom(gw, gwPort)))
	}
	if multicast {
		targets = append(targets, net.UDPAddrFromAddrPort(ssdpMulticastAddr))
	}
	if len(targets) == 0 {
		return nil, errNoIGD
	}
	c, err := open(ctx, local)
	if err != nil {
		return nil, fmt.Errorf("upnp: %w", err)
	}
	defer c.Close()

	reqs := make([][]byte, 0, len(ssdpSearchTargets))
	for _, st := range ssdpSearchTargets {
		reqs = append(reqs, []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: "+st+
			"\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n\r\n"))
	}
	buf := make([]byte, readBufSize)
	for interval := retransmitInitial; ; interval = min(interval*2, retransmitMax) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %w", errNoIGD, context.Cause(ctx))
		}
		var sent bool
		var sendErr error
		for _, dst := range targets {
			for _, req := range reqs {
				if _, err := c.pc.WriteTo(req, dst); err != nil {
					sendErr = err
					continue
				}
				sent = true
			}
		}
		if !sent {
			if ctx.Err() != nil {
				continue // reported at the top of the loop
			}
			return nil, fmt.Errorf("upnp: SSDP send: %w", sendErr)
		}
		var loc *url.URL
		_, err := c.readRound(ctx, time.Now().Add(interval), buf, func(b []byte, from netip.AddrPort) (bool, error) {
			if gw.IsValid() && from.Addr() != gw {
				return false, nil
			}
			u, ok := parseSSDPResponse(b, from.Addr())
			loc = u
			return ok, nil
		})
		if err != nil {
			return nil, fmt.Errorf("upnp: SSDP: %w", err)
		}
		if loc != nil {
			return loc, nil
		}
	}
}

// parseSSDPResponse extracts the description URL from an M-SEARCH answer
// sent by from. The URL must be http and name from as an IP literal.
func parseSSDPResponse(b []byte, from netip.Addr) (*url.URL, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil)
	if err != nil {
		return nil, false
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("St"), "InternetGatewayDevice") {
		return nil, false
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Scheme != "http" {
		return nil, false
	}
	host, err := netip.ParseAddr(loc.Hostname())
	if err != nil || host.Unmap() != from {
		return nil, false
	}
	return loc, true
}

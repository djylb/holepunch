package portmapper

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/protocol"
	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/huin/goupnp/soap"
)

// UPnP IGD. The device description is fetched with the Mapper's own HTTP
// client (see newHTTPClient) and goupnp supplies the SOAP service clients.

const (
	upnpDescription  = "holepunch"
	upnpErrConflict  = 718 // ConflictInMappingEntry
	upnpErrPermanent = 725 // OnlyPermanentLeasesSupported
)

// upnpService is the part of goupnp's WANIPConnection1/2 and
// WANPPPConnection1 clients that is used here.
type upnpService interface {
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
	AddPortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string, internalPort uint16, internalClient string, enabled bool, description string, leaseDuration uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
}

// upnpAnyPortService is implemented by IGD2's WANIPConnection2, which lets the
// gateway pick a free external port.
type upnpAnyPortService interface {
	AddAnyPortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string, internalPort uint16, internalClient string, enabled bool, description string, leaseDuration uint32) (uint16, error)
}

// upnpCode returns the UPnP error code of a SOAP fault, or 0.
func upnpCode(err error) int {
	var fault *soap.SOAPFaultError
	if errors.As(err, &fault) {
		return fault.Detail.UPnPError.Errorcode
	}
	return 0
}

// fetchRootDevice downloads and parses the device description at loc.
func fetchRootDevice(ctx context.Context, hc *http.Client, loc *url.URL) (*goupnp.RootDevice, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upnp: description %s: HTTP %s", loc, resp.Status)
	}
	root := new(goupnp.RootDevice)
	dec := xml.NewDecoder(resp.Body)
	dec.DefaultSpace = goupnp.DeviceXMLNamespace
	// Descriptions are ASCII in practice, whatever charset they declare.
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := dec.Decode(root); err != nil {
		return nil, fmt.Errorf("upnp: description %s: %w", loc, err)
	}
	base := loc
	if root.URLBaseStr != "" {
		if base, err = url.Parse(root.URLBaseStr); err != nil {
			return nil, fmt.Errorf("upnp: description %s: bad URLBase: %w", loc, err)
		}
	}
	root.SetURLBase(base)
	return root, nil
}

// upnpServices returns the WAN connection services of root in preference
// order: IGD2 IP connection, IGD1 IP connection, PPP connection.
func upnpServices(root *goupnp.RootDevice, loc *url.URL, hc *http.Client) []upnpService {
	var out []upnpService
	ip2, err := internetgateway2.NewWANIPConnection2ClientsFromRootDevice(root, loc)
	out = keepServices(out, ip2, err, loc, hc)
	ip1, err := internetgateway2.NewWANIPConnection1ClientsFromRootDevice(root, loc)
	out = keepServices(out, ip1, err, loc, hc)
	ppp, err := internetgateway2.NewWANPPPConnection1ClientsFromRootDevice(root, loc)
	return keepServices(out, ppp, err, loc, hc)
}

// wanClient is one of goupnp's WAN connection clients.
type wanClient interface {
	upnpService
	GetServiceClient() *goupnp.ServiceClient
}

// keepServices appends the clients whose control URL is plain http, like the
// description's, on the host of the description at loc, set up to use hc. A
// client pointing at another host is dropped, so a device cannot direct the
// SOAP requests elsewhere; so is one asking for another scheme: a gateway
// has no certificate the client could verify.
func keepServices[C wanClient](out []upnpService, cs []C, err error, loc *url.URL, hc *http.Client) []upnpService {
	if err != nil {
		return out
	}
	for _, c := range cs {
		sc := c.GetServiceClient()
		if sc.SOAPClient == nil || sc.SOAPClient.EndpointURL.Scheme != "http" || sc.SOAPClient.EndpointURL.Hostname() != loc.Hostname() {
			continue
		}
		sc.SOAPClient.HTTPClient = *hc
		out = append(out, c)
	}
	return out
}

// upnpProbe is a discovered IGD with at least one WAN service that reports a
// usable external address. Probing has no effect on the gateway.
type upnpProbe struct {
	services []upnpService // preference order, starting with the probed one
	external netip.Addr    // external address reported by services[0]
	client   netip.Addr    // internal client address to map to
}

func upnpDiscover(ctx context.Context, open opener, hc *http.Client, local, gw netip.Addr, gwSSDPPort uint16, multicast bool) (*upnpProbe, error) {
	loc, err := ssdpSearch(ctx, open, local, gw, gwSSDPPort, multicast)
	if err != nil {
		return nil, err
	}
	root, err := fetchRootDevice(ctx, hc, loc)
	if err != nil {
		return nil, err
	}
	services := upnpServices(root, loc, hc)
	if len(services) == 0 {
		return nil, fmt.Errorf("upnp: %s has no WAN connection service", loc)
	}
	var errs multiError
	for i, svc := range services {
		ext, err := upnpExternal(ctx, svc)
		if err != nil {
			errs = append(errs, err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		return &upnpProbe{services: services[i:], external: ext, client: local}, nil
	}
	return nil, fmt.Errorf("upnp: no service reports an external address: %w", errs)
}

func upnpExternal(ctx context.Context, svc upnpService) (netip.Addr, error) {
	s, err := svc.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
		if a = a.Unmap(); a.Is4() && !a.IsUnspecified() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("upnp: unusable external address %q", s)
}

// upnpMapping is one live UPnP port mapping, owned by its lease.
type upnpMapping struct {
	svc      upnpService
	external uint16
	internal netip.AddrPort
	lease    uint32 // seconds; 0 is a permanent mapping
}

// create is the probe's creator: it adds a UDP mapping for port. It tries the
// services in order. On each it asks for the internal port number as the
// external port (IGD2 lets the gateway pick another free one), falls back to
// a permanent mapping when the gateway only supports those, and after a port
// conflict retries once with a random external port. It never returns an
// orphan: without knowing whether the gateway created a mapping whose answer
// was lost, a delete could remove another host's mapping on that port, so
// the lease bounds what is left.
func (p *upnpProbe) create(ctx context.Context, port uint16, lease time.Duration) (liveMapping, protocol.PortMappingInfo, remover, error) {
	if err := faultinject.Point(pointMap); err != nil {
		return nil, protocol.PortMappingInfo{}, nil, err
	}
	internal := netip.AddrPortFrom(p.client, port)
	var errs multiError
	for i, svc := range p.services {
		ext := p.external
		if i > 0 {
			var err error
			if ext, err = upnpExternal(ctx, svc); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		um := &upnpMapping{svc: svc, internal: internal, lease: uint32(lease / time.Second)}
		err := um.add(ctx, port)
		if upnpCode(err) == upnpErrConflict {
			err = um.add(ctx, randomPort())
		}
		if err != nil {
			errs = append(errs, err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		info := protocol.PortMappingInfo{
			Method:   protocol.PortMapUPnP,
			External: netip.AddrPortFrom(ext, um.external),
			Internal: internal,
			Lease:    time.Duration(um.lease) * time.Second,
		}
		return um, info, nil, nil
	}
	return nil, protocol.PortMappingInfo{}, nil, fmt.Errorf("upnp: %w", errs)
}

// add creates the mapping with external port ext and records the external
// port and lease the gateway accepted.
func (um *upnpMapping) add(ctx context.Context, ext uint16) error {
	for {
		var err error
		got := ext
		if anySvc, ok := um.svc.(upnpAnyPortService); ok {
			got, err = anySvc.AddAnyPortMappingCtx(ctx, "", ext, "UDP", um.internal.Port(), um.internal.Addr().String(), true, upnpDescription, um.lease)
		} else {
			err = um.svc.AddPortMappingCtx(ctx, "", ext, "UDP", um.internal.Port(), um.internal.Addr().String(), true, upnpDescription, um.lease)
		}
		if err != nil && um.lease != 0 && upnpCode(err) == upnpErrPermanent {
			um.lease = 0 // only permanent mappings: release still deletes it
			continue
		}
		if err == nil && got == 0 {
			err = errors.New("upnp: gateway reserved external port 0")
		}
		if err == nil {
			um.external = got
		}
		return err
	}
}

func (um *upnpMapping) renew(ctx context.Context) (time.Duration, error) {
	err := um.svc.AddPortMappingCtx(ctx, "", um.external, "UDP", um.internal.Port(), um.internal.Addr().String(), true, upnpDescription, um.lease)
	if err != nil {
		return 0, fmt.Errorf("upnp renew: %w", err)
	}
	return time.Duration(um.lease) * time.Second, nil
}

func (um *upnpMapping) remove(ctx context.Context) error {
	if err := um.svc.DeletePortMappingCtx(ctx, "", um.external, "UDP"); err != nil {
		return fmt.Errorf("upnp delete: %w", err)
	}
	return nil
}

// randomPort returns a random port in [16384, 65535] for a retry after a
// port conflict.
func randomPort() uint16 {
	return uint16(16384 + rand.IntN(65536-16384))
}

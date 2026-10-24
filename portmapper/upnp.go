package portmapper

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/protocol"
)

// UPnP IGD: discovery (ssdp.go), then the description and SOAP control of
// the WAN connection services (upnpsoap.go).

const (
	upnpMappingDescription = "holepunch"
	upnpErrConflict        = 718 // ConflictInMappingEntry
	upnpErrPermanent       = 725 // OnlyPermanentLeasesSupported
)

// upnpProbe is a discovered IGD with at least one WAN service that reports a
// usable external address. Probing has no effect on the gateway.
type upnpProbe struct {
	services []*soapService // preference order, starting with the probed one
	external netip.Addr     // external address reported by services[0]
	client   netip.Addr     // internal client address to map to
}

func upnpDiscover(ctx context.Context, open opener, hc *http.Client, local, gw netip.Addr, gwSSDPPort uint16, multicast bool) (*upnpProbe, error) {
	loc, err := ssdpSearch(ctx, open, local, gw, gwSSDPPort, multicast)
	if err != nil {
		return nil, err
	}
	desc, err := fetchDescription(ctx, hc, loc)
	if err != nil {
		return nil, err
	}
	services, err := wanServices(desc, loc, hc)
	if err != nil {
		return nil, err
	}
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

func upnpExternal(ctx context.Context, svc *soapService) (netip.Addr, error) {
	s, err := svc.externalIP(ctx)
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
	svc      *soapService
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
		if um.svc.anyPort() {
			got, err = um.svc.addAnyPortMapping(ctx, ext, um.internal.Port(), um.internal.Addr().String(), um.lease)
		} else {
			err = um.svc.addPortMapping(ctx, ext, um.internal.Port(), um.internal.Addr().String(), um.lease)
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
	err := um.svc.addPortMapping(ctx, um.external, um.internal.Port(), um.internal.Addr().String(), um.lease)
	if err != nil {
		return 0, fmt.Errorf("upnp renew: %w", err)
	}
	return time.Duration(um.lease) * time.Second, nil
}

func (um *upnpMapping) remove(ctx context.Context) error {
	if err := um.svc.deletePortMapping(ctx, um.external); err != nil {
		return fmt.Errorf("upnp delete: %w", err)
	}
	return nil
}

// randomPort returns a random port in [16384, 65535] for a retry after a
// port conflict.
func randomPort() uint16 {
	return uint16(16384 + rand.IntN(65536-16384))
}

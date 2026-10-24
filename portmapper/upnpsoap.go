package portmapper

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// The UPnP IGD client: the device description and the SOAP control of the
// WAN connection services, on the Mapper's own HTTP client (newHTTPClient:
// no proxy, no redirects, bounded headers and bodies). XML is matched by
// local name only: gateways get namespaces wrong.

// WAN connection service types, in preference order.
const (
	urnWANIP2  = "urn:schemas-upnp-org:service:WANIPConnection:2"
	urnWANIP1  = "urn:schemas-upnp-org:service:WANIPConnection:1"
	urnWANPPP1 = "urn:schemas-upnp-org:service:WANPPPConnection:1"
)

// Description and SOAP bounds.
const (
	maxUPnPDevices  = 64       // devices of one description, nested ones included
	maxSOAPResponse = 16 << 10 // a SOAP response or fault; the actions here answer a few hundred bytes
)

// upnpDescription is the part of a device description used here: the
// URLBase of UPnP 1.0 and the devices with their services.
type upnpDescription struct {
	URLBase string     `xml:"URLBase"`
	Device  upnpDevice `xml:"device"`
}

type upnpDevice struct {
	Services []upnpServiceDesc `xml:"serviceList>service"`
	Devices  []upnpDevice      `xml:"deviceList>device"`
}

type upnpServiceDesc struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

// fetchDescription downloads and parses the device description at loc.
func fetchDescription(ctx context.Context, hc *http.Client, loc *url.URL) (*upnpDescription, error) {
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
	desc := new(upnpDescription)
	if err := newXMLDecoder(resp.Body).Decode(desc); err != nil {
		return nil, fmt.Errorf("upnp: description %s: %w", loc, err)
	}
	return desc, nil
}

// newXMLDecoder decodes r whatever charset it declares: descriptions and
// SOAP messages are ASCII in practice.
func newXMLDecoder(r io.Reader) *xml.Decoder {
	dec := xml.NewDecoder(r)
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	return dec
}

// wanServices returns the WAN connection services of desc, described at
// loc, in preference order (IGD2 IP, IGD1 IP, PPP), each once. A control URL
// resolves against URLBase, else loc. A service whose control URL is not
// plain http on the description's host is left out: a device must not
// direct the SOAP requests elsewhere, and a gateway has no certificate the
// client could verify.
func wanServices(desc *upnpDescription, loc *url.URL, hc *http.Client) ([]*soapService, error) {
	base := loc
	if s := strings.TrimSpace(desc.URLBase); s != "" {
		var err error
		ref, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("upnp: description %s: bad URLBase: %w", loc, err)
		}
		base = loc.ResolveReference(ref) // a relative URLBase is relative to the description
	}
	var found []upnpServiceDesc
	queue := []upnpDevice{desc.Device}
	for n := 0; len(queue) > 0 && n < maxUPnPDevices; n++ {
		d := queue[0]
		queue = append(queue[1:], d.Devices...)
		found = append(found, d.Services...)
	}
	var out []*soapService
	for _, urn := range []string{urnWANIP2, urnWANIP1, urnWANPPP1} {
		for _, sd := range found {
			if strings.TrimSpace(sd.ServiceType) != urn {
				continue
			}
			ref, err := url.Parse(strings.TrimSpace(sd.ControlURL))
			if err != nil {
				continue
			}
			u := base.ResolveReference(ref)
			if u.Scheme != "http" || u.Hostname() != loc.Hostname() || slices.ContainsFunc(out, func(x *soapService) bool {
				return x.urn == urn && x.control.String() == u.String()
			}) {
				continue
			}
			out = append(out, &soapService{hc: hc, control: u, urn: urn})
		}
	}
	return out, nil
}

// soapService is one WAN connection service of a gateway.
type soapService struct {
	hc      *http.Client
	control *url.URL
	urn     string
}

// anyPort reports whether the service has AddAnyPortMapping, which lets the
// gateway pick a free external port (IGD2).
func (s *soapService) anyPort() bool { return s.urn == urnWANIP2 }

// externalIP is GetExternalIPAddress.
func (s *soapService) externalIP(ctx context.Context) (string, error) {
	out, err := s.call(ctx, "GetExternalIPAddress", nil)
	return out["NewExternalIPAddress"], err
}

// mappingArgs are the arguments of AddPortMapping and AddAnyPortMapping, in
// the order the specification lists them: some gateways read them by
// position.
func mappingArgs(ext uint16, internalPort uint16, client string, lease uint32) [][2]string {
	return [][2]string{
		{"NewRemoteHost", ""},
		{"NewExternalPort", strconv.Itoa(int(ext))},
		{"NewProtocol", "UDP"},
		{"NewInternalPort", strconv.Itoa(int(internalPort))},
		{"NewInternalClient", client},
		{"NewEnabled", "1"},
		{"NewPortMappingDescription", upnpMappingDescription},
		{"NewLeaseDuration", strconv.FormatUint(uint64(lease), 10)},
	}
}

// addPortMapping is AddPortMapping of a UDP mapping.
func (s *soapService) addPortMapping(ctx context.Context, ext, internalPort uint16, client string, lease uint32) error {
	_, err := s.call(ctx, "AddPortMapping", mappingArgs(ext, internalPort, client, lease))
	return err
}

// addAnyPortMapping is AddAnyPortMapping of a UDP mapping: the gateway
// returns the external port it reserved, ext when free.
func (s *soapService) addAnyPortMapping(ctx context.Context, ext, internalPort uint16, client string, lease uint32) (uint16, error) {
	out, err := s.call(ctx, "AddAnyPortMapping", mappingArgs(ext, internalPort, client, lease))
	if err != nil {
		return 0, err
	}
	p, err := strconv.ParseUint(strings.TrimSpace(out["NewReservedPort"]), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("upnp: AddAnyPortMapping: bad NewReservedPort %q", out["NewReservedPort"])
	}
	return uint16(p), nil
}

// deletePortMapping is DeletePortMapping of a UDP mapping.
func (s *soapService) deletePortMapping(ctx context.Context, ext uint16) error {
	_, err := s.call(ctx, "DeletePortMapping", [][2]string{
		{"NewRemoteHost", ""},
		{"NewExternalPort", strconv.Itoa(int(ext))},
		{"NewProtocol", "UDP"},
	})
	return err
}

// upnpError is a SOAP fault with a UPnP error: errorCode 718
// ConflictInMappingEntry, 725 OnlyPermanentLeasesSupported and so on.
type upnpError struct {
	Action      string
	Code        int
	Description string
}

func (e *upnpError) Error() string {
	return fmt.Sprintf("upnp: %s: error %d %s", e.Action, e.Code, e.Description)
}

// upnpCode returns the UPnP error code of a SOAP fault in err's chain, or 0.
func upnpCode(err error) int {
	if ue, ok := errors.AsType[*upnpError](err); ok {
		return ue.Code
	}
	return 0
}

// call runs one SOAP action and returns the response's arguments by local
// name. A SOAP fault, whatever the HTTP status, is an *upnpError when it
// carries a UPnP error.
func (s *soapService) call(ctx context.Context, action string, args [][2]string) (map[string]string, error) {
	var body bytes.Buffer
	body.WriteString(`<?xml version="1.0"?>` + "\r\n" +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body><u:` + action + ` xmlns:u="` + s.urn + `">`)
	for _, a := range args {
		body.WriteString("<" + a[0] + ">")
		_ = xml.EscapeText(&body, []byte(a[1])) // a bytes.Buffer never fails
		body.WriteString("</" + a[0] + ">")
	}
	body.WriteString(`</u:` + action + `></s:Body></s:Envelope>`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.control.String(), &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	// Quoted and spelled as the specification writes it, not in Go's
	// canonical form: some gateways compare both byte for byte.
	req.Header["SOAPAction"] = []string{`"` + s.urn + "#" + action + `"`}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upnp: %s: %w", action, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSOAPResponse+1))
	if err != nil {
		return nil, fmt.Errorf("upnp: %s: %w", action, err)
	}
	if len(raw) > maxSOAPResponse {
		return nil, fmt.Errorf("upnp: %s: %w", action, errBodyTooLarge)
	}
	out, fault, perr := parseSOAPResponse(raw)
	switch {
	case fault != nil:
		fault.Action = action
		return nil, fault
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("upnp: %s: HTTP %s", action, resp.Status)
	case perr != nil:
		return nil, fmt.Errorf("upnp: %s: %w", action, perr)
	}
	return out, nil
}

// parseSOAPResponse reads a SOAP envelope: the arguments of the response
// element in its body (Envelope > Body > Response > Arg), by local name, or
// the UPnP error of a fault (Fault > detail > UPnPError). Anything else —
// an empty body, a web page — is an error, never a success without
// arguments.
func parseSOAPResponse(raw []byte) (map[string]string, *upnpError, error) {
	dec := newXMLDecoder(bytes.NewReader(raw))
	out := map[string]string{}
	var path []string
	var fault *upnpError
	answered := false // an element in Envelope > Body
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			if len(path) == 3 && path[1] == "Body" {
				answered = true
				if t.Name.Local == "Fault" {
					fault = &upnpError{}
				}
			}
			if len(path) == 4 && fault == nil && path[1] == "Body" {
				out[t.Name.Local] = ""
			}
		case xml.CharData:
			switch {
			case fault != nil && endsWith(path, "UPnPError", "errorCode"):
				fault.Code, _ = strconv.Atoi(strings.TrimSpace(string(t)))
			case fault != nil && endsWith(path, "UPnPError", "errorDescription"):
				fault.Description += strings.TrimSpace(string(t))
			case fault == nil && len(path) == 4 && path[1] == "Body":
				out[path[3]] += string(t)
			}
		case xml.EndElement:
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		}
	}
	if fault != nil {
		if fault.Code == 0 {
			return nil, nil, errors.New("SOAP fault without a UPnP error")
		}
		return nil, fault, nil
	}
	if len(path) != 0 {
		return nil, nil, errors.New("truncated SOAP response")
	}
	if !answered {
		return nil, nil, errors.New("no SOAP response element")
	}
	return out, nil, nil
}

// endsWith reports whether path ends with tail.
func endsWith(path []string, tail ...string) bool {
	return len(path) >= len(tail) && slices.Equal(path[len(path)-len(tail):], tail)
}

package portmapper

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// TestParseSOAPResponse: arguments by local name whatever the namespaces,
// a UPnP fault as an *upnpError, and malformed envelopes as errors.
func TestParseSOAPResponse(t *testing.T) {
	ok := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>` +
		`<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">` +
		`<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`
	out, fault, err := parseSOAPResponse([]byte(ok))
	if err != nil || fault != nil || out["NewExternalIPAddress"] != "203.0.113.7" {
		t.Fatalf("response: %v %v %v", out, fault, err)
	}
	bare := `<Envelope><Body><GetExternalIPAddressResponse><m:NewExternalIPAddress xmlns:m="x">198.51.100.1</m:NewExternalIPAddress>` +
		`</GetExternalIPAddressResponse></Body></Envelope>`
	if out, _, err := parseSOAPResponse([]byte(bare)); err != nil || out["NewExternalIPAddress"] != "198.51.100.1" {
		t.Fatalf("namespaces wrong or missing: %v %v", out, err)
	}
	f := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode>` +
		`<faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode> 718 </errorCode>` +
		`<errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`
	if _, fault, err := parseSOAPResponse([]byte(f)); err != nil || fault == nil || fault.Code != upnpErrConflict || fault.Description != "ConflictInMappingEntry" {
		t.Fatalf("fault: %+v %v", fault, err)
	}
	for name, raw := range map[string]string{
		"fault without a UPnP error": `<Envelope><Body><Fault><faultcode>Server</faultcode></Fault></Body></Envelope>`,
		"truncated":                  `<Envelope><Body><R><A>1</A>`,
		"not XML":                    `<<<`,
		"empty":                      ``,
		"a web page":                 `<html><body><p>OK</p></body></html>`,
	} {
		if _, _, err := parseSOAPResponse([]byte(raw)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestSOAPRequest: the quoted SOAPAction, the arguments in the order the
// specification lists them, escaped, and a fault answered with HTTP 200 or
// 500 alike; an oversized answer is refused.
func TestSOAPRequest(t *testing.T) {
	var action, ctype string
	var sent http.Header // as the client wrote it: the specification's spelling, not Go's canonical one
	var body []byte
	reply := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action, ctype = r.Header.Get("SOAPAction"), r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, reply)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/ctl")
	hc := newHTTPClient()
	inner := hc.Transport
	hc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent = r.Header.Clone()
		return inner.RoundTrip(r)
	})
	svc := &soapService{hc: hc, control: u, urn: urnWANIP1}
	reply = `<Envelope><Body><AddPortMappingResponse/></Body></Envelope>`
	if err := svc.addPortMapping(context.Background(), 40000, 40001, "192.168.1.2", 3600); err != nil {
		t.Fatal(err)
	}
	if action != `"`+urnWANIP1+`#AddPortMapping"` || !strings.HasPrefix(ctype, "text/xml") || len(sent["SOAPAction"]) != 1 {
		t.Fatalf("SOAPAction %q, Content-Type %q", action, ctype)
	}
	args, err := parseSOAP(body)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, name := range []string{"NewRemoteHost", "NewExternalPort", "NewProtocol", "NewInternalPort", "NewInternalClient",
		"NewEnabled", "NewPortMappingDescription", "NewLeaseDuration"} {
		order = append(order, name)
		if _, ok := args[name]; !ok {
			t.Fatalf("argument %s missing: %v", name, args)
		}
	}
	var got []string
	for _, f := range strings.Split(string(body), "<New")[1:] {
		got = append(got, "New"+f[:strings.IndexByte(f, '>')])
	}
	if !slices.Equal(got, order) || args["NewExternalPort"] != "40000" || args["NewInternalClient"] != "192.168.1.2" ||
		args["NewEnabled"] != "1" || args["NewLeaseDuration"] != "3600" || args["NewProtocol"] != "UDP" {
		t.Fatalf("arguments %v in order %v", args, got)
	}
	reply = `<Envelope><Body><Fault><detail><UPnPError><errorCode>725</errorCode></UPnPError></detail></Fault></Body></Envelope>`
	if err := svc.addPortMapping(context.Background(), 1, 1, "192.168.1.2", 60); upnpCode(err) != upnpErrPermanent {
		t.Fatalf("fault with HTTP 200: %v", err)
	}
	reply = `<Envelope><Body><R>` + strings.Repeat("x", maxSOAPResponse) + `</R></Body></Envelope>`
	if _, err := svc.externalIP(context.Background()); err == nil || !strings.Contains(err.Error(), errBodyTooLarge.Error()) {
		t.Fatalf("oversized answer: %v", err)
	}
}

// TestWANServices: services anywhere in the device tree, IGD2 before IGD1
// before PPP, each once, control URLs resolved against URLBase.
func TestWANServices(t *testing.T) {
	desc := &upnpDescription{
		URLBase: " /igd/ ", // relative to the description
		Device: upnpDevice{Devices: []upnpDevice{{
			Services: []upnpServiceDesc{{ServiceType: urnWANPPP1, ControlURL: "ppp"}},
			Devices: []upnpDevice{{Services: []upnpServiceDesc{
				{ServiceType: urnWANIP1, ControlURL: "/ip1"},
				{ServiceType: urnWANIP1, ControlURL: "/ip1"},
				{ServiceType: " " + urnWANIP2 + " ", ControlURL: " ip2 "},
				{ServiceType: "urn:schemas-upnp-org:service:Layer3Forwarding:1", ControlURL: "/l3f"},
			}}},
		}}},
	}
	loc, _ := url.Parse("http://192.168.1.1:5000/rootDesc.xml")
	svcs, err := wanServices(desc, loc, newHTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range svcs {
		got = append(got, s.urn+" "+s.control.String())
	}
	want := []string{
		urnWANIP2 + " http://192.168.1.1:5000/igd/ip2",
		urnWANIP1 + " http://192.168.1.1:5000/ip1",
		urnWANPPP1 + " http://192.168.1.1:5000/igd/ppp",
	}
	if !slices.Equal(got, want) || !svcs[0].anyPort() || svcs[1].anyPort() {
		t.Fatalf("services\n%v\nwant\n%v", got, want)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

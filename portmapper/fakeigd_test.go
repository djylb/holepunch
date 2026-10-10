package portmapper

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeIGD is a UPnP internet gateway device: an SSDP responder on 127.0.0.1
// plus an httptest server for the device description and SOAP control.

type upnpEntry struct {
	internal string
	lease    uint32
}

type fakeIGD struct {
	srv           *httptest.Server
	ssdp          *net.UDPConn
	done          chan struct{}
	hangCh        chan struct{}
	active        map[uint16]upnpEntry
	failAddsOn    string // AddPortMapping on this service fails
	external      string
	services      []string // svcIGD2, svcIGD1, svcPPP1, in description order
	adds          int
	renews        int
	deletes       int
	mu            sync.Mutex
	ssdpPort      uint16
	permanentOnly bool
	failAdds      bool // every AddPortMapping fails
	ssdpSilent    bool
	hangHTTP      bool // every request hangs
	hangAdds      bool // AddPortMapping and AddAnyPortMapping hang
}

const (
	svcIGD2 = "urn:schemas-upnp-org:service:WANIPConnection:2"
	svcIGD1 = "urn:schemas-upnp-org:service:WANIPConnection:1"
	svcPPP1 = "urn:schemas-upnp-org:service:WANPPPConnection:1"
)

func newFakeIGD(t testing.TB, services ...string) *fakeIGD {
	t.Helper()
	f := &fakeIGD{services: services, external: "198.51.100.9", active: map[uint16]upnpEntry{}, done: make(chan struct{}), hangCh: make(chan struct{})}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.ssdp = c
	f.ssdpPort = uint16(c.LocalAddr().(*net.UDPAddr).Port)
	go f.serveSSDP()
	t.Cleanup(func() {
		close(f.hangCh)
		_ = c.Close()
		<-f.done
		f.srv.Close()
	})
	return f
}

func (f *fakeIGD) set(fn func(*fakeIGD)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeIGD) counts() (adds, renews, deletes, active int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds, f.renews, f.deletes, len(f.active)
}

func (f *fakeIGD) serveSSDP() {
	defer close(f.done)
	buf := make([]byte, 2048)
	for {
		n, src, err := f.ssdp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		silent := f.ssdpSilent
		f.mu.Unlock()
		req := string(buf[:n])
		if silent || !strings.HasPrefix(req, "M-SEARCH * HTTP/1.1") {
			continue
		}
		st := ""
		for _, line := range strings.Split(req, "\r\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(k, "ST") {
				st = strings.TrimSpace(v)
			}
		}
		resp := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: " + st +
			"\r\nUSN: uuid:fake::" + st + "\r\nEXT:\r\nSERVER: fake UPnP/1.1\r\nLOCATION: " + f.srv.URL + "/rootDesc.xml\r\n\r\n"
		_, _ = f.ssdp.WriteToUDPAddrPort([]byte(resp), src)
	}
}

func (f *fakeIGD) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	hang := f.hangHTTP
	f.mu.Unlock()
	if hang {
		select {
		case <-r.Context().Done():
		case <-f.hangCh:
		}
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/rootDesc.xml":
		f.mu.Lock()
		services := f.services
		f.mu.Unlock()
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
		_, _ = io.WriteString(w, rootDescXML(services...))
	case r.Method == http.MethodPost && r.URL.Path == "/ctl":
		f.serveSOAP(w, r)
	default:
		http.NotFound(w, r)
	}
}

// rootDescXML is a device description listing services, all controlled at
// /ctl.
func rootDescXML(services ...string) string {
	var list strings.Builder
	for i, svc := range services {
		_, _ = fmt.Fprintf(&list, `<service>
     <serviceType>%s</serviceType>
     <serviceId>urn:upnp-org:serviceId:WANConn%d</serviceId>
     <controlURL>/ctl</controlURL>
     <eventSubURL>/evt</eventSubURL>
     <SCPDURL>/scpd.xml</SCPDURL>
    </service>`, svc, i+1)
	}
	return `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <specVersion><major>1</major><minor>0</minor></specVersion>
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
  <friendlyName>fake IGD</friendlyName>
  <UDN>uuid:fake</UDN>
  <deviceList><device>
   <deviceType>urn:schemas-upnp-org:device:WANDevice:2</deviceType>
   <UDN>uuid:fake-wan</UDN>
   <deviceList><device>
    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:2</deviceType>
    <UDN>uuid:fake-wanconn</UDN>
    <serviceList>` + list.String() + `</serviceList>
   </device></deviceList>
  </device></deviceList>
 </device>
</root>`
}

// parseSOAP returns the action's argument elements by local name.
func parseSOAP(body []byte) (map[string]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	args := map[string]string{}
	depth := 0
	var cur string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return args, nil
		}
		if err != nil {
			return nil, err
		}
		switch tt := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 4 { // Envelope > Body > Action > Arg
				cur = tt.Name.Local
				args[cur] = ""
			}
		case xml.CharData:
			if depth == 4 {
				args[cur] += string(tt)
			}
		case xml.EndElement:
			depth--
		}
	}
}

func soapResponse(w http.ResponseWriter, service, action, inner string) {
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:%sResponse xmlns:u="%s">%s</u:%sResponse></s:Body></s:Envelope>`, action, service, inner, action)
}

func soapFault(w http.ResponseWriter, code int, desc string) {
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode><errorDescription>%s</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code, desc)
}

func (f *fakeIGD) serveSOAP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	service, action, _ := strings.Cut(strings.Trim(r.Header.Get("SOAPACTION"), `"`), "#")
	args, err := parseSOAP(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	hang := f.hangAdds && strings.HasPrefix(action, "Add")
	f.mu.Unlock()
	if hang {
		select {
		case <-r.Context().Done():
		case <-f.hangCh:
		}
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !slices.Contains(f.services, service) {
		soapFault(w, 401, "Invalid Action")
		return
	}
	extPort64, _ := strconv.ParseUint(args["NewExternalPort"], 10, 16)
	extPort := uint16(extPort64)
	lease64, _ := strconv.ParseUint(args["NewLeaseDuration"], 10, 32)
	switch action {
	case "GetExternalIPAddress":
		soapResponse(w, service, action, "<NewExternalIPAddress>"+f.external+"</NewExternalIPAddress>")
	case "AddPortMapping", "AddAnyPortMapping":
		if action == "AddAnyPortMapping" && service != svcIGD2 {
			soapFault(w, 401, "Invalid Action")
			return
		}
		if f.failAdds || f.failAddsOn == service {
			soapFault(w, 501, "ActionFailed")
			return
		}
		if f.permanentOnly && lease64 != 0 {
			soapFault(w, upnpErrPermanent, "OnlyPermanentLeasesSupported")
			return
		}
		entry := upnpEntry{internal: args["NewInternalClient"] + ":" + args["NewInternalPort"], lease: uint32(lease64)}
		if old, ok := f.active[extPort]; ok {
			if old.internal != entry.internal {
				if action == "AddAnyPortMapping" {
					extPort = 50000 + uint16(len(f.active))
				} else {
					soapFault(w, upnpErrConflict, "ConflictInMappingEntry")
					return
				}
			} else {
				f.renews++
			}
		}
		if _, ok := f.active[extPort]; !ok {
			f.adds++
		}
		f.active[extPort] = entry
		if action == "AddAnyPortMapping" {
			soapResponse(w, service, action, "<NewReservedPort>"+strconv.Itoa(int(extPort))+"</NewReservedPort>")
		} else {
			soapResponse(w, service, action, "")
		}
	case "DeletePortMapping":
		if _, ok := f.active[extPort]; !ok {
			soapFault(w, 714, "NoSuchEntryInArray")
			return
		}
		delete(f.active, extPort)
		f.deletes++
		soapResponse(w, service, action, "")
	default:
		soapFault(w, 401, "Invalid Action")
	}
}

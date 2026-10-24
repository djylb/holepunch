package portmapper

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

func TestParseSSDPResponse(t *testing.T) {
	from := netip.MustParseAddr("192.168.1.1")
	mk := func(st, loc string) []byte {
		return []byte("HTTP/1.1 200 OK\r\nST: " + st + "\r\nLOCATION: " + loc + "\r\n\r\n")
	}
	igd := "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
	if loc, ok := parseSSDPResponse(mk(igd, "http://192.168.1.1:5000/rootDesc.xml"), from); !ok || loc.String() != "http://192.168.1.1:5000/rootDesc.xml" {
		t.Fatalf("valid answer rejected: %v %v", loc, ok)
	}
	for name, b := range map[string][]byte{
		"location on another host": mk(igd, "http://203.0.113.1:5000/rootDesc.xml"),
		"location by name":         mk(igd, "http://router.lan:5000/rootDesc.xml"),
		"https":                    mk(igd, "https://192.168.1.1:5000/rootDesc.xml"),
		"not an IGD":               mk("urn:schemas-upnp-org:device:MediaServer:1", "http://192.168.1.1:5000/x.xml"),
		"not 200":                  []byte("HTTP/1.1 404 Not Found\r\nST: " + igd + "\r\nLOCATION: http://192.168.1.1/\r\n\r\n"),
		"garbage":                  []byte("NOTIFY * HTTP/1.1\r\n\r\n"),
	} {
		if _, ok := parseSSDPResponse(b, from); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLimitedBody(t *testing.T) {
	small := &limitedBody{ReadCloser: io.NopCloser(strings.NewReader("hello")), left: 5}
	if b, err := io.ReadAll(small); err != nil || string(b) != "hello" {
		t.Fatalf("exact-size body: %q, %v", b, err)
	}
	big := &limitedBody{ReadCloser: io.NopCloser(strings.NewReader("hello world")), left: 5}
	if _, err := io.ReadAll(big); !errors.Is(err, errBodyTooLarge) {
		t.Fatalf("oversized body: err = %v", err)
	}
}

func TestUPnPServicesStayOnDeviceHost(t *testing.T) {
	for _, tc := range []struct {
		base, control string
		want          int
	}{
		{"", "/ctl", 1},
		{"http://127.0.0.1:1/", "/ctl", 1}, // same host, other port
		{"http://203.0.113.9/", "/ctl", 0},
		{"", "http://203.0.113.9/ctl", 0},
		{"", "https://127.0.0.1:1/ctl", 0}, // same host, TLS
	} {
		desc := strings.Replace(rootDescXML(svcIGD2), "<controlURL>/ctl</controlURL>", "<controlURL>"+tc.control+"</controlURL>", 1)
		if tc.base != "" {
			desc = strings.Replace(desc, "<specVersion>", "<URLBase>"+tc.base+"</URLBase><specVersion>", 1)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, desc) }))
		loc, _ := url.Parse(srv.URL + "/rootDesc.xml")
		hc := newHTTPClient()
		d, err := fetchDescription(context.Background(), hc, loc)
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		services, err := wanServices(d, loc, hc)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(services); got != tc.want {
			t.Errorf("URLBase %q controlURL %q: %d services, want %d", tc.base, tc.control, got, tc.want)
		}
	}
}

// TestHTTPDialEndsWithRequest: net/http dials with a context that is not
// cancelled with the request, so that another request could use the
// connection. The dial of a UPnP request must still end with the request, or
// a gateway that drops the connection attempt keeps it running, after the
// request and after Close, until the operating system's connect timeout.
func TestHTTPDialEndsWithRequest(t *testing.T) {
	hc := newHTTPClient()
	tr := hc.Transport.(limitTransport).tr
	t.Cleanup(tr.CloseIdleConnections) // ends a dial left running by a failure
	dials := make(chan context.Context, 1)
	// A gateway that drops the connection attempt: the dial waits for its
	// context, as net.Dialer does.
	tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://192.0.2.1:5000/rootDesc.xml", nil)
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		resp, err := hc.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		errc <- err
	}()
	dctx := <-dials
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("Do() = %v, want the cancellation", err)
	}
	if dctx.Err() == nil {
		t.Fatal("the dial goes on after its request ended")
	}
}

func TestFetchRootDeviceRejectsOversizedAndRedirects(t *testing.T) {
	big := strings.Repeat("x", maxUPnPBody+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/rootDesc.xml", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "<root>"+big+"</root>")
	}))
	defer srv.Close()
	hc := newHTTPClient()
	loc, _ := url.Parse(srv.URL + "/rootDesc.xml")
	if _, err := fetchDescription(context.Background(), hc, loc); !errors.Is(err, errBodyTooLarge) {
		t.Fatalf("oversized description: err = %v", err)
	}
	loc, _ = url.Parse(srv.URL + "/redirect")
	if _, err := fetchDescription(context.Background(), hc, loc); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect: err = %v, want the 302 itself", err)
	}
}

func TestMapUPnPNextServiceAfterFailure(t *testing.T) {
	igd := newFakeIGD(t, svcIGD1, svcPPP1)
	igd.set(func(f *fakeIGD) { f.failAddsOn = svcIGD1 })
	m := newTestMapper(t, Config{}, testEnv{igd: igd})
	pc := listenLoopback(t)
	info, release, err := m.Map(context.Background(), pc, policy(0, protocol.PortMapUPnP))
	if err != nil || info.Method != protocol.PortMapUPnP || info.External.Port() != portOf(pc) {
		t.Fatalf("Map() = %+v, %v; want the PPP service's mapping", info, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if adds, _, deletes, active := igd.counts(); adds != 1 || deletes != 1 || active != 0 {
		t.Fatalf("adds=%d deletes=%d active=%d, want 1/1/0", adds, deletes, active)
	}

	// When every service refuses, Map reports each failure.
	igd.set(func(f *fakeIGD) { f.failAdds = true })
	_, _, err = m.Map(context.Background(), pc, policy(0, protocol.PortMapUPnP))
	if !errors.Is(err, ErrUnsupported) || upnpCode(err) != 501 {
		t.Fatalf("Map() error = %v, want ErrUnsupported with the SOAP fault", err)
	}
}

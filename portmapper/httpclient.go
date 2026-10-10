package portmapper

import (
	"io"
	"net/http"
)

// HTTP limits for the UPnP device description and SOAP answers.
const (
	maxUPnPBody       = 256 << 10
	maxUPnPHeaderSize = 16 << 10
)

// newHTTPClient returns the client for all UPnP HTTP traffic of one Mapper.
// Keep-alive is off so that no connection, and none of net/http's connection
// goroutines, outlives a request; the proxy environment is ignored because
// the gateway is on the local network; redirects are not followed; bodies are
// limited to maxUPnPBody.
func newHTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: maxUPnPHeaderSize,
	}
	return &http.Client{
		Transport:     limitTransport{tr},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// limitTransport limits every response body to maxUPnPBody.
type limitTransport struct{ rt http.RoundTripper }

func (t limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{ReadCloser: resp.Body, left: maxUPnPBody}
	return resp, nil
}

// limitedBody fails with errBodyTooLarge once more than left bytes arrive,
// rather than truncating silently, so a cut-off description is not parsed.
type limitedBody struct {
	io.ReadCloser
	left int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		var one [1]byte
		if n, err := b.ReadCloser.Read(one[:]); n == 0 && err != nil {
			return 0, err
		}
		return 0, errBodyTooLarge
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, err
}

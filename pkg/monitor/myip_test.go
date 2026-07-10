package monitor

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/xos/serveragent/pkg/util"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func traceResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestFetchIP(t *testing.T) {
	tests := []struct {
		name string
		body string
		ipv6 bool
		want string
	}{
		{name: "IPv4", body: "fl=test\nip=198.51.100.8\n", want: "198.51.100.8"},
		{name: "IPv6", body: "fl=test\nip=2001:db8::8\n", ipv6: true, want: "2001:db8::8"},
		{name: "reject IPv6 for IPv4", body: "ip=2001:db8::8\n", want: ""},
		{name: "reject IPv4 for IPv6", body: "ip=198.51.100.8\n", ipv6: true, want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return traceResponse(test.body), nil
			})}
			if got := fetchIPWithClient([]string{"https://example.test/trace"}, test.ipv6, client); got != test.want {
				t.Fatalf("fetchIPWithClient() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFetchIPFallsBack(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return nil, errors.New("temporary failure")
		}
		return traceResponse("ip=198.51.100.9\n"), nil
	})}

	if got := fetchIPWithClient([]string{"https://first.test", "https://second.test"}, false, client); got != "198.51.100.9" {
		t.Fatalf("fetchIPWithClient() = %q, want %q", got, "198.51.100.9")
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestHTTPGetWithUA(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("User-Agent"); got != util.MacOSChromeUA {
			t.Fatalf("User-Agent = %q, want %q", got, util.MacOSChromeUA)
		}
		return traceResponse("ok"), nil
	})}

	resp, err := httpGetWithUA(client, "https://example.test")
	if err != nil {
		t.Fatalf("httpGetWithUA() error: %v", err)
	}
	resp.Body.Close()
}

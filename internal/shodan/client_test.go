package shodan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const hostJSON = `{
  "ip_str": "203.0.113.7", "org": "Example ISP", "isp": "Example ISP", "asn": "AS64500",
  "os": null, "country_name": "Netherlands", "city": "Amsterdam",
  "last_update": "2026-11-20T08:14:03.123456",
  "data": [
    {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0",
     "timestamp": "2026-11-20T08:14:03.123456", "data": "HTTP/1.1 200 OK",
     "_shodan": {"module": "https"}, "http": {"title": "Router"},
     "vulns": {"CVE-2021-23017": {"cvss": 7.7, "verified": false, "summary": "resolver bug"},
               "CVE-2000-0001": {"cvss": "5.0", "verified": true, "summary": "x"}}},
    {"port": 3389, "transport": "tcp", "timestamp": "2025-01-02T03:04:05.000000",
     "_shodan": {"module": "rdp"}, "data": "` + "\\u00e9" + `xxxxxxxx"}
  ]
}`

func TestHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "good" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Invalid API key"}`))
			return
		}
		switch r.URL.Path {
		case "/shodan/host/203.0.113.7":
			w.Write([]byte(hostJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "No information available for that IP."}`))
		}
	}))
	defer srv.Close()

	c := New()
	c.BaseURL = srv.URL
	c.MaxBanner = 4
	ctx := context.Background()

	scan, err := c.Host(ctx, "good", "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Services) != 2 || scan.Org != "Example ISP" || scan.OS != "" {
		t.Fatalf("unexpected scan: %+v", scan)
	}
	s := scan.Services[0]
	want := time.Date(2026, 11, 20, 8, 14, 3, 123456000, time.UTC)
	if !s.Timestamp.Equal(want) || s.Module != "https" || s.Title != "Router" {
		t.Fatalf("service parsed wrong: %+v", s)
	}
	if len(s.Vulns) != 2 || s.Vulns[0].ID != "CVE-2021-23017" || s.Vulns[1].CVSS != 5.0 {
		t.Fatalf("vulns parsed wrong: %+v", s.Vulns)
	}
	if !strings.HasPrefix(scan.Services[1].Banner, "é") || !strings.Contains(scan.Services[1].Banner, "truncated") {
		t.Fatalf("banner truncation wrong: %q", scan.Services[1].Banner)
	}

	nf, err := c.Host(ctx, "good", "198.51.100.1")
	if err != nil || !nf.NotFound {
		t.Fatalf("404 should give NotFound scan, got %+v, %v", nf, err)
	}

	_, err = c.Host(ctx, "secret-key-123", "203.0.113.7")
	if err == nil || !strings.Contains(err.Error(), "Invalid API key") {
		t.Fatalf("want auth error, got %v", err)
	}
}

func TestErrorsDoNotLeakKey(t *testing.T) {
	c := New()
	c.BaseURL = "http://127.0.0.1:1" // nothing listens here
	_, err := c.Host(context.Background(), "super-secret-key", "203.0.113.7")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "super-secret-key") {
		t.Fatalf("error leaks API key: %v", err)
	}
}

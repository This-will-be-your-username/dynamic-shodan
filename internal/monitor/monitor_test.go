package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"dynamic-shodan/internal/model"
	"dynamic-shodan/internal/shodan"
	"dynamic-shodan/internal/store"
)

func TestCheckOnceRefreshRules(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"ip_str":"x","data":[{"port":80,"transport":"tcp","timestamp":"2020-01-01T00:00:00.000000"}]}`))
	}))
	defer srv.Close()

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st.SaveConfig(model.Config{ShodanAPIKey: "k", Hostname: "home.example"})
	c := shodan.New()
	c.BaseURL = srv.URL
	m := New(st, c)

	ip := netip.MustParseAddr("203.0.113.1")
	m.Resolve = func(context.Context, model.Config) (netip.Addr, error) { return ip, nil }
	clock := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { clock = clock.Add(time.Hour); return clock }
	ctx := context.Background()

	check := func(force bool, wantCalls int32) {
		t.Helper()
		if err := m.CheckOnce(ctx, force); err != nil {
			t.Fatal(err)
		}
		if got := calls.Load(); got != wantCalls {
			t.Fatalf("shodan calls = %d, want %d", got, wantCalls)
		}
	}

	check(false, 1) // first sighting fetches
	check(false, 1) // cached and fresh: no fetch
	check(true, 2)  // forced
	ip = netip.MustParseAddr("203.0.113.2")
	check(false, 3) // IP changed
	ip = netip.MustParseAddr("203.0.113.1")
	check(false, 4) // back to old IP: cached scan predates new ownership

	snap := st.Snapshot()
	if len(snap.History) != 3 || snap.LastError != "" {
		t.Fatalf("history=%d err=%q", len(snap.History), snap.LastError)
	}
	// The 2020 service predates ownership, so it must be classified stale.
	scan := snap.Scans["203.0.113.1"]
	owner, ok := model.OwnershipFor(snap.History, scan.IP, scan.FetchedAt)
	fresh, stale := model.Classify(scan, owner, ok)
	if len(fresh) != 0 || len(stale) != 1 {
		t.Fatalf("fresh=%d stale=%d", len(fresh), len(stale))
	}
}

func TestDNSServerAddr(t *testing.T) {
	for in, want := range map[string]string{
		"1.1.1.1":           "1.1.1.1:53",
		"1.1.1.1:5353":      "1.1.1.1:5353",
		"2606:4700::1111":   "[2606:4700::1111]:53",
		"[2606:4700::1111]": "[2606:4700::1111]:53",
	} {
		if got := DNSServerAddr(in); got != want {
			t.Errorf("DNSServerAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

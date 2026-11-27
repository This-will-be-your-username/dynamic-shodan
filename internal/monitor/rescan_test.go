package monitor

import (
	"context"
	"errors"
	"fmt"
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

func TestRescan(t *testing.T) {
	var hosts, submits, infos atomic.Int32
	var status atomic.Value
	status.Store("QUEUE")
	var lastIPs atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api-info":
			// Balance drops by one for every scan submitted so far.
			infos.Add(1)
			fmt.Fprintf(w, `{"plan":"dev","query_credits":50,"scan_credits":%d}`, 100-submits.Load())
		case r.Method == http.MethodPost && r.URL.Path == "/shodan/scan":
			submits.Add(1)
			lastIPs.Store(r.FormValue("ips"))
			w.Write([]byte(`{"id":"SCAN1","count":1,"credits_left":99}`))
		case r.URL.Path == "/shodan/scan/SCAN1":
			w.Write([]byte(`{"id":"SCAN1","count":1,"status":"` + status.Load().(string) + `"}`))
		default:
			hosts.Add(1)
			w.Write([]byte(`{"ip_str":"x","data":[]}`))
		}
	}))
	defer srv.Close()

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st.SaveConfig(model.Config{ShodanAPIKey: "k", Hostname: "home.example", RescanOnIPChange: true})
	c := shodan.New()
	c.BaseURL = srv.URL
	m := New(st, c)
	ip := netip.MustParseAddr("203.0.113.1")
	m.Resolve = func(context.Context, model.Config) (netip.Addr, error) { return ip, nil }
	clock := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	ctx := context.Background()

	check := func(wantHosts, wantSubmits int32) {
		t.Helper()
		if err := m.CheckOnce(ctx, false); err != nil {
			t.Fatal(err)
		}
		if h, s := hosts.Load(), submits.Load(); h != wantHosts || s != wantSubmits {
			t.Fatalf("host lookups=%d scan requests=%d, want %d/%d", h, s, wantHosts, wantSubmits)
		}
	}

	credits := func(wantScan int, wantInfos int32) {
		t.Helper()
		c := st.Snapshot().CreditsFor("k")
		if c == nil || c.Scan != wantScan || infos.Load() != wantInfos {
			t.Fatalf("credits = %+v after %d api-info call(s), want scan=%d after %d", c, infos.Load(), wantScan, wantInfos)
		}
	}

	check(1, 0)     // first IP ever seen: no rescan
	credits(100, 1) // unknown balance looked up
	check(1, 0)
	credits(100, 1) // known balance: no repeat lookup
	ip = netip.MustParseAddr("203.0.113.2")
	check(2, 1)    // IP changed: rescan requested and host fetched
	credits(99, 2) // re-checked after the automatic rescan
	if got := lastIPs.Load(); got != "203.0.113.2" {
		t.Fatalf("scanned %v", got)
	}
	r := st.Snapshot().Rescan
	if r == nil || !r.Auto || r.ID != "SCAN1" || r.CreditsLeft != 99 || !r.Pending(clock) {
		t.Fatalf("rescan = %+v", r)
	}
	check(2, 1) // still queued: no re-fetch
	if s := st.Snapshot().Rescan.Status; s != "QUEUE" {
		t.Fatalf("status %q", s)
	}

	// A manual request while one is running for the same IP is refused.
	if _, err := m.RequestRescan(ctx); !errors.Is(err, ErrRescanPending) {
		t.Fatalf("err = %v", err)
	}

	status.Store("DONE")
	check(3, 1)    // finished: host re-fetched despite fresh cache
	credits(99, 3) // re-checked when the scan finished
	if st.Snapshot().Rescan.Pending(clock) {
		t.Fatal("rescan still pending after DONE")
	}
	check(3, 1) // nothing more to do

	// Manual request is allowed again once the earlier one is done.
	res, err := m.RequestRescan(ctx)
	if err != nil || res.Auto || submits.Load() != 2 {
		t.Fatalf("manual rescan: %+v, %v, submits=%d", res, err, submits.Load())
	}
	credits(98, 4) // re-checked after the manual rescan

	// A different key makes the balance unknown until it is looked up again.
	cfg := st.Config()
	cfg.ShodanAPIKey = "k2"
	st.SaveConfig(cfg)
	if st.Snapshot().CreditsFor("k2") != nil {
		t.Fatal("credits of the old key reported for the new one")
	}
}

func TestRescanDisabledOrFailing(t *testing.T) {
	var submits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/shodan/scan" {
			submits.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Insufficient scan credits"}`))
			return
		}
		w.Write([]byte(`{"ip_str":"x","data":[]}`))
	}))
	defer srv.Close()

	st, _ := store.Open(t.TempDir())
	st.SaveConfig(model.Config{ShodanAPIKey: "k", Hostname: "home.example"})
	c := shodan.New()
	c.BaseURL = srv.URL
	m := New(st, c)
	ip := netip.MustParseAddr("203.0.113.1")
	m.Resolve = func(context.Context, model.Config) (netip.Addr, error) { return ip, nil }
	ctx := context.Background()

	m.CheckOnce(ctx, false)
	ip = netip.MustParseAddr("203.0.113.2")
	m.CheckOnce(ctx, false)
	if submits.Load() != 0 {
		t.Fatal("rescan requested while the setting is off")
	}

	// A failed request is recorded (not pending) and doesn't fail the check.
	cfg := st.Config()
	cfg.RescanOnIPChange = true
	st.SaveConfig(cfg)
	ip = netip.MustParseAddr("203.0.113.3")
	if err := m.CheckOnce(ctx, false); err != nil {
		t.Fatal(err)
	}
	r := st.Snapshot().Rescan
	if submits.Load() != 1 || r == nil || r.Error == "" || r.Pending(time.Now()) {
		t.Fatalf("submits=%d rescan=%+v", submits.Load(), r)
	}
	if _, err := m.RequestRescan(ctx); err == nil {
		t.Fatal("manual rescan should report the API error")
	}
}

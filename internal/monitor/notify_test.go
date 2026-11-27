package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamic-shodan/internal/model"
	"dynamic-shodan/internal/notify"
	"dynamic-shodan/internal/shodan"
	"dynamic-shodan/internal/store"
)

const tgToken = "123456789:AAEhBP0av28PmUIIM5HRmwhAJb6DaNYVQ0x"

func TestNotifications(t *testing.T) {
	// Fake Shodan: one stale service (2020) plus whatever fresh ports are set.
	var mu sync.Mutex
	freshPorts := []int{443}
	shodanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api-info" {
			w.Write([]byte(`{"plan":"dev","query_credits":100,"scan_credits":100}`))
			return
		}
		mu.Lock()
		defer mu.Unlock()
		data := []map[string]any{{"port": 23, "transport": "tcp", "timestamp": "2020-01-01T00:00:00.000000"}}
		for _, p := range freshPorts {
			// Far future, so always after the ownership start: current.
			data = append(data, map[string]any{"port": p, "transport": "tcp", "timestamp": "2099-01-01T00:00:00.000000"})
		}
		json.NewEncoder(w).Encode(map[string]any{"ip_str": "x", "data": data})
	}))
	defer shodanSrv.Close()

	// Fake Telegram: collect message texts.
	var msgs []string
	tgSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Text string `json:"text"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		msgs = append(msgs, body.Text)
		mu.Unlock()
		w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer tgSrv.Close()

	st, _ := store.Open(t.TempDir())
	st.SaveConfig(model.Config{
		ShodanAPIKey: "k", Hostname: "home.example",
		TelegramBotToken: tgToken, TelegramChatID: "42",
		NotifyIPChange: true, NotifyExposure: true, NotifyHealth: true,
	})
	c := shodan.New()
	c.BaseURL = shodanSrv.URL
	n := notify.New(st.Config)
	n.TG.BaseURL = tgSrv.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	m := New(st, c)
	m.Notifier = n
	ip := netip.MustParseAddr("203.0.113.1")
	var resolveErr error
	m.Resolve = func(context.Context, model.Config) (netip.Addr, error) { return ip, resolveErr }
	clock := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { clock = clock.Add(time.Hour); return clock }

	// step runs a forced check and returns the messages it produced.
	seen := 0
	step := func(want int) []string {
		t.Helper()
		m.CheckOnce(ctx, true)
		deadline := time.Now().Add(3 * time.Second)
		for {
			mu.Lock()
			got := len(msgs)
			mu.Unlock()
			if got >= seen+want || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond) // catch unexpected extras
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), msgs[seen:]...)
		seen = len(msgs)
		if len(out) != want {
			t.Fatalf("got %d message(s), want %d: %q", len(out), want, out)
		}
		return out
	}

	// 1. First sighting: baseline exposure lists the current service only.
	out := step(1)
	if !strings.Contains(out[0], "443/tcp") || strings.Contains(out[0], "23/tcp") {
		t.Fatalf("baseline should list 443 but not stale 23:\n%s", out[0])
	}
	// 2. Nothing new: silence.
	step(0)
	// 3. A new current service appears.
	mu.Lock()
	freshPorts = []int{443, 8443}
	mu.Unlock()
	out = step(1)
	if !strings.Contains(out[0], "New exposure") || !strings.Contains(out[0], "8443/tcp") || strings.Contains(out[0], "443/tcp\n") {
		t.Fatalf("want only 8443 as new:\n%s", out[0])
	}
	// 4. IP change: change notice, then baseline exposure for the new IP.
	ip = netip.MustParseAddr("203.0.113.2")
	out = step(2)
	if !strings.Contains(out[0], "Public IP changed") || !strings.Contains(out[0], "203.0.113.1") || !strings.Contains(out[1], "203.0.113.2") {
		t.Fatalf("unexpected IP-change messages: %q", out)
	}
	// 5. Failures alert once, recovery alerts once.
	resolveErr = errors.New("no such host")
	out = step(1)
	if !strings.Contains(out[0], "failing") || !strings.Contains(out[0], "no such host") {
		t.Fatalf("unexpected failure message:\n%s", out[0])
	}
	step(0)
	resolveErr = nil
	out = step(1)
	if !strings.Contains(out[0], "working again") {
		t.Fatalf("unexpected recovery message:\n%s", out[0])
	}

	// 6. Toggles: with exposure alerts off, a new service is silent.
	cfg := st.Config()
	cfg.NotifyExposure = false
	st.SaveConfig(cfg)
	mu.Lock()
	freshPorts = []int{443, 8443, 9000}
	mu.Unlock()
	step(0)
}

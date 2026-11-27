package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamic-shodan/internal/model"
)

const testToken = "123456789:AAEhBP0av28PmUIIM5HRmwhAJb6DaNYVQ0x"

// fakeTelegram records sendMessage calls and serves getMe/getUpdates.
type fakeTelegram struct {
	mu       sync.Mutex
	sent     []map[string]any
	failWith int // HTTP status to fail sendMessage with, 0 = succeed
}

func (f *fakeTelegram) server(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/bot"+testToken+"/") {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"ok":false,"error_code":401,"description":"Unauthorized"}`))
			return
		}
		switch strings.TrimPrefix(r.URL.Path, "/bot"+testToken+"/") {
		case "getMe":
			w.Write([]byte(`{"ok":true,"result":{"id":1,"is_bot":true,"username":"test_bot"}}`))
		case "getUpdates":
			w.Write([]byte(`{"ok":true,"result":[
				{"update_id":1,"message":{"chat":{"id":111,"type":"private","first_name":"Old"}}},
				{"update_id":2,"message":{"chat":{"id":-1002,"type":"supergroup","title":"Ops"}}},
				{"update_id":3,"message":{"chat":{"id":111,"type":"private","first_name":"Old"}}}]}`))
		case "sendMessage":
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.failWith != 0 {
				w.WriteHeader(f.failWith)
				w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			f.sent = append(f.sent, body)
			w.Write([]byte(`{"ok":true,"result":{}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func (f *fakeTelegram) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func TestTelegramClient(t *testing.T) {
	fake := &fakeTelegram{}
	srv := fake.server(t)
	defer srv.Close()
	tg := NewTelegram()
	tg.BaseURL = srv.URL
	ctx := context.Background()

	if name, err := tg.BotName(ctx, testToken); err != nil || name != "test_bot" {
		t.Fatalf("BotName = %q, %v", name, err)
	}
	if err := tg.Send(ctx, testToken, "42", "<b>hi</b>"); err != nil {
		t.Fatal(err)
	}
	if got := fake.sent[0]; got["chat_id"] != "42" || got["parse_mode"] != "HTML" {
		t.Fatalf("unexpected sendMessage body: %v", got)
	}
	chats, err := tg.RecentChats(ctx, testToken)
	if err != nil || len(chats) != 2 || chats[0].ID != 111 || chats[1].Title != "Ops" {
		t.Fatalf("RecentChats = %+v, %v", chats, err)
	}

	fake.failWith = http.StatusBadRequest
	err = tg.Send(ctx, testToken, "42", "x")
	if err == nil || !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("want chat-not-found error, got %v", err)
	}
	_, err = tg.BotName(ctx, "999999999:wrongwrongwrongwrongwrongwrongwrong")
	if err == nil || !strings.Contains(err.Error(), "check the bot token") {
		t.Fatalf("want unauthorized error, got %v", err)
	}
}

func TestTelegramErrorsDoNotLeakToken(t *testing.T) {
	tg := NewTelegram()
	tg.BaseURL = "http://127.0.0.1:1" // nothing listens here
	err := tg.Send(context.Background(), testToken, "42", "x")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "AAEhBP0") {
		t.Fatalf("error leaks bot token: %v", err)
	}
}

func TestValidation(t *testing.T) {
	for s, want := range map[string]bool{
		testToken: true, "123:short": false, "abc:" + strings.Repeat("x", 35): false, "": false,
	} {
		if ValidToken(s) != want {
			t.Errorf("ValidToken(%q) != %v", s, want)
		}
	}
	for s, want := range map[string]bool{
		"123456789": true, "-1001234567890": true, "@mychannel": true, "@ab": false, "12a": false, "": false,
	} {
		if ValidChatID(s) != want {
			t.Errorf("ValidChatID(%q) != %v", s, want)
		}
	}
}

func TestNotifierRespectsToggles(t *testing.T) {
	fake := &fakeTelegram{}
	srv := fake.server(t)
	defer srv.Close()

	var mu sync.Mutex
	cfg := model.Config{TelegramBotToken: testToken, TelegramChatID: "42", NotifyIPChange: true}
	n := New(func() model.Config { mu.Lock(); defer mu.Unlock(); return cfg })
	n.TG.BaseURL = srv.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	n.Notify(EventExposure, "disabled event")
	n.Notify(EventIPChange, "enabled event")
	waitFor(t, func() bool { return fake.count() == 1 })
	if fake.sent[0]["text"] != "enabled event" {
		t.Fatalf("sent %v", fake.sent[0]["text"])
	}
	if n.Status().LastSent.IsZero() {
		t.Fatal("status not updated")
	}

	mu.Lock()
	cfg.TelegramChatID = "" // not configured: nothing is sent
	mu.Unlock()
	n.Notify(EventIPChange, "dropped")
	time.Sleep(100 * time.Millisecond)
	if fake.count() != 1 {
		t.Fatal("sent while Telegram was not configured")
	}

	var nilNotifier *Notifier
	nilNotifier.Notify(EventIPChange, "no panic")
}

func TestDiffExposureAndMessage(t *testing.T) {
	svc := func(port int, vulns ...model.Vuln) model.Verdict {
		return model.Verdict{Service: model.Service{Port: port, Transport: "tcp", Product: "<svc>", Vulns: vulns}}
	}
	prev := []model.Verdict{svc(22), svc(443, model.Vuln{ID: "CVE-A", CVSS: 5})}
	cur := []model.Verdict{svc(22), svc(443, model.Vuln{ID: "CVE-A", CVSS: 5}, model.Vuln{ID: "CVE-B", CVSS: 9.8}), svc(3389)}

	e := DiffExposure("203.0.113.1", prev, true, cur)
	if len(e.NewServices) != 1 || e.NewServices[0].Port != 3389 || len(e.NewVulns) != 1 || e.NewVulns[0].ID != "CVE-B" {
		t.Fatalf("diff = %+v", e)
	}
	msg := ExposureMessage(e)
	if !strings.Contains(msg, "New exposure") || !strings.Contains(msg, "3389/tcp") || !strings.Contains(msg, "CVE-B") {
		t.Fatalf("message missing content:\n%s", msg)
	}
	if strings.Contains(msg, "<svc>") {
		t.Fatalf("product name not HTML-escaped:\n%s", msg)
	}
	if !DiffExposure("x", cur, true, cur).Empty() {
		t.Fatal("identical scans should produce no alert")
	}
	if b := DiffExposure("x", nil, false, cur); !b.Baseline || len(b.NewServices) != 3 {
		t.Fatalf("baseline diff = %+v", b)
	}
}

func TestTruncate(t *testing.T) {
	long := strings.Repeat("<b>line</b>\n", 1000)
	got := Truncate(long, MaxMessageLen)
	if len(got) > MaxMessageLen || strings.Count(got, "<b>") != strings.Count(got, "</b>") {
		t.Fatalf("bad truncation: len=%d", len(got))
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

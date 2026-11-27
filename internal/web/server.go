// Package web serves the dashboard, IP history and configuration pages.
package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"dynamic-shodan/internal/model"
	"dynamic-shodan/internal/monitor"
	"dynamic-shodan/internal/shodan"
	"dynamic-shodan/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	store  *store.Store
	mon    *monitor.Monitor
	shodan *shodan.Client
	pages  map[string]*template.Template

	// Optional HTTP basic auth; empty user disables it.
	AuthUser, AuthPass string
}

func New(s *store.Store, m *monitor.Monitor, c *shodan.Client) (*Server, error) {
	srv := &Server{store: s, mon: m, shodan: c, pages: map[string]*template.Template{}}
	for _, name := range []string{"dashboard", "history", "config"} {
		t, err := template.New(name).Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("parsing %s template: %w", name, err)
		}
		srv.pages[name] = t
	}
	return srv, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /history", s.history)
	mux.HandleFunc("POST /history/{idx}/start", s.setPeriodStart)
	mux.HandleFunc("GET /config", s.configPage)
	mux.HandleFunc("POST /config", s.saveConfig)
	mux.HandleFunc("POST /config/test", s.testKey)
	mux.HandleFunc("POST /check", s.checkNow)
	mux.HandleFunc("GET /api/status", s.apiStatus)
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	// Reject cross-site form posts (CSRF) using Sec-Fetch-Site / Origin.
	var h http.Handler = http.NewCrossOriginProtection().Handler(mux)
	h = s.auth(h)
	return securityHeaders(h)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "no-referrer")
		hdr.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.Handler) http.Handler {
	if s.AuthUser == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(u), []byte(s.AuthUser)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(p), []byte(s.AuthPass)) == 1
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="dynamic-shodan", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- rendering ----

type page struct {
	Title    string
	Active   string
	Flash    string
	FlashErr string
	Data     any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title string, data any) {
	p := page{Title: title, Active: name, Flash: r.URL.Query().Get("ok"), FlashErr: r.URL.Query().Get("err"), Data: data}
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func redirect(w http.ResponseWriter, r *http.Request, path, key, msg string) {
	if msg != "" {
		path += "?" + url.Values{key: {msg}}.Encode()
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// ---- dashboard ----

type dashView struct {
	Configured bool
	Hostname   string
	Current    *model.Period
	ViewIP     string
	Viewing    bool // looking at a historical IP rather than the current one
	Scan       *model.Scan
	Owner      model.Period
	OwnerOK    bool
	Fresh      []model.Verdict
	Stale      []model.Verdict
	Vulns      []model.Vuln
	LastCheck  time.Time
	LastError  string
	NextCheck  time.Time
	Busy       bool
}

func (s *Server) buildDash(viewIP string) dashView {
	cfg := s.store.Config()
	snap := s.store.Snapshot()
	busy, next := s.mon.Status()
	v := dashView{
		Configured: cfg.Configured(),
		Hostname:   cfg.Hostname,
		LastCheck:  snap.LastCheck,
		LastError:  snap.LastError,
		NextCheck:  next,
		Busy:       busy,
	}
	if cur, ok := snap.Current(); ok {
		v.Current = &cur
		if viewIP == "" {
			viewIP = cur.IP
		}
	}
	v.ViewIP = viewIP
	v.Viewing = v.Current != nil && viewIP != v.Current.IP
	if scan := snap.Scans[viewIP]; scan != nil {
		v.Scan = scan
		v.Owner, v.OwnerOK = model.OwnershipFor(snap.History, scan.IP, scan.FetchedAt)
		v.Fresh, v.Stale = model.Classify(scan, v.Owner, v.OwnerOK)
		v.Vulns = model.FreshVulns(v.Fresh)
	}
	return v
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip != "" {
		if _, err := netip.ParseAddr(ip); err != nil {
			ip = ""
		}
	}
	s.render(w, r, "dashboard", "Dashboard", s.buildDash(ip))
}

func (s *Server) checkNow(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	if err := s.mon.CheckOnce(ctx, true); err != nil {
		redirect(w, r, "/", "err", "Check failed: "+err.Error())
		return
	}
	redirect(w, r, "/", "ok", "Check complete.")
}

// ---- history ----

type historyRow struct {
	Index    int
	Period   model.Period
	Current  bool
	ScanAt   time.Time
	HasScan  bool
	MinStart time.Time // start must be after this (zero = no lower bound)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	snap := s.store.Snapshot()
	rows := make([]historyRow, 0, len(snap.History))
	for i, p := range snap.History {
		row := historyRow{Index: i, Period: p, Current: i == len(snap.History)-1}
		if i > 0 {
			row.MinStart = snap.History[i-1].LastSeen
		}
		// The cached scan belongs to this period only if it was fetched during it.
		if sc := snap.Scans[p.IP]; sc != nil {
			if owner, ok := model.OwnershipFor(snap.History, p.IP, sc.FetchedAt); ok && owner.FirstSeen.Equal(p.FirstSeen) {
				row.HasScan, row.ScanAt = true, sc.FetchedAt
			}
		}
		rows = append(rows, row)
	}
	slices.Reverse(rows)
	s.render(w, r, "history", "IP history", rows)
}

func (s *Server) setPeriodStart(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		redirect(w, r, "/history", "err", "Invalid entry.")
		return
	}
	start, err := time.ParseInLocation("2006-01-02T15:04", r.FormValue("start"), time.Local)
	if err != nil {
		redirect(w, r, "/history", "err", "Invalid date/time.")
		return
	}
	if err := s.store.SetPeriodStart(idx, start); err != nil {
		redirect(w, r, "/history", "err", err.Error())
		return
	}
	redirect(w, r, "/history", "ok", "Ownership start updated; findings re-evaluated.")
}

// ---- config ----

type configView struct {
	Cfg     model.Config
	KeyHint string
	DataDir string
	MaxMin  int
	MaxHrs  int
}

func (s *Server) configPage(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.Config()
	hint := cfg.KeyHint()
	cfg.ShodanAPIKey = "" // never send the key back to the browser
	s.render(w, r, "config", "Configuration", configView{
		Cfg: cfg, KeyHint: hint, DataDir: s.store.Dir(),
		MaxMin: model.MaxCheckIntervalMinutes, MaxHrs: model.MaxShodanRefreshHours,
	})
}

func (s *Server) saveConfig(w http.ResponseWriter, r *http.Request) {
	old := s.store.Config()
	cfg, err := parseConfigForm(r, old)
	if err != nil {
		redirect(w, r, "/config", "err", err.Error())
		return
	}
	if err := s.store.SaveConfig(cfg); err != nil {
		redirect(w, r, "/config", "err", "Saving failed: "+err.Error())
		return
	}
	forceShodan := cfg.ShodanAPIKey != old.ShodanAPIKey
	s.mon.Trigger(forceShodan)
	redirect(w, r, "/config", "ok", "Saved. A check has been started.")
}

func (s *Server) testKey(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.FormValue("shodan_api_key"))
	if key == "" {
		key = s.store.Config().ShodanAPIKey
	}
	if key == "" {
		redirect(w, r, "/config", "err", "Enter an API key to test.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	info, err := s.shodan.APIInfo(ctx, key)
	if err != nil {
		redirect(w, r, "/config", "err", "Key test failed: "+err.Error())
		return
	}
	redirect(w, r, "/config", "ok", fmt.Sprintf("Key is valid (plan: %s, query credits: %d, scan credits: %d). Not saved yet unless you press Save.",
		info.Plan, info.QueryCredits, info.ScanCredits))
}

func parseConfigForm(r *http.Request, old model.Config) (model.Config, error) {
	cfg := old
	if r.FormValue("clear_key") == "on" {
		cfg.ShodanAPIKey = ""
	} else if k := strings.TrimSpace(r.FormValue("shodan_api_key")); k != "" {
		if strings.ContainsAny(k, " \t\r\n") || len(k) > 128 {
			return old, fmt.Errorf("that doesn't look like a Shodan API key")
		}
		cfg.ShodanAPIKey = k
	}

	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.FormValue("hostname"))), ".")
	if host != "" && !validHostname(host) {
		return old, fmt.Errorf("invalid hostname %q", host)
	}
	cfg.Hostname = host

	dns := strings.TrimSpace(r.FormValue("dns_server"))
	if dns != "" {
		h, _, err := net.SplitHostPort(monitor.DNSServerAddr(dns))
		if err != nil {
			return old, fmt.Errorf("invalid DNS server %q", dns)
		}
		if _, err := netip.ParseAddr(h); err != nil {
			return old, fmt.Errorf("DNS server must be an IP address (optionally with :port)")
		}
	}
	cfg.DNSServer = dns

	var err error
	if cfg.CheckIntervalMinutes, err = intField(r, "check_interval_minutes", 1, model.MaxCheckIntervalMinutes); err != nil {
		return old, err
	}
	if cfg.ShodanRefreshHours, err = intField(r, "shodan_refresh_hours", 1, model.MaxShodanRefreshHours); err != nil {
		return old, err
	}
	return cfg, nil
}

func intField(r *http.Request, name string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(r.FormValue(name)))
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s must be a whole number between %d and %d", strings.ReplaceAll(name, "_", " "), lo, hi)
	}
	return n, nil
}

func validHostname(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// ---- JSON API ----

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	d := s.buildDash("")
	out := map[string]any{
		"hostname":       d.Hostname,
		"configured":     d.Configured,
		"current":        d.Current,
		"last_check":     d.LastCheck,
		"next_check":     d.NextCheck,
		"last_error":     d.LastError,
		"ownership":      nil,
		"scan_fetched":   nil,
		"fresh_services": d.Fresh,
		"stale_count":    len(d.Stale),
		"fresh_vulns":    d.Vulns,
	}
	if d.OwnerOK {
		out["ownership"] = d.Owner
	}
	if d.Scan != nil {
		out["scan_fetched"] = d.Scan.FetchedAt
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// ---- template helpers ----

var funcs = template.FuncMap{
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("2006-01-02 15:04:05 MST")
	},
	"day": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("2006-01-02 15:04")
	},
	"dtlocal": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Local().Format("2006-01-02T15:04")
	},
	"ago":   func(t time.Time) string { return human(time.Since(t), "ago", "from now") },
	"until": func(t time.Time) string { return human(time.Until(t), "from now", "ago") },
	"span": func(a, b time.Time) string {
		return human(b.Sub(a), "", "")
	},
	"join": strings.Join,
	"sev": func(c float64) string {
		switch {
		case c >= 9:
			return "crit"
		case c >= 7:
			return "high"
		case c >= 4:
			return "med"
		case c > 0:
			return "low"
		}
		return "none"
	},
	"cvss": func(c float64) string {
		if c == 0 {
			return "n/a"
		}
		return strconv.FormatFloat(c, 'f', 1, 64)
	},
}

func human(d time.Duration, pos, neg string) string {
	suffix := pos
	if d < 0 {
		d, suffix = -d, neg
	}
	var s string
	switch {
	case d < time.Minute:
		s = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		s = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		s = fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		s = fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	}
	if suffix == "" {
		return s
	}
	return s + " " + suffix
}

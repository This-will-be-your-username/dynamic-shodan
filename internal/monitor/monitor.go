// Package monitor periodically resolves the dynamic DNS hostname, records
// IP changes, and refreshes Shodan intel for the current address.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"dynamic-shodan/internal/model"
	"dynamic-shodan/internal/shodan"
	"dynamic-shodan/internal/store"
)

// Resolver turns the configured hostname into the current public IPv4.
type Resolver func(ctx context.Context, cfg model.Config) (netip.Addr, error)

type Monitor struct {
	store   *store.Store
	shodan  *shodan.Client
	Resolve Resolver
	Now     func() time.Time

	trigger chan bool // value = force Shodan refresh
	checkMu sync.Mutex

	mu        sync.Mutex
	busy      bool
	nextCheck time.Time
}

func New(s *store.Store, c *shodan.Client) *Monitor {
	return &Monitor{store: s, shodan: c, Resolve: DefaultResolver, Now: time.Now, trigger: make(chan bool, 1)}
}

// Status reports whether a check is running and when the next is due.
func (m *Monitor) Status() (busy bool, next time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.busy, m.nextCheck
}

// Trigger asks the background loop to check now without blocking.
func (m *Monitor) Trigger(force bool) {
	for {
		select {
		case m.trigger <- force:
			return
		default:
		}
		select {
		case old := <-m.trigger:
			force = force || old
		default:
		}
	}
}

// Run checks immediately, then on every configured interval until ctx ends.
func (m *Monitor) Run(ctx context.Context) {
	force := false
	for {
		if err := m.CheckOnce(ctx, force); err != nil && ctx.Err() == nil {
			log.Printf("check: %v", err)
		}
		interval := m.store.Config().CheckInterval()
		// Follow a running on-demand scan more closely so its results show
		// up soon after Shodan finishes.
		if m.store.Snapshot().Rescan.Pending(m.Now()) && interval > RescanPollInterval {
			interval = RescanPollInterval
		}
		m.mu.Lock()
		m.nextCheck = time.Now().Add(interval)
		m.mu.Unlock()
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case force = <-m.trigger:
			t.Stop()
		case <-t.C:
			force = false
		}
	}
}

// RescanPollInterval is how often a running on-demand scan is checked.
const RescanPollInterval = 2 * time.Minute

// CheckOnce resolves the hostname, records the IP, and fetches Shodan intel
// when the IP changed, the cached scan predates the current ownership
// period, the cache is older than the refresh interval, a requested rescan
// has just finished, or force is set. If enabled, it also requests a
// Shodan rescan when the IP changes.
func (m *Monitor) CheckOnce(ctx context.Context, force bool) error {
	m.checkMu.Lock()
	defer m.checkMu.Unlock()
	m.setBusy(true)
	defer m.setBusy(false)

	cfg := m.store.Config()
	now := m.Now()
	if cfg.Hostname == "" {
		return m.finish(now, errors.New("no dynamic DNS hostname configured"))
	}

	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	addr, err := m.Resolve(rctx, cfg)
	cancel()
	if err != nil {
		return m.finish(now, fmt.Errorf("resolving %s: %w", cfg.Hostname, err))
	}
	ip := addr.String()

	changed, err := m.store.ObserveIP(ip, cfg.Hostname, now)
	if err != nil {
		return m.finish(now, err)
	}
	if changed {
		log.Printf("public IP is now %s (via %s)", ip, cfg.Hostname)
	}

	if cfg.ShodanAPIKey == "" {
		return m.finish(now, errors.New("no Shodan API key configured"))
	}

	snap := m.store.Snapshot()
	// len > 1: a real change, not the first address the app has seen.
	if changed && cfg.RescanOnIPChange && len(snap.History) > 1 {
		if _, err := m.requestRescan(ctx, cfg, ip, now, true); err != nil {
			log.Printf("rescan: %v", err)
		}
	} else if r := snap.Rescan; r.Pending(now) && r.IP == ip && m.pollRescan(ctx, cfg, *r, now) {
		force = true
	}

	// Fill in the credit balance whenever it isn't known yet (first run,
	// new key, or an earlier lookup failed).
	if m.store.Snapshot().CreditsFor(cfg.ShodanAPIKey) == nil {
		m.refreshCredits(ctx, cfg, now, -1)
	}

	owner, _ := model.OwnershipFor(snap.History, ip, now)
	if prev := snap.Scans[ip]; !force && prev != nil &&
		!prev.FetchedAt.Before(owner.FirstSeen) &&
		now.Sub(prev.FetchedAt) < cfg.ShodanRefresh() {
		return m.finish(now, nil)
	}

	sctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	scan, err := m.shodan.Host(sctx, cfg.ShodanAPIKey, ip)
	cancel()
	if err != nil {
		return m.finish(now, err)
	}
	// Stamp with the check time so the scan maps exactly onto the
	// ownership period just recorded.
	scan.FetchedAt = now
	if err := m.store.SaveScan(scan); err != nil {
		return m.finish(now, err)
	}
	log.Printf("shodan: %s has %d service record(s)", ip, len(scan.Services))
	return m.finish(now, nil)
}

// ErrRescanPending is returned by RequestRescan while an earlier rescan of
// the same IP is still running.
var ErrRescanPending = errors.New("a rescan of this IP is already in progress")

// RequestRescan asks Shodan to scan the current IP now. The result is
// picked up automatically once Shodan reports the scan as done.
func (m *Monitor) RequestRescan(ctx context.Context) (model.Rescan, error) {
	m.checkMu.Lock()
	defer m.checkMu.Unlock()
	cfg := m.store.Config()
	if cfg.ShodanAPIKey == "" {
		return model.Rescan{}, errors.New("no Shodan API key configured")
	}
	snap := m.store.Snapshot()
	cur, ok := snap.Current()
	if !ok {
		return model.Rescan{}, errors.New("current IP is not known yet")
	}
	now := m.Now()
	if r := snap.Rescan; r.Pending(now) && r.IP == cur.IP {
		return *r, ErrRescanPending
	}
	r, err := m.requestRescan(ctx, cfg, cur.IP, now, false)
	if err == nil {
		m.Trigger(false) // reschedule the loop to follow the scan
	}
	return r, err
}

// requestRescan submits an on-demand scan and records the outcome, failed
// or not, so the dashboard can show it.
func (m *Monitor) requestRescan(ctx context.Context, cfg model.Config, ip string, now time.Time, auto bool) (model.Rescan, error) {
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	id, credits, err := m.shodan.RequestScan(sctx, cfg.ShodanAPIKey, ip)
	cancel()
	r := model.Rescan{ID: id, IP: ip, RequestedAt: now, Auto: auto, CreditsLeft: credits, Status: "SUBMITTING"}
	if err != nil {
		r.Status, r.Error = "", "request failed: "+err.Error()
		err = fmt.Errorf("requesting Shodan rescan of %s: %w", ip, err)
	} else {
		log.Printf("shodan: requested rescan of %s (scan %s, %d credit(s) left)", ip, id, credits)
	}
	if serr := m.store.SetRescan(r); serr != nil && err == nil {
		err = serr
	}
	fallback := -1
	if r.Error == "" {
		fallback = credits
	}
	m.refreshCredits(ctx, cfg, now, fallback)
	return r, err
}

// refreshCredits looks up the key's credit balance and stores it. If the
// lookup fails and fallback is >= 0 (a scan credit count Shodan just
// reported), that count is stored instead; otherwise the old value stays.
func (m *Monitor) refreshCredits(ctx context.Context, cfg model.Config, now time.Time, fallback int) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	info, err := m.shodan.APIInfo(cctx, cfg.ShodanAPIKey)
	cancel()
	c := model.Credits{CheckedAt: now, KeyID: model.KeyID(cfg.ShodanAPIKey)}
	switch {
	case err == nil:
		c.Scan, c.Query, c.Plan = info.ScanCredits, info.QueryCredits, info.Plan
	case fallback >= 0:
		log.Printf("credits: %v (using count from scan request)", err)
		c.Scan = fallback
		if old := m.store.Snapshot().CreditsFor(cfg.ShodanAPIKey); old != nil {
			c.Query, c.Plan = old.Query, old.Plan
		}
	default:
		log.Printf("credits: %v", err)
		return
	}
	if err := m.store.SetCredits(c); err != nil {
		log.Printf("credits: %v", err)
	}
}

// pollRescan updates the status of a running rescan and reports whether it
// has just finished, meaning the host data should be re-fetched.
func (m *Monitor) pollRescan(ctx context.Context, cfg model.Config, r model.Rescan, now time.Time) bool {
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	status, err := m.shodan.ScanStatus(sctx, cfg.ShodanAPIKey, r.ID)
	cancel()
	var apiErr *shodan.APIError
	switch {
	case errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 && apiErr.Status != http.StatusTooManyRequests:
		r.Error = "status check failed: " + err.Error() // won't fix itself; stop polling
	case err != nil:
		log.Printf("rescan status: %v", err) // transient; try again next check
		return false
	default:
		r.Status = status
		if status == shodan.ScanDone {
			r.CompletedAt = now
			log.Printf("shodan: rescan of %s finished", r.IP)
		}
	}
	if err := m.store.SetRescan(r); err != nil {
		log.Printf("rescan: %v", err)
	}
	if !r.CompletedAt.IsZero() {
		m.refreshCredits(ctx, cfg, now, -1) // re-check once the scan has run
	}
	return !r.CompletedAt.IsZero()
}

func (m *Monitor) finish(at time.Time, err error) error {
	if serr := m.store.SetCheckResult(at, err); serr != nil && err == nil {
		err = serr
	}
	return err
}

func (m *Monitor) setBusy(b bool) {
	m.mu.Lock()
	m.busy = b
	m.mu.Unlock()
}

// DefaultResolver looks up the hostname's A records, either with the system
// resolver or, if cfg.DNSServer is set, by querying that server directly
// (useful to bypass local caches or split-horizon DNS).
func DefaultResolver(ctx context.Context, cfg model.Config) (netip.Addr, error) {
	r := net.DefaultResolver
	if cfg.DNSServer != "" {
		server := DNSServerAddr(cfg.DNSServer)
		d := net.Dialer{Timeout: 5 * time.Second}
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, server)
			},
		}
	}
	addrs, err := r.LookupNetIP(ctx, "ip4", cfg.Hostname)
	if err != nil {
		return netip.Addr{}, err
	}
	var v4 []netip.Addr
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			v4 = append(v4, a)
		}
	}
	if len(v4) == 0 {
		return netip.Addr{}, errors.New("no IPv4 address found")
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i].Less(v4[j]) })
	return v4[0], nil
}

// DNSServerAddr normalises "1.1.1.1", "[2606:4700::1111]" or "host:5353"
// into a dialable host:port.
func DNSServerAddr(s string) string {
	s = strings.TrimSpace(s)
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(strings.Trim(s, "[]"), "53")
}

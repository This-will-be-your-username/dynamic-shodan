// Package monitor periodically resolves the dynamic DNS hostname, records
// IP changes, and refreshes Shodan intel for the current address.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
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

// CheckOnce resolves the hostname, records the IP, and fetches Shodan intel
// when the IP changed, the cached scan predates the current ownership
// period, the cache is older than the refresh interval, or force is set.
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

// Package model holds the data types shared across the app and the
// staleness rules that decide which Shodan findings still apply to you.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// Config is the user-editable configuration.
type Config struct {
	ShodanAPIKey         string `json:"shodan_api_key"`
	Hostname             string `json:"hostname"`
	DNSServer            string `json:"dns_server,omitempty"`
	CheckIntervalMinutes int    `json:"check_interval_minutes"`
	ShodanRefreshHours   int    `json:"shodan_refresh_hours"`
	// RescanOnIPChange asks Shodan for an on-demand scan of the new address
	// whenever the IP changes (one scan credit each time).
	RescanOnIPChange bool `json:"rescan_on_ip_change,omitempty"`
}

const (
	DefaultCheckIntervalMinutes = 10
	DefaultShodanRefreshHours   = 12
	MaxCheckIntervalMinutes     = 24 * 60
	MaxShodanRefreshHours       = 24 * 7
)

func DefaultConfig() Config {
	return Config{
		CheckIntervalMinutes: DefaultCheckIntervalMinutes,
		ShodanRefreshHours:   DefaultShodanRefreshHours,
	}
}

// Normalized fills in defaults and clamps out-of-range values.
func (c Config) Normalized() Config {
	if c.CheckIntervalMinutes < 1 {
		c.CheckIntervalMinutes = DefaultCheckIntervalMinutes
	}
	if c.CheckIntervalMinutes > MaxCheckIntervalMinutes {
		c.CheckIntervalMinutes = MaxCheckIntervalMinutes
	}
	if c.ShodanRefreshHours < 1 {
		c.ShodanRefreshHours = DefaultShodanRefreshHours
	}
	if c.ShodanRefreshHours > MaxShodanRefreshHours {
		c.ShodanRefreshHours = MaxShodanRefreshHours
	}
	return c
}

func (c Config) CheckInterval() time.Duration {
	return time.Duration(c.Normalized().CheckIntervalMinutes) * time.Minute
}

func (c Config) ShodanRefresh() time.Duration {
	return time.Duration(c.Normalized().ShodanRefreshHours) * time.Hour
}

func (c Config) Configured() bool { return c.Hostname != "" && c.ShodanAPIKey != "" }

// KeyHint returns a non-secret hint identifying the stored key.
func (c Config) KeyHint() string {
	if c.ShodanAPIKey == "" {
		return ""
	}
	if len(c.ShodanAPIKey) <= 8 {
		return "set"
	}
	return "ends in " + c.ShodanAPIKey[len(c.ShodanAPIKey)-4:]
}

// Period is one continuous stretch during which the DDNS hostname resolved
// to IP. FirstSeen/LastSeen are the first and last checks that observed it.
type Period struct {
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Adjusted is set when the user manually backdated FirstSeen.
	Adjusted bool `json:"adjusted,omitempty"`
}

type Vuln struct {
	ID       string  `json:"id"`
	CVSS     float64 `json:"cvss,omitempty"`
	Verified bool    `json:"verified,omitempty"`
	Summary  string  `json:"summary,omitempty"`
}

// Service is one Shodan banner (one port/transport observation).
type Service struct {
	Port      int       `json:"port"`
	Transport string    `json:"transport"`
	Module    string    `json:"module,omitempty"`
	Product   string    `json:"product,omitempty"`
	Version   string    `json:"version,omitempty"`
	Title     string    `json:"title,omitempty"`
	Hostnames []string  `json:"hostnames,omitempty"`
	CPE       []string  `json:"cpe,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Vulns     []Vuln    `json:"vulns,omitempty"`
	Banner    string    `json:"banner,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Rescan tracks the latest on-demand scan requested from Shodan.
type Rescan struct {
	ID          string    `json:"id"`
	IP          string    `json:"ip"`
	RequestedAt time.Time `json:"requested_at"`
	Auto        bool      `json:"auto,omitempty"` // requested because the IP changed
	Status      string    `json:"status,omitempty"`
	CreditsLeft int       `json:"credits_left"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	Error       string    `json:"error,omitempty"` // set when following the scan failed
}

// Credits is the last known Shodan credit balance for the configured key.
type Credits struct {
	Scan      int       `json:"scan"`
	Query     int       `json:"query"`
	Plan      string    `json:"plan,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	// KeyID fingerprints the API key the balance belongs to, so a new key
	// makes the balance unknown again.
	KeyID string `json:"key_id"`
}

// KeyID returns a short, non-reversible fingerprint of an API key.
func KeyID(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

// RescanPollWindow is how long a requested rescan is followed before the
// app stops asking Shodan about it.
const RescanPollWindow = 24 * time.Hour

// Pending reports whether the rescan may still be running at Shodan.
func (r *Rescan) Pending(now time.Time) bool {
	return r != nil && r.Error == "" && r.CompletedAt.IsZero() && now.Sub(r.RequestedAt) < RescanPollWindow
}

// Scan is the result of one Shodan host lookup.
type Scan struct {
	IP         string    `json:"ip"`
	FetchedAt  time.Time `json:"fetched_at"`
	NotFound   bool      `json:"not_found,omitempty"`
	LastUpdate time.Time `json:"last_update,omitempty"`
	Org        string    `json:"org,omitempty"`
	ISP        string    `json:"isp,omitempty"`
	ASN        string    `json:"asn,omitempty"`
	OS         string    `json:"os,omitempty"`
	Country    string    `json:"country,omitempty"`
	City       string    `json:"city,omitempty"`
	Hostnames  []string  `json:"hostnames,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	Services   []Service `json:"services,omitempty"`
}

// OwnershipFor returns the period in which ip was yours at time t: the most
// recent period for ip that had started by t. Scans are fetched just after
// an observation, so t may be slightly past that period's LastSeen.
func OwnershipFor(history []Period, ip string, t time.Time) (Period, bool) {
	for i := len(history) - 1; i >= 0; i-- {
		p := history[i]
		if p.IP == ip && !p.FirstSeen.After(t) {
			return p, true
		}
	}
	return Period{}, false
}

// Verdict is a service plus the decision on whether it still applies.
type Verdict struct {
	Service
	Stale  bool   `json:"stale"`
	Reason string `json:"reason,omitempty"`
}

// Classify splits a scan's services into fresh ones (observed by Shodan
// while the IP was yours) and stale ones (observed before you held it, so
// they most likely describe the previous holder of the address).
func Classify(scan *Scan, owner Period, ok bool) (fresh, stale []Verdict) {
	if scan == nil {
		return nil, nil
	}
	for _, s := range scan.Services {
		v := Verdict{Service: s}
		switch {
		case !ok:
			v.Stale, v.Reason = true, "no record of you holding this IP"
		case s.Timestamp.IsZero():
			v.Stale, v.Reason = true, "Shodan record has no timestamp"
		case s.Timestamp.Before(owner.FirstSeen):
			v.Stale = true
			v.Reason = fmt.Sprintf("observed %s, before this IP was yours (since %s)",
				s.Timestamp.Local().Format("2006-01-02 15:04"),
				owner.FirstSeen.Local().Format("2006-01-02 15:04"))
		}
		if v.Stale {
			stale = append(stale, v)
		} else {
			fresh = append(fresh, v)
		}
	}
	sort.SliceStable(fresh, func(i, j int) bool {
		if fresh[i].Port != fresh[j].Port {
			return fresh[i].Port < fresh[j].Port
		}
		return fresh[i].Transport < fresh[j].Transport
	})
	sort.SliceStable(stale, func(i, j int) bool { return stale[i].Timestamp.After(stale[j].Timestamp) })
	return fresh, stale
}

// FreshVulns de-duplicates vulnerabilities across fresh services, highest
// CVSS first.
func FreshVulns(fresh []Verdict) []Vuln {
	byID := map[string]Vuln{}
	for _, f := range fresh {
		for _, v := range f.Vulns {
			cur, seen := byID[v.ID]
			if !seen || v.CVSS > cur.CVSS || (v.Verified && !cur.Verified) {
				byID[v.ID] = v
			}
		}
	}
	out := make([]Vuln, 0, len(byID))
	for _, v := range byID {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CVSS != out[j].CVSS {
			return out[i].CVSS > out[j].CVSS
		}
		return out[i].ID < out[j].ID
	})
	return out
}

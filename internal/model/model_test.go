package model

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func at(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }

func TestOwnershipForReusedIP(t *testing.T) {
	// A, then B, then A again.
	hist := []Period{
		{IP: "1.1.1.1", FirstSeen: at(0), LastSeen: at(10)},
		{IP: "2.2.2.2", FirstSeen: at(11), LastSeen: at(20)},
		{IP: "1.1.1.1", FirstSeen: at(21), LastSeen: at(30)},
	}
	p, ok := OwnershipFor(hist, "1.1.1.1", at(25))
	if !ok || !p.FirstSeen.Equal(at(21)) {
		t.Fatalf("scan during 2nd ownership of A should map to 2nd period, got %+v ok=%v", p, ok)
	}
	p, ok = OwnershipFor(hist, "1.1.1.1", at(5))
	if !ok || !p.FirstSeen.Equal(at(0)) {
		t.Fatalf("scan during 1st ownership of A should map to 1st period, got %+v", p)
	}
	if _, ok := OwnershipFor(hist, "3.3.3.3", at(5)); ok {
		t.Fatal("unknown IP should not match")
	}
	if _, ok := OwnershipFor(hist, "2.2.2.2", at(1)); ok {
		t.Fatal("scan before B was held should not match")
	}
}

func TestClassify(t *testing.T) {
	owner := Period{IP: "1.1.1.1", FirstSeen: at(21), LastSeen: at(30)}
	scan := &Scan{IP: "1.1.1.1", Services: []Service{
		{Port: 443, Timestamp: at(25), Vulns: []Vuln{{ID: "CVE-1", CVSS: 5}}},
		{Port: 22, Timestamp: at(22), Vulns: []Vuln{{ID: "CVE-1", CVSS: 7.5}, {ID: "CVE-2", CVSS: 9.8}}},
		{Port: 3389, Timestamp: at(5), Vulns: []Vuln{{ID: "CVE-OLD", CVSS: 10}}}, // previous holder
		{Port: 21, Timestamp: at(21)}, // exactly at boundary: fresh
		{Port: 80},                    // no timestamp
	}}
	fresh, stale := Classify(scan, owner, true)
	if got := ports(fresh); !equal(got, []int{21, 22, 443}) {
		t.Fatalf("fresh ports = %v", got)
	}
	if len(stale) != 2 {
		t.Fatalf("want 2 stale, got %d", len(stale))
	}
	for _, s := range stale {
		if s.Reason == "" || !s.Stale {
			t.Fatalf("stale entry missing reason: %+v", s)
		}
	}
	vulns := FreshVulns(fresh)
	if len(vulns) != 2 || vulns[0].ID != "CVE-2" || vulns[1].ID != "CVE-1" || vulns[1].CVSS != 7.5 {
		t.Fatalf("fresh vulns = %+v", vulns)
	}

	fresh, stale = Classify(scan, Period{}, false)
	if len(fresh) != 0 || len(stale) != 5 {
		t.Fatalf("without ownership everything is stale; got %d fresh", len(fresh))
	}
}

func TestNormalized(t *testing.T) {
	c := Config{CheckIntervalMinutes: -1, ShodanRefreshHours: 100000}.Normalized()
	if c.CheckIntervalMinutes != DefaultCheckIntervalMinutes || c.ShodanRefreshHours != MaxShodanRefreshHours {
		t.Fatalf("got %+v", c)
	}
	if h := (Config{ShodanAPIKey: "abcdefghijklmnop"}).KeyHint(); h != "ends in mnop" {
		t.Fatalf("hint = %q", h)
	}
}

func ports(v []Verdict) []int {
	var out []int
	for _, x := range v {
		out = append(out, x.Port)
	}
	return out
}

func equal(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

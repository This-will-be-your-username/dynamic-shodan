package notify

import (
	"fmt"
	"html"
	"strings"
	"time"

	"dynamic-shodan/internal/model"
)

// maxListItems caps each bullet list so messages stay readable.
const maxListItems = 15

// IPChangedMessage announces a new public IP.
func IPChangedMessage(hostname string, prev, cur model.Period) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🔄 <b>Public IP changed</b>\n<code>%s</code> → <code>%s</code>\n", esc(prev.IP), esc(cur.IP))
	fmt.Fprintf(&b, "Hostname: <code>%s</code>\n", esc(hostname))
	if !prev.FirstSeen.IsZero() {
		fmt.Fprintf(&b, "Previous IP held for about %s.", Duration(prev.LastSeen.Sub(prev.FirstSeen)))
	}
	return b.String()
}

// Exposure is what's new in a scan compared to the previous scan from the
// same ownership period.
type Exposure struct {
	IP          string
	NewServices []model.Verdict
	NewVulns    []model.Vuln
	Baseline    bool // no earlier scan in this ownership period: everything is "new"
	TotalFresh  int
}

func (e Exposure) Empty() bool { return len(e.NewServices) == 0 && len(e.NewVulns) == 0 }

// DiffExposure compares current findings with the previous ones from the
// same ownership period (prevFresh is nil if there was no such scan).
func DiffExposure(ip string, prevFresh []model.Verdict, havePrev bool, fresh []model.Verdict) Exposure {
	e := Exposure{IP: ip, Baseline: !havePrev, TotalFresh: len(fresh)}
	seenSvc := map[string]bool{}
	for _, p := range prevFresh {
		seenSvc[svcKey(p.Service)] = true
	}
	for _, f := range fresh {
		if !seenSvc[svcKey(f.Service)] {
			e.NewServices = append(e.NewServices, f)
		}
	}
	seenVuln := map[string]bool{}
	for _, v := range model.FreshVulns(prevFresh) {
		seenVuln[v.ID] = true
	}
	for _, v := range model.FreshVulns(fresh) {
		if !seenVuln[v.ID] {
			e.NewVulns = append(e.NewVulns, v)
		}
	}
	return e
}

func svcKey(s model.Service) string { return fmt.Sprintf("%d/%s", s.Port, s.Transport) }

// ExposureMessage describes new services and vulnerabilities.
func ExposureMessage(e Exposure) string {
	var b strings.Builder
	if e.Baseline {
		fmt.Fprintf(&b, "🛰 <b>Shodan exposure on <code>%s</code></b>\n", esc(e.IP))
		fmt.Fprintf(&b, "%d service(s) observed since this IP became yours.\n", e.TotalFresh)
	} else {
		fmt.Fprintf(&b, "⚠️ <b>New exposure on <code>%s</code></b>\n", esc(e.IP))
	}
	if len(e.NewServices) > 0 {
		b.WriteString("\n<b>Services</b>\n")
		for i, s := range e.NewServices {
			if i == maxListItems {
				fmt.Fprintf(&b, "…and %d more\n", len(e.NewServices)-i)
				break
			}
			fmt.Fprintf(&b, "• <code>%d/%s</code> %s\n", s.Port, esc(s.Transport), esc(describe(s.Service)))
		}
	}
	if len(e.NewVulns) > 0 {
		b.WriteString("\n<b>Vulnerabilities</b>\n")
		for i, v := range e.NewVulns {
			if i == maxListItems {
				fmt.Fprintf(&b, "…and %d more\n", len(e.NewVulns)-i)
				break
			}
			cvss := "n/a"
			if v.CVSS > 0 {
				cvss = fmt.Sprintf("%.1f", v.CVSS)
			}
			fmt.Fprintf(&b, "• %s %s (CVSS %s)\n", severityIcon(v.CVSS), esc(v.ID), cvss)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// HealthMessage reports checks starting to fail (err != "") or recovering.
func HealthMessage(errMsg string, failingSince time.Time, now time.Time) string {
	if errMsg != "" {
		return "❌ <b>dynamic-shodan check failing</b>\n" + esc(errMsg)
	}
	msg := "✅ <b>dynamic-shodan checks working again</b>"
	if !failingSince.IsZero() {
		msg += fmt.Sprintf("\nFailed for about %s.", Duration(now.Sub(failingSince)))
	}
	return msg
}

// TestMessage is sent by the "Send test message" button.
func TestMessage(hostname string) string {
	msg := "✅ <b>dynamic-shodan</b> test message.\nTelegram notifications are working."
	if hostname != "" {
		msg += fmt.Sprintf("\nWatching <code>%s</code>.", esc(hostname))
	}
	return msg
}

func describe(s model.Service) string {
	name := s.Product
	if name == "" {
		name = s.Module
	}
	if s.Version != "" {
		name += " " + s.Version
	}
	if s.Title != "" {
		name += fmt.Sprintf(" “%s”", s.Title)
	}
	return strings.TrimSpace(name)
}

func severityIcon(cvss float64) string {
	switch {
	case cvss >= 9:
		return "🟥"
	case cvss >= 7:
		return "🟧"
	case cvss >= 4:
		return "🟨"
	}
	return "⬜"
}

func esc(s string) string { return html.EscapeString(s) }

// Duration renders a duration as "3d 4h", "5h 12m" or "7m".
func Duration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
}

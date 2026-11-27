// Package shodan is a minimal client for the Shodan REST API endpoints the
// app needs: host lookup and API key info.
package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"dynamic-shodan/internal/model"
)

const DefaultBaseURL = "https://api.shodan.io"

type Client struct {
	BaseURL   string
	HTTP      *http.Client
	MaxBanner int // banners longer than this are truncated before storing
}

func New() *Client {
	return &Client{
		BaseURL:   DefaultBaseURL,
		HTTP:      &http.Client{Timeout: 30 * time.Second},
		MaxBanner: 2048,
	}
}

// APIError is a non-200 response from Shodan.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("shodan API error (HTTP %d): %s", e.Status, e.Message)
}

// get performs a GET and decodes JSON into out.
func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	return c.do(ctx, http.MethodGet, path, q, nil, out)
}

// do sends a request (with form as a urlencoded body when non-nil) and
// decodes the JSON reply into out. The API key travels in the query string,
// so errors are scrubbed of the URL to keep it out of logs/UI.
func (c *Client) do(ctx context.Context, method, path string, q, form url.Values, out any) error {
	var reqBody io.Reader
	if form != nil {
		reqBody = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path+"?"+q.Encode(), reqBody)
	if err != nil {
		return errors.New("building shodan request failed")
	}
	req.Header.Set("User-Agent", "dynamic-shodan/1.0")
	req.Header.Set("Accept", "application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("shodan request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("reading shodan response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return &APIError{Status: resp.StatusCode, Message: e.Error}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding shodan response: %w", err)
	}
	return nil
}

type APIInfo struct {
	Plan         string `json:"plan"`
	QueryCredits int    `json:"query_credits"`
	ScanCredits  int    `json:"scan_credits"`
	MonitoredIPs int    `json:"monitored_ips"`
}

// APIInfo validates a key and returns plan/credit information.
func (c *Client) APIInfo(ctx context.Context, key string) (*APIInfo, error) {
	var info APIInfo
	if err := c.get(ctx, "/api-info", url.Values{"key": {key}}, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// RequestScan asks Shodan to crawl ip on demand. It costs one scan credit
// and needs a plan that includes scan credits. Poll the returned ID with
// ScanStatus.
func (c *Client) RequestScan(ctx context.Context, key, ip string) (id string, creditsLeft int, err error) {
	var out struct {
		ID          string `json:"id"`
		CreditsLeft int    `json:"credits_left"`
	}
	if err := c.do(ctx, http.MethodPost, "/shodan/scan", url.Values{"key": {key}}, url.Values{"ips": {ip}}, &out); err != nil {
		return "", 0, err
	}
	if out.ID == "" {
		return "", 0, errors.New("shodan accepted the scan request but returned no scan ID")
	}
	return out.ID, out.CreditsLeft, nil
}

// ScanDone is the ScanStatus value of a finished scan. Others are
// SUBMITTING, QUEUE and PROCESSING.
const ScanDone = "DONE"

// ScanStatus returns the state of an on-demand scan.
func (c *Client) ScanStatus(ctx context.Context, key, id string) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	if err := c.get(ctx, "/shodan/scan/"+url.PathEscape(id), url.Values{"key": {key}}, &out); err != nil {
		return "", err
	}
	return out.Status, nil
}

type rawVuln struct {
	CVSS     any    `json:"cvss"`
	Verified bool   `json:"verified"`
	Summary  string `json:"summary"`
}

type rawService struct {
	Port      int                `json:"port"`
	Transport string             `json:"transport"`
	Product   string             `json:"product"`
	Version   string             `json:"version"`
	CPE23     []string           `json:"cpe23"`
	CPE       []string           `json:"cpe"`
	Timestamp string             `json:"timestamp"`
	Data      string             `json:"data"`
	Hostnames []string           `json:"hostnames"`
	Tags      []string           `json:"tags"`
	Vulns     map[string]rawVuln `json:"vulns"`
	Shodan    struct {
		Module string `json:"module"`
	} `json:"_shodan"`
	HTTP *struct {
		Title string `json:"title"`
	} `json:"http"`
}

type rawHost struct {
	IPStr      string       `json:"ip_str"`
	Org        string       `json:"org"`
	ISP        string       `json:"isp"`
	ASN        string       `json:"asn"`
	OS         string       `json:"os"`
	Country    string       `json:"country_name"`
	City       string       `json:"city"`
	Hostnames  []string     `json:"hostnames"`
	Tags       []string     `json:"tags"`
	LastUpdate string       `json:"last_update"`
	Data       []rawService `json:"data"`
}

// Host looks up everything Shodan has on ip. A 404 ("no information
// available") is not an error: it yields a Scan with NotFound set.
func (c *Client) Host(ctx context.Context, key, ip string) (*model.Scan, error) {
	now := time.Now()
	var raw rawHost
	err := c.get(ctx, "/shodan/host/"+url.PathEscape(ip), url.Values{"key": {key}}, &raw)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
		return &model.Scan{IP: ip, FetchedAt: now, NotFound: true}, nil
	}
	if err != nil {
		return nil, err
	}
	scan := &model.Scan{
		IP:         ip,
		FetchedAt:  now,
		LastUpdate: parseTime(raw.LastUpdate),
		Org:        raw.Org,
		ISP:        raw.ISP,
		ASN:        raw.ASN,
		OS:         raw.OS,
		Country:    raw.Country,
		City:       raw.City,
		Hostnames:  raw.Hostnames,
		Tags:       raw.Tags,
	}
	for _, d := range raw.Data {
		s := model.Service{
			Port:      d.Port,
			Transport: d.Transport,
			Module:    d.Shodan.Module,
			Product:   d.Product,
			Version:   d.Version,
			Hostnames: d.Hostnames,
			Tags:      d.Tags,
			CPE:       d.CPE23,
			Banner:    truncate(d.Data, c.MaxBanner),
			Timestamp: parseTime(d.Timestamp),
		}
		if len(s.CPE) == 0 {
			s.CPE = d.CPE
		}
		if d.HTTP != nil {
			s.Title = d.HTTP.Title
		}
		for id, v := range d.Vulns {
			s.Vulns = append(s.Vulns, model.Vuln{ID: id, CVSS: toFloat(v.CVSS), Verified: v.Verified, Summary: v.Summary})
		}
		sort.Slice(s.Vulns, func(i, j int) bool {
			if s.Vulns[i].CVSS != s.Vulns[j].CVSS {
				return s.Vulns[i].CVSS > s.Vulns[j].CVSS
			}
			return s.Vulns[i].ID < s.Vulns[j].ID
		})
		scan.Services = append(scan.Services, s)
	}
	return scan, nil
}

// parseTime handles Shodan's timestamps, which are UTC without a zone
// suffix (e.g. "2026-11-20T08:14:03.123456").
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999999Z07:00", "2006-01-02T15:04:05.999999999", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	}
	return 0
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "\n…[truncated]"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// Package store persists configuration, IP history and cached Shodan scans
// as JSON files in the data directory.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"dynamic-shodan/internal/model"
)

const (
	configFile = "config.json"
	stateFile  = "state.json"
)

// State is everything the app learns at runtime.
type State struct {
	History   []model.Period         `json:"history"`
	Scans     map[string]*model.Scan `json:"scans"` // latest scan per IP
	LastCheck time.Time              `json:"last_check"`
	LastError string                 `json:"last_error,omitempty"`
	Rescan    *model.Rescan          `json:"rescan,omitempty"`  // latest on-demand scan request
	Credits   *model.Credits         `json:"credits,omitempty"` // last known credit balance
}

// CreditsFor returns the stored credit balance if it belongs to key; nil
// means the balance is unknown.
func (s State) CreditsFor(key string) *model.Credits {
	if s.Credits == nil || key == "" || s.Credits.KeyID != model.KeyID(key) {
		return nil
	}
	return s.Credits
}

// Current returns the most recent ownership period, if any.
func (s State) Current() (model.Period, bool) {
	if len(s.History) == 0 {
		return model.Period{}, false
	}
	return s.History[len(s.History)-1], true
}

type Store struct {
	mu  sync.RWMutex
	dir string
	cfg model.Config
	st  State
}

// Open loads (or initialises) the store in dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}
	s := &Store{dir: dir, cfg: model.DefaultConfig(), st: State{Scans: map[string]*model.Scan{}}}
	if err := readJSON(filepath.Join(dir, configFile), &s.cfg); err != nil {
		return nil, err
	}
	s.cfg = s.cfg.Normalized()
	if err := readJSON(filepath.Join(dir, stateFile), &s.st); err != nil {
		return nil, err
	}
	if s.st.Scans == nil {
		s.st.Scans = map[string]*model.Scan{}
	}
	return s, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) Config() model.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *Store) SaveConfig(c model.Config) error {
	c = c.Normalized()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeJSON(filepath.Join(s.dir, configFile), c, 0o600); err != nil {
		return err
	}
	s.cfg = c
	return nil
}

// Snapshot returns a copy of the state that is safe to read without locks.
func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.st
	out.History = append([]model.Period(nil), s.st.History...)
	if s.st.Rescan != nil {
		r := *s.st.Rescan
		out.Rescan = &r
	}
	if s.st.Credits != nil {
		c := *s.st.Credits
		out.Credits = &c
	}
	out.Scans = make(map[string]*model.Scan, len(s.st.Scans))
	for k, v := range s.st.Scans {
		c := *v
		out.Scans[k] = &c
	}
	return out
}

// ObserveIP records that hostname resolved to ip at time now. It extends
// the current period if the IP is unchanged, otherwise opens a new one.
func (s *Store) ObserveIP(ip, hostname string, now time.Time) (changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.st.History)
	if n > 0 && s.st.History[n-1].IP == ip {
		s.st.History[n-1].LastSeen = now
		s.st.History[n-1].Hostname = hostname
	} else {
		s.st.History = append(s.st.History, model.Period{IP: ip, Hostname: hostname, FirstSeen: now, LastSeen: now})
		changed = true
	}
	return changed, s.saveStateLocked()
}

func (s *Store) SaveScan(scan *model.Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Scans[scan.IP] = scan
	return s.saveStateLocked()
}

// SetRescan records the latest on-demand scan request.
func (s *Store) SetRescan(r model.Rescan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Rescan = &r
	return s.saveStateLocked()
}

// SetCredits records the latest known credit balance.
func (s *Store) SetCredits(c model.Credits) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Credits = &c
	return s.saveStateLocked()
}

func (s *Store) SetCheckResult(at time.Time, checkErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.LastCheck = at
	s.st.LastError = ""
	if checkErr != nil {
		s.st.LastError = checkErr.Error()
	}
	return s.saveStateLocked()
}

// SetPeriodStart backdates (or moves) the start of period idx, e.g. when
// you know you've had an address since before the app started watching.
// The new start must fall after the previous period ended and no later
// than the period's last observation.
func (s *Store) SetPeriodStart(idx int, start time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx < 0 || idx >= len(s.st.History) {
		return errors.New("no such history entry")
	}
	p := &s.st.History[idx]
	if start.After(p.LastSeen) {
		return fmt.Errorf("start must be on or before %s (last time this IP was seen)",
			p.LastSeen.Local().Format("2006-01-02 15:04"))
	}
	if idx > 0 && !start.After(s.st.History[idx-1].LastSeen) {
		return fmt.Errorf("start must be after %s, when the previous IP (%s) was last seen",
			s.st.History[idx-1].LastSeen.Local().Format("2006-01-02 15:04"), s.st.History[idx-1].IP)
	}
	p.FirstSeen = start
	p.Adjusted = true
	return s.saveStateLocked()
}

func (s *Store) saveStateLocked() error {
	return writeJSON(filepath.Join(s.dir, stateFile), s.st, 0o600)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}
	// Tolerate a UTF-8 BOM, which Windows editors often add.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing %s: %w", filepath.Base(path), err)
	}
	return nil
}

// writeJSON writes atomically via a temp file + rename.
func writeJSON(path string, v any, perm os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("writing %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replacing %s: %w", filepath.Base(path), err)
	}
	return nil
}

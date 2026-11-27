package store

import (
	"testing"
	"time"

	"dynamic-shodan/internal/model"
)

func TestObserveIPAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	steps := []struct {
		ip      string
		h       int
		changed bool
	}{
		{"1.1.1.1", 0, true}, {"1.1.1.1", 1, false}, {"2.2.2.2", 2, true}, {"1.1.1.1", 3, true}, {"1.1.1.1", 4, false},
	}
	for _, st := range steps {
		ch, err := s.ObserveIP(st.ip, "h.example", t0.Add(time.Duration(st.h)*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if ch != st.changed {
			t.Fatalf("ObserveIP(%s @%dh) changed=%v want %v", st.ip, st.h, ch, st.changed)
		}
	}

	if err := s.SaveConfig(model.Config{ShodanAPIKey: "k", Hostname: "h.example"}); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := s2.Snapshot().History
	if len(h) != 3 {
		t.Fatalf("want 3 periods, got %d", len(h))
	}
	if !h[0].LastSeen.Equal(t0.Add(time.Hour)) || !h[2].LastSeen.Equal(t0.Add(4*time.Hour)) {
		t.Fatalf("unexpected periods: %+v", h)
	}
	if c := s2.Config(); c.ShodanAPIKey != "k" || c.CheckIntervalMinutes != model.DefaultCheckIntervalMinutes {
		t.Fatalf("config not persisted/normalised: %+v", c)
	}
}

func TestSetPeriodStart(t *testing.T) {
	s, _ := Open(t.TempDir())
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	s.ObserveIP("1.1.1.1", "h", t0)
	s.ObserveIP("2.2.2.2", "h", t0.Add(10*time.Hour))
	s.ObserveIP("2.2.2.2", "h", t0.Add(12*time.Hour))

	if err := s.SetPeriodStart(0, t0.Add(-30*24*time.Hour)); err != nil {
		t.Fatalf("backdating first period should work: %v", err)
	}
	if err := s.SetPeriodStart(1, t0); err == nil {
		t.Fatal("start overlapping previous period should fail")
	}
	if err := s.SetPeriodStart(1, t0.Add(13*time.Hour)); err == nil {
		t.Fatal("start after last seen should fail")
	}
	if err := s.SetPeriodStart(1, t0.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	p := s.Snapshot().History[1]
	if !p.Adjusted || !p.FirstSeen.Equal(t0.Add(5*time.Hour)) {
		t.Fatalf("period not updated: %+v", p)
	}
}

package coord

import (
	"strings"
	"testing"
	"time"
)

// The memory bounds, the write deadlines, bursts and the session deadlines
// cannot be lifted: a negative value fails New. Negative counts and rates
// remove their limit, and negative ConfirmLinger and ResultGrace end the
// session early.
func TestNegativeSettings(t *testing.T) {
	bad := map[string]Config{
		"MaxSessions":       {Limits: Limits{MaxSessions: -1}},
		"MaxKeys":           {Limits: Limits{MaxKeys: -1}},
		"ObserverQueue":     {Limits: Limits{ObserverQueue: -1}},
		"FramesPerLink":     {Limits: Limits{FramesPerLink: -1}},
		"WriteTimeout":      {Limits: Limits{WriteTimeout: -1}},
		"AbortTimeout":      {Limits: Limits{AbortTimeout: -1}},
		"NewSessions.Burst": {Limits: Limits{NewSessions: Rate{Burst: -1}}},
		"FrameRate.Burst":   {Limits: Limits{FrameRate: Rate{Burst: -1}}},
		"BindTimeout":       {TTL: TTLConfig{BindTimeout: -1}},
		"ReportSlack":       {TTL: TTLConfig{ReportSlack: -1}},
		"ReadyTimeout":      {TTL: TTLConfig{ReadyTimeout: -1}},
		"PunchSlack":        {TTL: TTLConfig{PunchSlack: -1}},
	}
	for name, cfg := range bad {
		cfg.NoObserver = true
		if _, err := newSettings(cfg); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok := Config{NoObserver: true,
		Limits: Limits{MaxPending: -1, NewSessions: Rate{PerSec: -1}, MaxPerInitiatorKey: -1, PacketsPerMinute: [2]int{-1, -1}},
		TTL:    TTLConfig{ConfirmLinger: -1, ResultGrace: -1, BindTimeout: time.Hour}}
	s, err := newSettings(ok)
	if err != nil {
		t.Fatal(err)
	}
	if s.limits.MaxPending != -1 || s.limits.NewSessions.PerSec != -1 || s.limits.MaxSessions != defMaxSessions {
		t.Errorf("limits %+v", s.limits)
	}
}

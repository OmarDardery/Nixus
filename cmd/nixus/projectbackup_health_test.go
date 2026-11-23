package main

import "testing"

func TestBackupHealthUsesTheExplicitOutcome(t *testing.T) {
	const now = 1_000_000.0
	day := float64(24 * 3600)
	base := func(extra M) M {
		s := M{"enabled": true, "schedule": "daily"}
		for k, v := range extra {
			s[k] = v
		}
		return s
	}
	for name, c := range map[string]struct {
		status M
		want   string
	}{
		"disabled":                 {M{"enabled": false}, "disabled"},
		"no run yet":               {base(nil), "never"},
		"first run failed":         {base(M{"lastAttempt": now - 10, "lastOutcome": "failed"}), "failed"},
		"success, same instant":    {base(M{"lastSuccess": now - 10, "lastAttempt": now - 10, "lastOutcome": "success"}), "ok"},
		"success, attempt later":   {base(M{"lastSuccess": now - 10, "lastAttempt": now - 9, "lastOutcome": "success"}), "ok"},
		"failure after success":    {base(M{"lastSuccess": now - day, "lastAttempt": now - 10, "lastOutcome": "failed"}), "failed"},
		"overdue":                  {base(M{"lastSuccess": now - 3*day, "lastAttempt": now - 3*day, "lastOutcome": "success"}), "overdue"},
		"older status, no outcome": {base(M{"lastSuccess": now - 10, "lastAttempt": now - 9}), "ok"},
	} {
		if got := backupHealth(c.status, now); got != c.want {
			t.Errorf("%s: got %s, want %s", name, got, c.want)
		}
	}
}

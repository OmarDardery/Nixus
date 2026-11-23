package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

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

// Saving an app variable changes ciphertext in the live workspace without a
// project review. Backups must still accept it, while an unreviewed edit to a
// declaration is still rejected (#108).
func TestApprovedSecretChangeKeepsTheWorkspaceAccepted(t *testing.T) {
	state := useState(t)
	workspace := filepath.Join(t.TempDir(), "workspace")
	writeFile(t, filepath.Join(workspace, "flake.nix"), "{ outputs = { self }: {}; }\n")
	writeFile(t, filepath.Join(workspace, "flake.lock"), `{"nodes":{"root":{}},"root":"root","version":7}`)
	writeFile(t, filepath.Join(workspace, "web", "default.nix"), "{ ... }: { }\n")
	writeFile(t, filepath.Join(workspace, "web", "secrets.enc.yaml"), "one\n")
	tx := NewProjectTransactions(workspace, state)
	live, err := validateWorkspace(workspace, true)
	if err != nil {
		t.Fatal(err)
	}
	id := tokenHex(16)
	dir := filepath.Join(tx.jobs, id)
	os.MkdirAll(dir, 0o700)
	writeJSON(filepath.Join(dir, "job.json"), M{"id": id, "status": "published-source", "candidateHash": live["sourceHash"]})
	writeJSON(filepath.Join(state, "project-last.json"), M{"id": id})
	if _, ok := workspaceApproved(tx); !ok {
		t.Fatal("a freshly published workspace must be approved")
	}
	// An approved secret change: ciphertext differs, then the change is adopted.
	writeFile(t, filepath.Join(workspace, "web", "secrets.enc.yaml"), "two\n")
	if _, ok := workspaceApproved(tx); ok {
		t.Fatal("the changed ciphertext is not yet recorded")
	}
	if err := adoptWorkspaceChange(tx, id); err != nil {
		t.Fatal(err)
	}
	if _, ok := workspaceApproved(tx); !ok {
		t.Fatal("backups would reject a legitimate secret change")
	}
	// An unreviewed declaration edit is still caught.
	writeFile(t, filepath.Join(workspace, "web", "default.nix"), "{ ... }: { evil = true; }\n")
	if _, ok := workspaceApproved(tx); ok {
		t.Fatal("an unreviewed declaration edit was accepted")
	}
}

func backupGuest(project, name string, devices M) M {
	return M{"project": project, "name": name, "expanded_devices": devices}
}

func diskDevice(source string) M {
	return M{"data": M{"type": "disk", "path": "/data", "pool": "default", "source": source}}
}

// Backing up one project must not stop or export another one's guests (#109).
func TestScopedBackupLeavesOtherProjectsAlone(t *testing.T) {
	guests := []M{backupGuest("a", "a1", diskDevice("custom/va")), backupGuest("b", "b1", diskDevice("custom/vb"))}
	volumes := []M{{"project": "a", "pool": "default", "name": "va"}, {"project": "b", "pool": "default", "name": "vb"}}
	namespaces := map[string]string{"a": "a", "b": "b"}
	groups, err := consistencyGroups(guests, volumes, nil, namespaces)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := scopeGroups(groups, map[string]bool{"a": true}, namespaces)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || len(list(kept[0]["guests"])) != 1 || str(obj(list(kept[0]["guests"])[0])["name"]) != "a1" {
		t.Fatalf("only a1 may be selected: %v", kept)
	}
	for _, v := range list(kept[0]["volumes"]) {
		if str(obj(v)["project"]) == "b" {
			t.Fatal("the excluded project's volume leaked in")
		}
	}
}

func TestScopedBackupRefusesASharedVolumeBeforeStoppingAnything(t *testing.T) {
	// Both projects use the shared (default-namespace) volume "shared".
	guests := []M{backupGuest("a", "a1", diskDevice("custom/shared")), backupGuest("b", "b1", diskDevice("custom/shared"))}
	volumes := []M{{"project": "default", "pool": "default", "name": "shared"}}
	namespaces := map[string]string{"a": "default", "b": "default"}
	groups, err := consistencyGroups(guests, volumes, nil, namespaces)
	if err != nil {
		t.Fatal(err)
	}
	_, err = scopeGroups(groups, map[string]bool{"a": true}, namespaces)
	if err == nil || !strings.Contains(publicError(err), "share a writable volume") || !strings.Contains(publicError(err), "b/b1") {
		t.Fatalf("a shared volume with an unselected guest must be refused: %v", err)
	}
	// Selecting both is fine.
	if _, err := scopeGroups(groups, map[string]bool{"a": true, "b": true}, namespaces); err != nil {
		t.Fatal(err)
	}
}

// Several days of backups, each from a new generation directory, must expire
// down to the retention policy, and two installations sharing a repository must
// not affect each other (#112). Uses the real restic when it is available.
func TestRetentionExpiresGenerationsPerInstallation(t *testing.T) {
	restic := "/nix/store/kglf8qzqjmf2jandyqxkr0l57jwiix2n-restic-0.18.1/bin/restic"
	if _, err := os.Stat(restic); err != nil {
		t.Skip("restic not available")
	}
	work := t.TempDir()
	repo := filepath.Join(work, "repo")
	env := []string{"PATH=" + filepath.Dir(restic) + ":/usr/bin:/bin", "HOME=" + work, "RESTIC_REPOSITORY=" + repo, "RESTIC_PASSWORD=test"}
	run1 := func(args ...string) string {
		res, err := run(append([]string{restic}, args...), nil, 2*time.Minute, env, "")
		if err != nil || res.Code != 0 {
			t.Fatalf("restic %v: %v %s", args, err, res.Stderr)
		}
		return string(res.Stdout)
	}
	run1("init")
	day := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, host := range []string{"nixus-aaaaaaaaaaaaaaaa", "nixus-bbbbbbbbbbbbbbbb"} {
		for d := 0; d < 6; d++ {
			gen := filepath.Join(work, host, "generation-"+strconv.Itoa(d))
			os.MkdirAll(gen, 0o700)
			os.WriteFile(filepath.Join(gen, "file"), []byte(strconv.Itoa(d)), 0o600)
			args := resticBackupArgs(host, []string{gen})
			args = append(args, "--time", day.AddDate(0, 0, d).Format("2006-01-02 15:04:05"))
			run1(args...)
		}
	}
	count := func(host string) int {
		var snaps []M
		raw := run1("snapshots", "--json", "--host", host)
		if err := json.Unmarshal([]byte(raw), &snaps); err != nil {
			t.Fatal(err)
		}
		return len(snaps)
	}
	if count("nixus-aaaaaaaaaaaaaaaa") != 6 {
		t.Fatal("fixture should hold six snapshots per installation")
	}
	policy := M{"daily": 2, "weekly": 0, "monthly": 0}
	run1(resticForgetArgs("nixus-aaaaaaaaaaaaaaaa", policy)...)
	if got := count("nixus-aaaaaaaaaaaaaaaa"); got != 2 {
		t.Fatalf("installation a kept %d snapshots, want 2", got)
	}
	if got := count("nixus-bbbbbbbbbbbbbbbb"); got != 6 {
		t.Fatalf("installation b lost snapshots: %d", got)
	}
}

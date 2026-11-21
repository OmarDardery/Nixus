package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func backupPolicyFixture() M {
	return M{"enable": true, "includeProjects": "all", "schedule": "daily", "data": false,
		"retention": M{"daily": float64(7), "weekly": float64(4), "monthly": float64(6)}, "verification": "metadata",
		"restic": M{"repository": "rclone:gdrive:nixus-backups", "passwordFile": "/var/lib/nixus-secrets/project-restic-password",
			"environmentFile": nil, "rcloneConfigFile": "/var/lib/nixus-secrets/rclone.conf", "initialize": false}}
}

func TestBackupPolicyValidation(t *testing.T) {
	if _, err := validateBackupPolicy(backupPolicyFixture()); err != nil {
		t.Fatal(err)
	}
	if p, err := validateBackupPolicy(nil); p != nil || err != nil {
		t.Fatal("absent policy must be accepted as disabled")
	}
	for _, mutate := range []func(M){
		func(p M) { obj(p["restic"])["repository"] = "https://user:token@example.com/repo" },
		func(p M) { obj(p["restic"])["passwordFile"] = "/nix/store/x-password" },
		func(p M) { obj(p["restic"])["rcloneConfigFile"] = nil },
		func(p M) { p["github"] = M{"repository": "git@github.com:a/b.git", "branch": "main"} },
		func(p M) { p["schedule"] = "minutely" },
		func(p M) { p["extra"] = true },
	} {
		p := cloneM(backupPolicyFixture())
		mutate(p)
		if _, err := validateBackupPolicy(p); err == nil {
			t.Errorf("accepted invalid policy %v", p)
		}
	}
}

func TestIncludedProjectsTracksNewProjects(t *testing.T) {
	inventory := M{"projects": M{"alpha": M{}, "beta": M{}}}
	policy := backupPolicyFixture()
	if got := strings.Join(includedProjects(policy, inventory), ","); got != "alpha,beta" {
		t.Fatalf("all: %s", got)
	}
	obj(inventory["projects"])["gamma"] = M{}
	if got := strings.Join(includedProjects(policy, inventory), ","); got != "alpha,beta,gamma" {
		t.Fatalf("new project not included: %s", got)
	}
	policy["includeProjects"] = []any{"beta", "missing"}
	if got := strings.Join(includedProjects(policy, inventory), ","); got != "beta" {
		t.Fatalf("explicit: %s", got)
	}
}

func TestConfigSnapshotCopiesOnlyIncludedReviewedBytes(t *testing.T) {
	useState(t)
	workspace := t.TempDir()
	writeFile(t, filepath.Join(workspace, "flake.nix"), "{ }\n")
	writeFile(t, filepath.Join(workspace, "flake.lock"), `{"version": 7, "root": "root", "nodes": {"root": {}}}`)
	writeFile(t, filepath.Join(workspace, "backups.nix"), "{ }\n")
	writeFile(t, filepath.Join(workspace, "alpha/default.nix"), "{ }\n")
	writeFile(t, filepath.Join(workspace, "alpha/secrets.enc.yaml"), "sops: {}\n")
	writeFile(t, filepath.Join(workspace, "beta/default.nix"), "{ }\n")
	oldSources := os.Getenv("NIXUS_PROJECT_SOURCES")
	os.Setenv("NIXUS_PROJECT_SOURCES", filepath.Join(t.TempDir(), "none"))
	defer os.Setenv("NIXUS_PROJECT_SOURCES", oldSources)
	tx := &ProjectTransactions{workspace: workspace, state: STATE}
	inventory := M{"projects": M{
		"alpha": M{"source": "alpha", "backend": "incus-native", "enable": true, "incusProject": "alpha"},
		"beta":  M{"source": "beta", "backend": "incus-compose", "enable": true, "incusProject": "beta"}}}
	policy := backupPolicyFixture()
	policy["includeProjects"] = []any{"alpha"}
	destination := filepath.Join(t.TempDir(), "snap")
	manifest, err := configSnapshot(tx, policy, inventory, destination)
	if err != nil {
		t.Fatal(err)
	}
	files := obj(manifest["files"])
	for _, want := range []string{"workspace/flake.nix", "workspace/backups.nix", "workspace/alpha/default.nix", "workspace/alpha/secrets.enc.yaml"} {
		if files[want] == nil {
			t.Errorf("missing %s", want)
		}
	}
	if files["workspace/beta/default.nix"] != nil {
		t.Error("excluded project copied")
	}
	if jget(manifest, "projects", "alpha", "data") != "not-selected" {
		t.Errorf("coverage: %v", manifest["projects"])
	}
	if _, err := os.Stat(filepath.Join(destination, "MANIFEST.json")); err != nil {
		t.Fatal(err)
	}
}

func TestProjectFileAllowlist(t *testing.T) {
	for _, ok := range []string{"backups.nix", "alpha/default.nix", "alpha/modules/net.nix", "alpha/modules/a/b.nix"} {
		if !fullmatch(editableProjectFile, ok) {
			t.Errorf("rejected %s", ok)
		}
	}
	for _, bad := range []string{"flake.nix", "flake.lock", "alpha/secrets.enc.yaml", "alpha/../x.nix", "alpha/modules/.x.nix", "/etc/passwd", "alpha/.sops.yaml"} {
		if fullmatch(editableProjectFile, bad) {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := projectFile("alpha/secrets.enc.yaml"); err == nil {
		t.Fatal("ciphertext file opened in the editor")
	}
}

func TestForwardedQueryOnlyPassesReviewedParameters(t *testing.T) {
	r, _ := http.NewRequest("GET", "/api/project-logs?project=beta&instance=web&evil=1", nil)
	if got := forwardedQuery("/api/project-logs", r); got != "?instance=web&project=beta" {
		t.Fatalf("logs: %q", got)
	}
	r, _ = http.NewRequest("GET", "/api/status?x=1", nil)
	if forwardedQuery("/api/status", r) != "" {
		t.Fatal("query forwarded for a view without parameters")
	}
}

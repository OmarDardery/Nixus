package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupDestinationBuildsRepositories(t *testing.T) {
	cases := []struct {
		body M
		repo string
		env  int
	}{
		{M{"kind": "local", "path": "/mnt/backup/nixus"}, "/mnt/backup/nixus", 0},
		{M{"kind": "s3", "endpoint": "s3.example.com", "bucket": "nixus", "accessKey": "a", "secretKey": "b"}, "s3:s3.example.com/nixus", 2},
		{M{"kind": "b2", "bucket": "nixus", "accountId": "a", "accountKey": "b"}, "b2:nixus", 2},
		{M{"kind": "rclone", "remote": "gdrive", "folder": "nixus", "config": "[gdrive]\ntype = drive\n"}, "rclone:gdrive:nixus", 0},
	}
	for _, c := range cases {
		repo, env, _, err := backupDestination(c.body)
		if err != nil || repo != c.repo || len(env) != c.env {
			t.Fatalf("%v: %s %v %v", c.body, repo, env, err)
		}
		if !fullmatch(resticRepository, repo) {
			t.Fatalf("%s fails the policy pattern", repo)
		}
	}
	for _, bad := range []M{
		{"kind": "local", "path": "relative"}, {"kind": "local", "path": "/a/../b"},
		{"kind": "s3", "endpoint": "x", "bucket": "b"}, {"kind": "rclone", "remote": "gdrive", "folder": "f", "config": "[other]"},
		{"kind": "s3", "endpoint": "s3.example.com", "bucket": "b", "accessKey": "a\nB2_ACCOUNT_ID=x", "secretKey": "b"},
		{"kind": "ftp"},
	} {
		if _, _, _, err := backupDestination(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestBackupPolicyTextValidates(t *testing.T) {
	text := backupPolicyText("s3:s3.example.com/nixus", "daily", "full", true, "", "/var/lib/nixus-secrets/project-restic-environment")
	for _, want := range []string{`repository = "s3:s3.example.com/nixus";`, `environmentFile = "/var/lib/nixus-secrets/project-restic-environment";`, "initialize = true;", `verification = "full";`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in\n%s", want, text)
		}
	}
	if strings.Contains(text, "github") {
		t.Fatal("unexpected github mirror")
	}
}

// The generated password survives a failed first attempt and is shown by the
// first successful one (#116).
func TestFirstBackupPasswordSurvivesAFailedSetup(t *testing.T) {
	dir := useState(t)
	oldDir, oldPw := backupSecretsDir, backupPasswordPth
	backupSecretsDir, backupPasswordPth = dir, filepath.Join(dir, "pw")
	defer func() { backupSecretsDir, backupPasswordPth = oldDir, oldPw }()
	// First attempt: the folder cannot be created, so setup fails after the password exists.
	if _, err := setupBackups("admin", M{"kind": "local", "path": "/proc/nixus-no-such/backup"}); err == nil {
		t.Fatal("setup into an impossible folder succeeded")
	}
	if !isFile(backupPasswordPth) || !isFile(pendingBackupPasswordMarker()) {
		t.Fatal("the password must be kept and marked as not yet shown")
	}
	first, _ := os.ReadFile(backupPasswordPth)
	// Nothing is handed out while setup is still failing.
	if got := takePendingBackupPassword(); got == "" || got != strings.TrimSpace(string(first)) {
		t.Fatalf("pending password: %q", got)
	}
	// Once handed over, it is not shown again.
	if takePendingBackupPassword() != "" {
		t.Fatal("password shown twice")
	}
}

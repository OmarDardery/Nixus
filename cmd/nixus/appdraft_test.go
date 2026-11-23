package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDraftRoundTripAndList(t *testing.T) {
	useState(t)
	body := M{"name": "notes", "mode": "files", "entries": []any{M{"path": "compose.yaml", "text": "services: {}\n"}}, "nix": "", "instance": M{"cpus": 2.0, "image": "debian"}}
	out, err := saveDraft("admin", body)
	if err != nil || out["saved"] != true || out["envSaved"] != false {
		t.Fatalf("save: %v %v", out, err)
	}
	listed := list(listDrafts()["drafts"])
	if len(listed) != 1 || str(obj(listed[0])["name"]) != "notes" {
		t.Fatalf("list: %v", listed)
	}
	if strings.Contains(string(jsonFile(listDrafts())), "services") {
		t.Fatal("the list must not return file contents")
	}
	got, err := readDraft("notes", false)
	if err != nil || str(obj(list(got["entries"])[0])["text"]) != "services: {}\n" || got["mode"] != "files" {
		t.Fatalf("read: %v %v", got, err)
	}
	if _, err := deleteDraft("notes"); err != nil {
		t.Fatal(err)
	}
	if _, err := readDraft("notes", false); err == nil {
		t.Fatal("deleted draft still readable")
	}
}

func TestDraftValidation(t *testing.T) {
	useState(t)
	for name, body := range map[string]M{
		"bad name": {"name": "../x", "mode": "files"},
		"bad mode": {"name": "ok", "mode": "zip"},
		"huge":     {"name": "ok", "mode": "files", "entries": []any{M{"path": "a", "text": strings.Repeat("x", maxDraftEntry+1)}}},
		"many":     {"name": "ok", "mode": "files", "entries": make([]any, maxDraftEntries+1)},
	} {
		if _, err := saveDraft("admin", body); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := readDraft("../etc", false); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestDraftEnvWithoutKeyIsLeftOut(t *testing.T) {
	dir := useState(t)
	out, err := saveDraft("admin", M{"name": "app", "mode": "nix", "nix": "{}", "env": M{"GREETING": "hello"}})
	if err != nil || out["envSaved"] != false || str(out["note"]) == "" {
		t.Fatalf("expected a note about the missing key: %v %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "app-drafts", "app.env.age")); err == nil {
		t.Fatal("env file written without a key")
	}
	raw, _ := os.ReadFile(draftPath("app"))
	if strings.Contains(string(raw), "hello") {
		t.Fatal("plaintext variable stored in the draft")
	}
}

func TestDraftEnvIsSealedAndRestored(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age not installed")
	}
	useState(t)
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	key := filepath.Join(dir, "projects.agekey")
	if out, err := exec.Command("age-keygen", "-o", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	old := projectsIdentity
	projectsIdentity = key
	defer func() { projectsIdentity = old }()
	out, err := saveDraft("admin", M{"name": "app", "mode": "nix", "nix": "{}", "env": M{"API_KEY": "sk-plain-value"}})
	if err != nil || out["envSaved"] != true {
		t.Fatalf("%v %v", out, err)
	}
	for _, p := range []string{draftPath("app"), draftEnvPath("app")} {
		raw, _ := os.ReadFile(p)
		if strings.Contains(string(raw), "sk-plain-value") {
			t.Fatalf("plaintext variable on disk in %s", p)
		}
	}
	if plain, _ := readDraft("app", false); plain["env"] != nil {
		t.Fatal("variables returned without reauthentication")
	}
	got, err := readDraft("app", true)
	if err != nil || obj(got["env"])["API_KEY"] != "sk-plain-value" || got["envCount"] != float64(1) && got["envCount"] != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := deleteDraft("app"); err != nil || isFile(draftEnvPath("app")) {
		t.Fatalf("env file left behind: %v", err)
	}
}

func TestFailedAddsTheCausesLastLine(t *testing.T) {
	got := publicError(Failed("Incus operation failed", errors.New("Error: first\nError: Instance not found")))
	if got != "Incus operation failed: Error: Instance not found" {
		t.Fatalf("%q", got)
	}
	if got := publicError(Failed("Could not run", nil)); got != "Could not run" {
		t.Fatalf("%q", got)
	}
	if got := publicError(Failed("Outer", Public("inner reason"))); got != "Outer: inner reason" {
		t.Fatalf("%q", got)
	}
	res := CmdResult{Stderr: []byte("noise\nrestic: wrong password\n")}
	if got := publicError(cmdFailed("restic check failed", res, nil)); got != "restic check failed: restic: wrong password" {
		t.Fatalf("%q", got)
	}
}

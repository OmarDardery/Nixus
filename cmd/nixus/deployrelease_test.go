package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A deployment whose worker is gone can never finish; it must not block host
// changes forever.
func TestStaleProjectDeploymentIsReleased(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, "project-transactions", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	os.MkdirAll(dir, 0o700)
	writeJSON(filepath.Join(dir, "deployment.json"), M{"status": "applying", "updatedAt": now() - 600})
	writeJSON(filepath.Join(state, "project-deploy-active.json"), M{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	alive := true
	old := projectWorkerActive
	projectWorkerActive = func(string) bool { return alive }
	defer func() { projectWorkerActive = old }()

	if checkIdle(state, "") == nil {
		t.Fatal("a running deployment must block host changes")
	}
	alive = false
	if err := checkIdle(state, ""); err != nil {
		t.Fatalf("a deployment whose worker stopped must be released: %v", err)
	}
	if isFile(filepath.Join(state, "project-deploy-active.json")) {
		t.Fatal("the active marker must be removed")
	}
	if j := readObj(filepath.Join(dir, "deployment.json")); str(j["status"]) != "superseded" || str(j["supersededFrom"]) != "applying" {
		t.Fatalf("journal kept and marked: %v", j)
	}
}

func TestFreshProjectDeploymentIsNotReleased(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, "project-transactions", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	os.MkdirAll(dir, 0o700)
	writeJSON(filepath.Join(dir, "deployment.json"), M{"status": "queued", "updatedAt": now()})
	writeJSON(filepath.Join(state, "project-deploy-active.json"), M{"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
	old := projectWorkerActive
	projectWorkerActive = func(string) bool { return false }
	defer func() { projectWorkerActive = old }()
	if activeProjectDeployment(state) != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatal("a just-queued deployment's worker may not have started yet")
	}
}

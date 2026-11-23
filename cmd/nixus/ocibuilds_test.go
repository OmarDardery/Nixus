package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Apps made only of prebuilt images have nothing to build: the job must not
// start the sandbox and must end up imported with no artifacts.
func TestImageOnlyBuildSkipsSandbox(t *testing.T) {
	state := useState(t)
	oldSandbox := ociRunSandbox
	ociRunSandbox = func(string, string, string) error { t.Fatal("sandbox must not run for image-only apps"); return nil }
	t.Cleanup(func() { ociRunSandbox = oldSandbox })
	b := NewOCIBuilds(state, nil)
	var created []string
	b.incus = func(_ time.Duration, args ...string) (string, error) {
		if len(args) > 1 && args[0] == "project" && args[1] == "create" {
			created = append(created, args[2])
		}
		if args[0] == "query" {
			return "", os.ErrNotExist
		}
		return "", nil
	}
	id := tokenHex(16)
	dir := filepath.Join(b.jobs, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	record := M{"id": id, "format": 1, "project": "aiostreams", "revision": strings.Repeat("a", 64), "status": "queued",
		"services": []any{M{"service": "web", "image": "ghcr.io/x/y@sha256:" + strings.Repeat("b", 64), "built": false}}}
	writeJSON(filepath.Join(dir, "job.json"), record)
	out, err := b.run(id)
	if err != nil {
		t.Fatal(err)
	}
	if str(out["status"]) != "imported" {
		t.Fatalf("status %v, detail %v", out["status"], out["errorDetail"])
	}
	if len(created) != 1 {
		t.Fatalf("incus project not prepared: %v", created)
	}
}

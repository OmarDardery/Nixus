package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestComposeUpCommand(t *testing.T) {
	scratch := t.TempDir()
	image := M{"intentHash": "new", "services": []any{M{"service": "web", "built": false}}}
	args, _, err := composeUpCommand("incus-compose", []string{"-p", "x"}, image, "", scratch)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--no-build") || slices.Contains(args, "--build") || slices.Contains(args, "--recreate") {
		t.Fatalf("image-only first deploy: %v", args)
	}
	args, _, _ = composeUpCommand("incus-compose", nil, image, "old", scratch)
	if !slices.Contains(args, "--recreate") {
		t.Fatalf("a new revision must recreate instances: %v", args)
	}
	args, _, _ = composeUpCommand("incus-compose", nil, image, "new", scratch)
	if slices.Contains(args, "--recreate") {
		t.Fatalf("an unchanged revision must not recreate: %v", args)
	}
	built := M{"intentHash": "new", "services": []any{M{"service": "app", "built": true}}}
	t.Setenv("NIXUS_OCI_BUILDAH_BIN", "/nix/store/x-buildah/bin/buildah")
	args, env, err := composeUpCommand("incus-compose", nil, built, "", scratch)
	if err != nil || !slices.Contains(args, "--build") || slices.Contains(args, "--no-build") ||
		args[slices.Index(args, "--builder")+1] != "/nix/store/x-buildah/bin/buildah" || !slices.Contains(env, "BUILDAH_ISOLATION=chroot") {
		t.Fatalf("built service: %v %v %v", args, env, err)
	}
}

// The real parser names paths under the materialised source; validation must
// see them under /context. Skipped where incus-compose is not installed.
func TestComposeModelRootsPathsAtContext(t *testing.T) {
	bin := "/nix/store/0fzs9002z6jlram1zm408djf6alz71sy-incus-compose-1.4.1/bin/incus-compose"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("incus-compose not available")
	}
	t.Setenv("NIXUS_OCI_COMPOSE_BIN", bin)
	t.Setenv("NIXUS_OCI_PATH", "/usr/bin:/bin")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  app:\n    build: .\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o600)
	model, err := composeJSON(M{"project": "demo", "entrypoint": "compose.yaml"}, dir, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	context := str(obj(obj(obj(model["services"])["app"])["build"])["context"])
	if context != "/context" {
		t.Fatalf("context %q", context)
	}
	if p, err := composeSourcePath(".", context, true); err != nil || p != "." {
		t.Fatalf("%q %v", p, err)
	}
}

// reviewFixture publishes files as a project's source and reviews them with
// the real incus-compose parser.
func reviewFixture(t *testing.T, project string, files map[string]string) (M, error) {
	t.Helper()
	bin := "/nix/store/0fzs9002z6jlram1zm408djf6alz71sy-incus-compose-1.4.1/bin/incus-compose"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("incus-compose not available")
	}
	useState(t)
	t.Setenv("NIXUS_OCI_COMPOSE_BIN", bin)
	t.Setenv("NIXUS_OCI_PATH", "/usr/bin:/bin")
	var entries []any
	var list []sourceEntry
	contents := map[string][]byte{}
	for name, text := range files {
		sum := sha256.Sum256([]byte(text))
		e := sourceEntry{name, int64(len(text)), hex.EncodeToString(sum[:])}
		list = append(list, e)
		entries = append(entries, e.M())
		contents[name] = []byte(text)
	}
	staged, err := stageFiles("admin", project, entries, list, contents)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := publishStaged("admin", M{"id": staged["id"], "manifestHash": staged["manifestHash"]})
	if err != nil {
		t.Fatal(err)
	}
	builds := NewOCIBuilds("", nil)
	builds.incus = func(time.Duration, ...string) (string, error) { return "", nil }
	return builds.review(project, revision, "admin")
}

func TestReviewImageOnlyApp(t *testing.T) {
	digest := strings.Repeat("a", 64)
	out, err := reviewFixture(t, "aiostreams", map[string]string{
		"compose.yaml": "services:\n  web:\n    image: ghcr.io/x/y:latest@sha256:" + digest + "\n    ports:\n      - \"3000:3000\"\n    volumes:\n      - data:/app/data\nvolumes:\n  data: {}\n"})
	if err != nil {
		t.Fatal(publicError(err))
	}
	if str(out["status"]) != "imported" {
		t.Fatalf("%v", out)
	}
	services := list(out["services"])
	if len(services) != 1 || isTrue(obj(services[0])["built"]) {
		t.Fatalf("services: %v", services)
	}
}

func TestReviewDockerfileApp(t *testing.T) {
	digest := strings.Repeat("b", 64)
	out, err := reviewFixture(t, "hello", map[string]string{
		"compose.yaml": "services:\n  hello:\n    build: .\n",
		"Dockerfile":   "FROM docker.io/library/debian:13@sha256:" + digest + "\nCMD [\"sleep\", \"1\"]\n"})
	if err != nil {
		t.Fatal(publicError(err))
	}
	services := list(out["services"])
	if len(services) != 1 || !isTrue(obj(services[0])["built"]) {
		t.Fatalf("services: %v", services)
	}
}

func TestReviewLoneDockerfile(t *testing.T) {
	digest := strings.Repeat("c", 64)
	if _, err := reviewFixture(t, "solo", map[string]string{"Dockerfile": "FROM docker.io/library/debian:13@sha256:" + digest + "\n"}); err != nil {
		t.Fatal(publicError(err))
	}
}

func TestReviewRefusesUnpinnedImage(t *testing.T) {
	if _, err := reviewFixture(t, "loose", map[string]string{"compose.yaml": "services:\n  web:\n    image: nginx:latest\n"}); err == nil {
		t.Fatal("an unpinned image was approved")
	}
}

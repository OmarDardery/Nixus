package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestComposeUpCommand(t *testing.T) {
	scratch := t.TempDir()
	image := M{"intentHash": "new", "services": []any{M{"service": "web", "built": false}}}
	args, _, err := composeUpCommand("incus-compose", []string{"-p", "x"}, image, scratch)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--no-build") || slices.Contains(args, "--build") || slices.Contains(args, "--recreate") {
		t.Fatalf("image-only first deploy: %v", args)
	}
	built := M{"intentHash": "new", "services": []any{M{"service": "app", "built": true}}}
	t.Setenv("NIXUS_OCI_BUILDAH_BIN", "/nix/store/x-buildah/bin/buildah")
	args, env, err := composeUpCommand("incus-compose", nil, built, scratch)
	if err != nil || !slices.Contains(args, "--build") || slices.Contains(args, "--no-build") ||
		args[slices.Index(args, "--builder")+1] != "/nix/store/x-buildah/bin/buildah" || !slices.Contains(env, "BUILDAH_ISOLATION=chroot") {
		t.Fatalf("built service: %v %v %v", args, env, err)
	}
	if _, err := os.Stat(filepath.Join(scratch, ".config", "containers", "policy.json")); err != nil {
		t.Fatalf("buildah needs a signature policy under HOME: %v", err)
	}
	if !slices.Contains(env, "HOME="+scratch) {
		t.Fatalf("HOME must point at the scratch directory: %v", env)
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

// Variables must be set before the containers start, so a service that needs
// them at startup does not exit and fail the deployment.
func TestStartCommandOnlyStartsExistingInstances(t *testing.T) {
	scratch := t.TempDir()
	t.Setenv("NIXUS_OCI_BUILDAH_BIN", "/nix/store/x-buildah/bin/buildah")
	built := M{"intentHash": "h", "services": []any{M{"service": "app", "built": true}}}
	args, _, err := composeUpCommand("incus-compose", []string{"-p", "x"}, built, scratch)
	if err != nil || !slices.Contains(args, "--build") {
		t.Fatalf("the first run builds: %v %v", args, err)
	}
	start := startCommand(args)
	if slices.Contains(start, "--build") || slices.Contains(start, "--builder") || slices.Contains(start, "/nix/store/x-buildah/bin/buildah") {
		t.Fatalf("starting must not build: %v", start)
	}
	if !slices.Contains(start, "--no-build") || !slices.Contains(start, "--detach") || !slices.Contains(start, "up") {
		t.Fatalf("starting still brings the project up detached: %v", start)
	}
}

func TestNotRunningNamesTheServices(t *testing.T) {
	resource := M{"services": []any{"aiostreams", "cloudflared", "ghost"},
		"instances": M{"a-1": M{"service": "aiostreams", "status": "Running"}, "c-1": M{"service": "cloudflared", "status": "Stopped"}}}
	got := notRunning(resource)
	if !strings.Contains(got, "cloudflared is Stopped") || !strings.Contains(got, "ghost has no instance") || strings.Contains(got, "aiostreams is") {
		t.Fatalf("%q", got)
	}
	if notRunning(M{"services": []any{"a"}, "instances": M{"a-1": M{"service": "a", "status": "Running"}}}) != "" {
		t.Fatal("nothing to report when everything runs")
	}
}

func TestAppStartEnvUsesPendingValues(t *testing.T) {
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
	if v, err := appStartEnv("web"); err != nil || len(v) != 0 {
		t.Fatal("an app without variables starts as before")
	}
	if err := sealDeployEnv("web", M{"TUNNEL_TOKEN": "t", "SECRET_KEY": "k"}); err != nil {
		t.Fatal(err)
	}
	got, err := appStartEnv("web")
	if err != nil {
		t.Fatal(err)
	}
	if got["TUNNEL_TOKEN"] != "t" || got["SECRET_KEY"] != "k" {
		t.Fatalf("pending variables must be available before the first start: %v", got)
	}
	os.WriteFile(appEnvPath("web"), []byte("not age data"), 0o600)
	if _, err := appStartEnv("web"); err == nil {
		t.Fatal("an unreadable pending file must be an error, not an app started without its variables")
	}
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	if slices.Contains(args, "--image-cache") || slices.Contains(args, "--no-dns") || slices.Contains(args, "--no-healthd") {
		t.Fatalf("online deploy should use native incus-compose defaults: %v", args)
	}
	t.Setenv("NIXUS_COMPOSE_OFFLINE", "1")
	offArgs, _, err := composeUpCommand("incus-compose", []string{"-p", "x"}, image, scratch)
	if err != nil {
		t.Fatal(err)
	}
	if idx := slices.Index(offArgs, "--image-cache"); idx < 0 || offArgs[idx+1] != "" || slices.Contains(offArgs, "--no-dns") || slices.Contains(offArgs, "--no-healthd") {
		t.Fatalf("offline deploy flags: %v", offArgs)
	}
	t.Setenv("NIXUS_COMPOSE_OFFLINE", "")
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
	pubRoot := filepath.Join(t.TempDir(), "project-sources")
	os.MkdirAll(pubRoot, 0o700)
	t.Setenv("NIXUS_PROJECT_SOURCES", pubRoot)
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

// An app's variables are part of the Compose model, so each container is
// created with them and records user.nixus.env-keys; "$" reaches the container literally.
func TestAppComposeOverrideSetsEnvSecretsAndAutostart(t *testing.T) {
	var doc M
	if err := json.Unmarshal(appComposeOverride([]string{"web", "tunnel"}, M{"TUNNEL_TOKEN": "a$b"}, nil, "", M{"web": "/run/nixus-secrets/demo/web", "tunnel": "/run/nixus-secrets/demo/tunnel"}, nil), &doc); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"web", "tunnel"} {
		svc := obj(obj(doc["services"])[s])
		if svc["container_name"] != nil {
			t.Fatalf("incus-compose should own container naming: %v", svc)
		}
		if got := obj(svc["environment"])["TUNNEL_TOKEN"]; got != "a$$b" {
			t.Fatalf("%s: %v", s, got)
		}
		if str(jget(svc, "x-incus", envKeysConfig)) != "TUNNEL_TOKEN" || jget(svc, "x-incus", "boot.autostart") != nil {
			t.Fatalf("x-incus metadata: %v", svc)
		}
		sec := obj(jget(svc, "x-incus-compose", "devices", "nixus-secrets"))
		if str(sec["type"]) != "disk" || str(sec["source"]) != "/run/nixus-secrets/demo/"+s || str(sec["path"]) != "/run/secrets" || str(sec["readonly"]) != "true" {
			t.Fatalf("secrets mount: %v", sec)
		}
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
	oldIncus, oldMount, oldInject, oldRoot := updateIncus, ensureSecretsDiskMount, injectEnv, secretMountRoot
	defer func() {
		updateIncus, ensureSecretsDiskMount, injectEnv, secretMountRoot = oldIncus, oldMount, oldInject, oldRoot
	}()
	secretMountRoot = filepath.Join(t.TempDir(), "mounts")
	updateIncus = func(time.Duration, ...string) (string, error) {
		return `[{"name":"web-1","config":{"user.label.incus-compose.service":"web"},"status":"Running"}]`, nil
	}
	ensureSecretsDiskMount = func(string, string, string) error { return nil }
	var delivered M
	injectEnv = func(_, _ string, values M) (bool, error) { delivered = values; return false, nil }
	if _, err := deliverProjectSecrets("web", M{"enable": true, "backend": composeBackend, "incusProject": "web"}); err != nil {
		t.Fatal(err)
	}
	if !equalJSON(got, delivered) {
		t.Fatalf("post-deploy delivery cleared pending startup variables: %v", delivered)
	}
	os.WriteFile(appEnvPath("web"), []byte("not age data"), 0o600)
	if _, err := appStartEnv("web"); err == nil {
		t.Fatal("an unreadable pending file must be an error, not an app started without its variables")
	}
}

// A failed start explains itself: which variables were used and what the
// stopped container printed.
func TestStartDetailNamesVariablesAndLogTail(t *testing.T) {
	useState(t)
	resource := M{"instances": M{"cf-1": M{"service": "cloudflared", "status": "Stopped"}, "web-1": M{"service": "web", "status": "Running"}}}
	var asked []string
	incus := func(_ time.Duration, args ...string) (string, error) {
		asked = append(asked, args[1])
		return "line1\nERR requires the ID or name of the tunnel\n", nil
	}
	got := startDetail(incus, "web", "web", resource)
	if !strings.Contains(got, "Started with no variables") || !strings.Contains(got, "cloudflared log:") ||
		!strings.Contains(got, "requires the ID or name of the tunnel") {
		t.Fatalf("%q", got)
	}
	if len(asked) != 1 || asked[0] != "cf-1" {
		t.Fatalf("only stopped containers are read: %v", asked)
	}
}

// "Own IP on your router": only the chosen services attach to the external LAN network.
func TestAppComposeOverrideLANNetwork(t *testing.T) {
	var doc M
	if err := json.Unmarshal(appComposeOverride([]string{"aiostreams", "cloudflared"}, nil, map[string]bool{"aiostreams": true}, "nixus-lan", nil, nil), &doc); err != nil {
		t.Fatal(err)
	}
	if jget(obj(obj(doc["services"])["aiostreams"]), "networks", "nixus_lan") == nil {
		t.Fatalf("aiostreams missing nixus_lan: %v", doc)
	}
	if jget(obj(obj(doc["services"])["cloudflared"]), "networks") != nil {
		t.Fatalf("cloudflared stays private: %v", doc)
	}
	lanDef := obj(jget(doc, "networks", "nixus_lan"))
	if str(lanDef["name"]) != "nixus-lan" || !isTrue(lanDef["external"]) {
		t.Fatalf("external LAN network definition: %v", lanDef)
	}
}

func TestLANServicesAndNetworkName(t *testing.T) {
	if got := lanServices(M{"network": M{"lan": M{"services": []any{"web", "db", "web"}}}}); got != "db,web" {
		t.Fatalf("%q", got)
	}
	if lanServices(M{}) != "" {
		t.Fatal("private by default")
	}
	dir := t.TempDir()
	old := effectiveSettingsPath
	defer func() { effectiveSettingsPath = old }()
	effectiveSettingsPath = filepath.Join(dir, "effective-settings.json")
	if _, err := lanNetworkName(); err == nil {
		t.Fatal("no LAN interface configured is an error")
	}
	os.WriteFile(effectiveSettingsPath, []byte(`{"management":{"interface":"eth0"},"connectivity":{"bridges":[]},"radios":{"wifi":{"enable":false,"interface":""}}}`), 0o644)
	if netName, err := lanNetworkName(); err != nil || netName != "nixus-lan" {
		t.Fatalf("wired Ethernet uses preseeded nixus-lan: %q %v", netName, err)
	}
	os.WriteFile(effectiveSettingsPath, []byte(`{"management":{"interface":"br-lan"},"connectivity":{"bridges":[{"name":"br-lan","interfaces":["eth0"]}]},"radios":{"wifi":{"enable":false,"interface":""}}}`), 0o644)
	if netName, err := lanNetworkName(); err != nil || netName != "br-lan" {
		t.Fatalf("host bridge is referenced directly: %q %v", netName, err)
	}
	os.WriteFile(effectiveSettingsPath, []byte(`{"management":{"interface":"wlan0"},"connectivity":{"bridges":[]},"radios":{"wifi":{"enable":true,"interface":"wlan0"}}}`), 0o644)
	if _, err := lanNetworkName(); err == nil {
		t.Fatal("Wi-Fi should be rejected for LAN IP")
	}
}

func TestWaitRunningStopsImmediatelyWhenReady(t *testing.T) {
	old := waitSleep
	defer func() { waitSleep = old }()
	waitSleep = func(time.Duration) {}
	seq := []string{"compose-up", "noop"}
	n := 0
	r, _ := waitRunning(func() (M, error) { s := seq[min(n, len(seq)-1)]; n++; return M{"action": s}, nil },
		func(r M) bool { return r["action"] == "noop" })
	if r["action"] != "noop" || n != 2 {
		t.Fatalf("%v after %d", r, n)
	}
	n = 0
	r, _ = waitRunning(func() (M, error) { n++; return M{"action": "compose-up"}, nil }, func(r M) bool { return r["action"] == "noop" })
	if r["action"] == "noop" || n != 6 {
		t.Fatalf("a service that stays stopped fails: %v after %d", r, n)
	}
}

func TestLegacyNamingMigrationKeepsExplicitNamesAndNativeReplicas(t *testing.T) {
	instances := []M{{"name": "web", "service": "web"}, {"name": "db-1", "service": "db"}, {"name": "explicit", "service": "explicit"}, {"name": "old-api", "service": "old_api"}}
	legacy := legacyComposeServices(instances, M{"explicit": M{"container_name": "explicit"}})
	if len(legacy) != 2 || legacy["web"] == nil || legacy["old_api"] == nil {
		t.Fatalf("wrong legacy retirement: %v", legacy)
	}
	if legacy["db"] != nil || legacy["explicit"] != nil {
		t.Fatal("native names treated as legacy")
	}
}

func TestGlobalComposeControllersAreInfrastructure(t *testing.T) {
	for _, name := range []string{"ic-dns", "ic-healthd"} {
		if !isComposeSidecar("incus-compose", name) {
			t.Fatal("global controller exported as a guest")
		}
		if isComposeSidecar("my-app", name) {
			t.Fatal("app instance mistaken for global infrastructure")
		}
	}
}

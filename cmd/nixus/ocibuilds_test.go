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

// An app's variables are part of the Compose model, so each container is
// created with them; "$" must reach the container literally.
func TestServiceOverrideNamesContainersAfterServices(t *testing.T) {
	var doc M
	if err := json.Unmarshal(serviceOverride([]string{"web", "my_db"}, nil, nil, nil), &doc); err != nil {
		t.Fatal(err)
	}
	if got := obj(obj(doc["services"])["web"]); str(got["container_name"]) != "web" || got["environment"] != nil {
		t.Fatalf("%v", got)
	}
	if got := obj(obj(doc["services"])["my_db"]); str(got["container_name"]) != "my-db" {
		t.Fatalf("Incus names have no underscore: %v", got)
	}
}

func TestEnvOverrideGivesEveryServiceTheVariables(t *testing.T) {
	var doc M
	if err := json.Unmarshal(serviceOverride([]string{"web", "tunnel"}, M{"TUNNEL_TOKEN": "a$b"}, nil, nil), &doc); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"web", "tunnel"} {
		if got := obj(obj(obj(doc["services"])[s])["environment"])["TUNNEL_TOKEN"]; got != "a$$b" {
			t.Fatalf("%s: %v", s, got)
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

// "Own IP on your router": only the chosen services get a LAN card.
func TestServiceOverrideLANCard(t *testing.T) {
	nic := M{"type": "nic", "nictype": "macvlan", "parent": "enp2s0", "name": "eth1"}
	var doc M
	if err := json.Unmarshal(serviceOverride([]string{"aiostreams", "cloudflared"}, nil, map[string]bool{"aiostreams": true}, nic), &doc); err != nil {
		t.Fatal(err)
	}
	dev := obj(obj(jget(obj(obj(doc["services"])["aiostreams"]), "x-incus-compose", "devices"))["lan"])
	if str(dev["nictype"]) != "macvlan" || str(dev["parent"]) != "enp2s0" {
		t.Fatalf("%v", doc)
	}
	if jget(obj(obj(doc["services"])["cloudflared"]), "x-incus-compose") != nil {
		t.Fatalf("cloudflared stays private: %v", doc)
	}
}

func TestLANServicesAndNIC(t *testing.T) {
	if got := lanServices(M{"network": M{"lan": M{"services": []any{"web", "db", "web"}}}}); got != "db,web" {
		t.Fatalf("%q", got)
	}
	if lanServices(M{}) != "" {
		t.Fatal("private by default")
	}
	dir := t.TempDir()
	old := lanSettingsPath
	defer func() { lanSettingsPath = old }()
	lanSettingsPath = filepath.Join(dir, "lan.json")
	if _, err := lanNIC(); err == nil {
		t.Fatal("no LAN interface configured is an error")
	}
	os.WriteFile(lanSettingsPath, []byte(`{"parent":"br-lan","nictype":"bridged"}`), 0o644)
	if nic, err := lanNIC(); err != nil || str(nic["parent"]) != "br-lan" || str(nic["nictype"]) != "bridged" {
		t.Fatalf("%v %v", nic, err)
	}
}

// Every container is created with its app network's gateway as DNS server.
func TestAppGatewayAndOverride(t *testing.T) {
	nets := `[{"name":"incusbr0","config":{"ipv4.address":"10.0.100.1/24"}},{"name":"aio_default","config":{"ipv4.address":"10.120.7.1/24"}}]`
	incus := func(_ time.Duration, args ...string) (string, error) { return nets, nil }
	if gw, err := appGateway(incus, "aio"); err != nil || gw != "10.120.7.1" {
		t.Fatalf("an existing app keeps its network: %q %v", gw, err)
	}
	gw, err := appGateway(incus, "web")
	if err != nil || !strings.HasPrefix(gw, "10.120.") || gw == "10.120.7.1" {
		t.Fatalf("a new app gets a free /24: %q %v", gw, err)
	}
	if again, _ := appGateway(incus, "web"); again != gw {
		t.Fatal("the choice is stable")
	}
	var doc M
	json.Unmarshal(appOverride(serviceOverride([]string{"web"}, nil, nil, nil), "10.120.9.1"), &doc)
	if str(jget(obj(obj(doc["services"])["web"]), "x-incus", "oci.dns.nameservers")) != "10.120.9.1" ||
		str(jget(doc, "networks", "default", "x-incus", "ipv4.address")) != "10.120.9.1/24" {
		t.Fatalf("%v", doc)
	}
}

func TestSettledWaitsForStableRunning(t *testing.T) {
	old := settleSleep
	defer func() { settleSleep = old }()
	settleSleep = func(time.Duration) {}
	seq := []string{"compose-up", "noop", "noop", "noop"}
	n := 0
	r, _ := settled(func() (M, error) { s := seq[min(n, len(seq)-1)]; n++; return M{"action": s}, nil },
		func(r M) bool { return r["action"] == "noop" })
	if r["action"] != "noop" || n != 4 {
		t.Fatalf("%v after %d", r, n)
	}
	n = 0
	r, _ = settled(func() (M, error) { n++; return M{"action": "compose-up"}, nil }, func(r M) bool { return r["action"] == "noop" })
	if r["action"] == "noop" || n != 30 {
		t.Fatalf("a service that stays stopped fails: %v after %d", r, n)
	}
	var doc M
	json.Unmarshal(appOverride(serviceOverride([]string{"web"}, nil, nil, nil), "10.120.9.1"), &doc)
	if str(jget(obj(obj(doc["services"])["web"]), "x-incus", "boot.autorestart")) != "true" {
		t.Fatalf("%v", doc)
	}
}

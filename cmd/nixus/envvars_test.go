package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnvPatchManagesOnlyNixusVariables(t *testing.T) {
	config := M{"environment.PATH": "/bin", "environment.OLD": "x", "environment.KEEP": "same", envKeysConfig: "KEEP,OLD"}
	patch, changed := envPatch(config, M{"KEEP": "same", "NEW": "v"})
	if !changed {
		t.Fatal("no change detected")
	}
	if patch["environment.NEW"] != "v" || patch["environment.OLD"] != "" || patch[envKeysConfig] != "KEEP,NEW" {
		t.Fatalf("patch %v", patch)
	}
	if _, touched := patch["environment.PATH"]; touched {
		t.Fatal("touched an image-defined variable")
	}
	if _, touched := patch["environment.KEEP"]; touched {
		t.Fatal("rewrote an unchanged variable")
	}
	if _, changed := envPatch(M{"environment.A": "1", envKeysConfig: "A"}, M{"A": "1"}); changed {
		t.Fatal("unchanged variables reported as changed")
	}
	if patch, _ := envPatch(M{"environment.A": "1", envKeysConfig: "A"}, M{"A": "2"}); patch["environment.A"] != "2" {
		t.Fatal("changed value not applied")
	}
}

func TestInjectEnvRestartsOnlyRunningContainersOnChange(t *testing.T) {
	oldAPI, oldIncus := envAPI, updateIncus
	defer func() { envAPI, updateIncus = oldAPI, oldIncus }()
	var puts, restarts int
	state := M{"config": M{}, "status": "Running", "type": "container", "devices": M{}, "profiles": []any{}}
	envAPI = func(method, path string, body any, etag string) (M, string, error) {
		if method == "PUT" {
			puts++
			state["config"] = obj(body)["config"]
			if etag != "e1" {
				t.Fatal("PUT without the read ETag")
			}
		}
		return cloneM(state), "e1", nil
	}
	updateIncus = func(_ time.Duration, args ...string) (string, error) {
		if args[0] == "restart" {
			restarts++
		}
		return "", nil
	}
	if changed, err := injectEnv("p", "app-1", M{"TOKEN": "s"}); err != nil || !changed || puts != 1 || restarts != 1 {
		t.Fatalf("first apply: %v %v puts=%d restarts=%d", changed, err, puts, restarts)
	}
	if obj(state["config"])["environment.TOKEN"] != "s" {
		t.Fatalf("config %v", state["config"])
	}
	if changed, _ := injectEnv("p", "app-1", M{"TOKEN": "s"}); changed || puts != 1 || restarts != 1 {
		t.Fatal("re-applied unchanged variables")
	}
	state["type"] = "virtual-machine"
	injectEnv("p", "app-1", M{"TOKEN": "t"})
	if restarts != 1 {
		t.Fatal("restarted a VM for an environment change")
	}
}

func TestDeployEnvValidation(t *testing.T) {
	if m, err := deployEnv(nil); m != nil || err != nil {
		t.Fatalf("no env: %v %v", m, err)
	}
	if m, err := deployEnv(M{}); m != nil || err != nil {
		t.Fatalf("empty env: %v %v", m, err)
	}
	if m, err := deployEnv(M{"API_KEY": "x", "PORT": "80"}); err != nil || len(m) != 2 {
		t.Fatalf("valid env: %v %v", m, err)
	}
	for _, bad := range []any{M{"bad-name": "x"}, M{"OK": 5}, "KEY=value", M{"NUL": "a\x00b"}} {
		if _, err := deployEnv(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	many := M{}
	for i := 0; i < 65; i++ {
		many[fmt.Sprintf("K%d", i)] = "v"
	}
	if _, err := deployEnv(many); err == nil {
		t.Fatal("accepted 65 variables")
	}
}

func TestDeployWithEnvNeedsEncryptionKey(t *testing.T) {
	useState(t)
	_, err := startAppDeploy("admin", M{"project": "web", "kind": "nix", "declaration": "{ ... }: { }", "env": M{"API_KEY": "x"}})
	if err == nil || !strings.Contains(publicError(err), "encryption key") {
		t.Fatalf("expected a clear key error, got %v", err)
	}
	if isFile(appEnvPath("web")) || isFile(appJobPath("web")) {
		t.Fatal("nothing may be queued without a key")
	}
}

func TestDeployEnvIsSealedAtRest(t *testing.T) {
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
	if err := sealDeployEnv("web", M{"API_KEY": "sk-plain-value"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(appEnvPath("web"))
	if strings.Contains(string(raw), "sk-plain-value") || strings.Contains(string(raw), "API_KEY") {
		t.Fatal("pending variables must not be stored in plaintext")
	}
	vars, err := openDeployEnv("web")
	if err != nil || vars["API_KEY"] != "sk-plain-value" {
		t.Fatalf("%v %v", vars, err)
	}
}

// An empty value means "unset" in Incus: delivering it again must not look like
// a change (it used to restart the container every time), and removal works.
func TestEmptyEnvValueIsStable(t *testing.T) {
	config := M{envKeysConfig: ""}
	patch, changed := envPatch(config, M{"EMPTY": ""})
	if !changed || patch[envKeysConfig] != "EMPTY" {
		t.Fatalf("first delivery records the name: %v %v", patch, changed)
	}
	applied := M{envKeysConfig: "EMPTY"} // what the instance holds afterwards: no environment.EMPTY key
	for i := 0; i < 3; i++ {
		if p, changed := envPatch(applied, M{"EMPTY": ""}); changed {
			t.Fatalf("delivery %d must not change anything: %v", i, p)
		}
	}
	// Going from a real value to empty unsets it; removing the variable still works.
	if p, changed := envPatch(M{"environment.A": "1", envKeysConfig: "A"}, M{"A": ""}); !changed || p["environment.A"] != "" {
		t.Fatalf("emptying a set value: %v %v", p, changed)
	}
	if p, changed := envPatch(M{"environment.A": "1", envKeysConfig: "A"}, M{}); !changed || p["environment.A"] != "" || p[envKeysConfig] != "" {
		t.Fatalf("removal: %v %v", p, changed)
	}
}

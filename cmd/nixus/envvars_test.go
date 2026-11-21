package main

import (
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

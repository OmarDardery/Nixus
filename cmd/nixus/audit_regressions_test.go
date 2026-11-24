package main

import (
	"path/filepath"
	"testing"
)

func TestEmptyEnvironmentDeliveryUsesIncusUnsetSemantics(t *testing.T) {
	oldAPI, oldIncus := envAPI, updateIncus
	defer func() { envAPI, updateIncus = oldAPI, oldIncus }()
	state := M{"config": M{}, "status": "Stopped", "type": "container"}
	puts := 0
	envAPI = func(method, path string, body any, etag string) (M, string, error) {
		if method == "PUT" {
			puts++
			state["config"] = obj(body)["config"]
		}
		return cloneM(state), "tag", nil
	}
	for i := 0; i < 3; i++ {
		if _, err := injectEnv("p", "web", M{"EMPTY": ""}); err != nil {
			t.Fatal(err)
		}
	}
	if puts != 1 {
		t.Fatalf("got %d writes for unchanged empty value", puts)
	}
	if _, exists := obj(state["config"])["environment.EMPTY"]; exists {
		t.Fatal("empty value must use native Incus unset semantics")
	}
	if _, err := injectEnv("p", "web", M{}); err != nil {
		t.Fatal(err)
	}
	if _, exists := obj(state["config"])["environment.EMPTY"]; exists {
		t.Fatal("removed variable retained")
	}
}

func TestSuccessfulBackupHealth(t *testing.T) {
	useState(t)
	stamp := now()
	if err := writeJSON(filepath.Join(STATE, "project-backup-status.json"), M{"enabled": true, "schedule": "daily", "lastSuccess": stamp, "lastAttempt": stamp}); err != nil {
		t.Fatal(err)
	}
	if got := projectBackupHealth(); got != "ok" {
		t.Fatalf("health %s", got)
	}
}

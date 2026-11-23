package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A guest that cannot be restarted after its export must stop the backup, stay
// recorded across a restart of the process, and only clear after recovery (#107).
func TestBackupStopsWhenAGuestCannotBeRestarted(t *testing.T) {
	dir := t.TempDir()
	oldPending, oldIncus := backupPending, backupIncus
	backupPending = filepath.Join(dir, "restart-pending.json")
	defer func() { backupPending, backupIncus = oldPending, oldIncus }()
	destination := filepath.Join(dir, "out")
	os.MkdirAll(destination, 0o700)

	state := map[string]string{"a1": "Running", "b1": "Running"}
	startFails := true
	var calls []string
	backupIncus = func(_ time.Duration, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "stop":
			state[args[1]] = "Stopped"
		case "start":
			if args[1] == "a1" && startFails {
				return "", Hidden("start failed")
			}
			state[args[1]] = "Running"
		case "export":
			os.WriteFile(args[4], []byte("archive"), 0o600)
		case "query":
			// /1.0/instances/<name>/state?project=...
			for name, s := range state {
				if strings.Contains(args[1], "/"+name+"/state") {
					return `{"status":"` + s + `"}`, nil
				}
			}
			return `{}`, nil
		}
		return "", nil
	}
	group := func(name string) M {
		return M{"guests": []any{M{"project": "p", "name": name, "status": "Running", "archive": name + ".tar.gz"}}, "volumes": []any{}}
	}
	if _, err := backupGroups([]M{group("a1"), group("b1")}, destination, "gen"); err == nil {
		t.Fatal("a backup that left a guest stopped reported success")
	}
	for _, c := range calls {
		if strings.Contains(c, "b1") {
			t.Fatalf("the next group must not be touched after a failed recovery: %v", calls)
		}
	}
	raw, _ := os.ReadFile(backupPending)
	if !strings.Contains(string(raw), "a1") {
		t.Fatalf("the offline guest must stay recorded: %q", raw)
	}
	// A retry refuses to start until recovery succeeds, then clears the record.
	if err := backupRecover(); err == nil {
		t.Fatal("recovery must fail while the guest cannot start")
	}
	startFails = false
	if err := backupRecover(); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(backupPending)
	if strings.Contains(string(raw), "a1") || state["a1"] != "Running" {
		t.Fatalf("recovery should clear the record: %q %v", raw, state)
	}
}

// The staged inventory must not carry variable values (#110).
func TestBackupInventoryRedactsEnvironmentValues(t *testing.T) {
	guest := M{"name": "web", "project": "p", "config": M{"environment.API_TOKEN": "marker-s3cret", "limits.cpu": "2"},
		"expanded_config": M{"environment.API_TOKEN": "marker-s3cret", "volatile.uuid": "u"}}
	out := redactGuest(guest)
	if strings.Contains(string(jsonFile(out)), "marker-s3cret") {
		t.Fatalf("a value survived: %v", out)
	}
	if obj(out["config"])["limits.cpu"] != "2" || obj(out["expanded_config"])["volatile.uuid"] != "u" {
		t.Fatalf("other configuration must be kept: %v", out)
	}
	if _, ok := obj(out["config"])["environment.API_TOKEN"]; !ok {
		t.Fatal("the variable name is still listed")
	}
	if !strings.Contains(string(jsonFile(guest)), "marker-s3cret") {
		t.Fatal("the original record must not be modified")
	}
}

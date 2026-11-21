package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifiedRestoredFileChecksHashAndPath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.nix"), []byte("x"), 0o600)
	if _, err := verifiedRestoredFile(dir, "a.nix", sha256hex([]byte("x"))); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedRestoredFile(dir, "a.nix", sha256hex([]byte("y"))); err == nil {
		t.Fatal("accepted a file whose hash changed")
	}
	if _, err := verifiedRestoredFile(dir, "../a.nix", sha256hex([]byte("x"))); err == nil {
		t.Fatal("accepted a traversing path")
	}
}

func TestFindOnePicksNewestMarker(t *testing.T) {
	root := t.TempDir()
	for _, g := range []string{"100", "200"} {
		d := filepath.Join(root, "var/lib/nixus/project-backups/config", g)
		os.MkdirAll(d, 0o700)
		os.WriteFile(filepath.Join(d, "MANIFEST.json"), []byte("{}"), 0o600)
	}
	if got := findOne(root, "/config/", "MANIFEST.json"); !strings.HasSuffix(got, "/200") {
		t.Fatalf("got %s", got)
	}
	if findOne(root, "/generations/", "inventory.json") != "" {
		t.Fatal("found a marker that does not exist")
	}
}

func TestRestoreWorkspaceRefusesExistingWorkspace(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "projects")
	os.Mkdir(existing, 0o700)
	tx := &ProjectTransactions{workspace: existing}
	if _, err := restoreWorkspace(tx, dir, M{}); err == nil || !strings.Contains(publicError(err), "already exists") {
		t.Fatalf("restored over an existing workspace: %v", err)
	}
}

func TestRestoreIncusRefusesCollisionsBeforeChanging(t *testing.T) {
	generation := t.TempDir()
	data := []byte("archive")
	name := "instance-" + strings.Repeat("a", 64) + ".tar.gz"
	os.WriteFile(filepath.Join(generation, name), data, 0o600)
	writeJSON(filepath.Join(generation, "inventory.json"), M{
		"archiveSHA256": M{name: sha256hex(data)},
		"projects":      []any{M{"name": "web", "config": M{}}},
		"guests":        []any{M{"name": "app", "project": "web", "archive": name, "status": "Running"}},
	})
	var mutations []string
	fake := func(_ time.Duration, args ...string) (string, error) {
		switch {
		case args[0] == "storage" && args[1] == "list":
			return `[{"name":"default"}]`, nil
		case args[0] == "query" && strings.HasPrefix(args[1], "/1.0/instances/app"):
			return `{"name":"app"}`, nil
		case args[0] == "query":
			return "", Public("not found")
		}
		mutations = append(mutations, strings.Join(args, " "))
		return "", nil
	}
	if _, err := restoreIncus(fake, generation); err == nil || !strings.Contains(publicError(err), "already exists") {
		t.Fatalf("restored over an existing instance: %v", err)
	}
	if len(mutations) != 0 {
		t.Fatalf("changed Incus before refusing: %v", mutations)
	}
	os.WriteFile(filepath.Join(generation, name), []byte("tampered"), 0o600)
	if _, err := restoreIncus(fake, generation); err == nil || !strings.Contains(publicError(err), "damaged") {
		t.Fatalf("accepted a damaged archive: %v", err)
	}
}

func TestRestoreNetworksRecreatesMissingManagedBridges(t *testing.T) {
	inventory := M{
		"projects": []any{M{"name": "testapp", "config": M{"features.images": "true"}}},
		"networks": M{"testapp": []any{
			M{"name": "incusbr0", "type": "bridge", "managed": true, "config": M{}},
			M{"name": "ic-abc", "type": "bridge", "managed": true, "config": M{"ipv4.address": "10.1.2.1/24", "volatile.bridge.hwaddr": "x"}},
			M{"name": "eth0", "type": "physical", "managed": false, "config": M{}},
		}},
	}
	var calls []string
	fake := func(_ time.Duration, args ...string) (string, error) {
		if args[0] == "query" {
			if strings.Contains(args[1], "/networks/incusbr0") {
				return `{"name":"incusbr0"}`, nil
			}
			return "", Public("not found")
		}
		calls = append(calls, strings.Join(args, " "))
		return "", nil
	}
	created, err := restoreNetworks(fake, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 || created[0] != "default/ic-abc" {
		t.Fatalf("created %v", created)
	}
	if len(calls) != 1 || calls[0] != "network create ic-abc --type bridge --project default ipv4.address=10.1.2.1/24" {
		t.Fatalf("calls %v", calls)
	}
}

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

// A restore that fails after importing one guest resumes from the journal: the
// imported guest is kept, not re-imported or reported as a collision, while an
// unrelated instance with the same name is still refused (#111).
func TestRestoreResumesAfterAFailedImport(t *testing.T) {
	state := useState(t)
	generation := t.TempDir()
	archive := func(letter string) string {
		name := "instance-" + strings.Repeat(letter, 64) + ".tar.gz"
		os.WriteFile(filepath.Join(generation, name), []byte("archive-"+letter), 0o600)
		return name
	}
	one, two := archive("a"), archive("b")
	writeJSON(filepath.Join(generation, "inventory.json"), M{
		"archiveSHA256": M{one: sha256hex([]byte("archive-a")), two: sha256hex([]byte("archive-b"))},
		"projects":      []any{M{"name": "web", "config": M{}}},
		"guests": []any{
			M{"name": "one", "project": "web", "archive": one, "status": "Stopped"},
			M{"name": "two", "project": "web", "archive": two, "status": "Stopped"},
		},
	})
	existing := map[string]bool{}
	imports := map[string]int{}
	failSecond := true
	fake := func(_ time.Duration, args ...string) (string, error) {
		switch {
		case args[0] == "storage" && args[1] == "list":
			return `[{"name":"default"}]`, nil
		case args[0] == "query" && strings.HasPrefix(args[1], "/1.0/instances/"):
			name := strings.TrimPrefix(strings.SplitN(args[1], "?", 2)[0], "/1.0/instances/")
			if existing[name] {
				return `{"name":"` + name + `"}`, nil
			}
			return "", Public("not found")
		case args[0] == "query":
			return "", Public("not found")
		case args[0] == "import":
			name := args[2]
			if name == "two" && failSecond {
				return "", Hidden("disk full")
			}
			imports[name]++
			existing[name] = true
		}
		return "", nil
	}
	run1 := func(j *restoreJournal) error {
		inventory, err := restoreIncusPreflight(fake, generation, j)
		if err != nil {
			return err
		}
		_, err = restoreIncusApply(fake, generation, inventory, j)
		return err
	}
	identity := "snapshot-content-hash"
	if err := run1(openRestoreJournal(identity)); err == nil {
		t.Fatal("the first attempt should fail on the second import")
	}
	if !existing["one"] || existing["two"] {
		t.Fatalf("after the failure: %v", existing)
	}
	// Retry the same snapshot: resumes, does not collide on "one" and does not import it twice.
	failSecond = false
	if err := run1(openRestoreJournal(identity)); err != nil {
		t.Fatalf("resume failed: %v", err)
	}
	if imports["one"] != 1 || imports["two"] != 1 {
		t.Fatalf("imports: %v", imports)
	}
	// A different snapshot gets no credit for what exists: the collision is refused.
	if _, err := restoreIncusPreflight(fake, generation, openRestoreJournal("another-snapshot")); err == nil ||
		!strings.Contains(publicError(err), "already exists") {
		t.Fatalf("an unrelated collision must still be refused: %v", err)
	}
	if !isFile(filepath.Join(state, "project-restore-journal.json")) {
		t.Fatal("the journal must persist between attempts")
	}
}

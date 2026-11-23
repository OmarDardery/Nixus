package main

import (
	"strings"
	"testing"
	"time"
)

func TestDeleteAppNeedsTheNameTyped(t *testing.T) {
	useState(t)
	if _, err := deleteApp("admin", M{"project": "web", "confirm": "wbe"}); err == nil || !strings.Contains(publicError(err), "Type the app's name") {
		t.Fatalf("%v", err)
	}
	if _, err := deleteApp("admin", M{"project": "../x", "confirm": "../x"}); err == nil {
		t.Fatal("invalid names are refused")
	}
}

func TestWholeAppRemovalIsAValidPatch(t *testing.T) {
	if _, err := projectPatches(M{"web/": nil}); err != nil {
		t.Fatal(err)
	}
	if _, err := projectPatches(M{"web/default.nix": nil}); err == nil {
		t.Fatal("removing only the entrypoint stays refused")
	}
	if _, err := projectPatches(M{"Bad/": nil}); err == nil {
		t.Fatal("an invalid app name is refused")
	}
}

// Only Incus projects Nixus owns for this app are deleted.
func TestAppIncusProjectsOnlyOwned(t *testing.T) {
	projects := map[string]string{
		"web":     `{"config":{"user.nixus.owner":"true","user.nixus.backend":"incus-compose"}}`,
		"printer": `{"config":{"user.nixus.owner":"true","user.nixus.backend":"incus-native","user.nixus.project":"printer"}}`,
		"other":   `{"config":{"user.nixus.owner":"true","user.nixus.backend":"incus-native","user.nixus.project":"someone-else"}}`,
		"manual":  `{"config":{}}`,
	}
	old := updateIncus
	defer func() { updateIncus = old }()
	updateIncus = func(_ time.Duration, args ...string) (string, error) {
		if len(args) == 2 && args[0] == "query" {
			if body, ok := projects[strings.TrimPrefix(args[1], "/1.0/projects/")]; ok {
				return body, nil
			}
		}
		return "", Public("not found")
	}
	if got := appIncusProjects("web", nil); len(got) != 1 || got[0] != "web" {
		t.Fatalf("compose app: %v", got)
	}
	if got := appIncusProjects("printer", M{"incusProject": "printer"}); len(got) != 1 || got[0] != "printer" {
		t.Fatalf("native app: %v", got)
	}
	if got := appIncusProjects("mine", M{"incusProject": "other"}); len(got) != 0 {
		t.Fatalf("another app's project: %v", got)
	}
	if got := appIncusProjects("manual", nil); len(got) != 0 {
		t.Fatalf("a project Nixus does not own: %v", got)
	}
	if got := appIncusProjects("default", M{"incusProject": "default"}); len(got) != 0 {
		t.Fatalf("never the default project: %v", got)
	}
}

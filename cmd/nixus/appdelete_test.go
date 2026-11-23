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
		var items []any
		for name, raw := range projects {
			item, _ := parseObject([]byte(raw))
			item["name"] = name
			items = append(items, item)
		}
		return canonical(items), nil
	}
	if got, err := appIncusProjects("web", nil); err != nil || len(got) != 1 || got[0] != "web" {
		t.Fatalf("compose app: %v", got)
	}
	if got, err := appIncusProjects("printer", M{"incusProject": "printer"}); err != nil || len(got) != 1 || got[0] != "printer" {
		t.Fatalf("native app: %v", got)
	}
	if got, err := appIncusProjects("mine", M{"incusProject": "other"}); err != nil || len(got) != 0 {
		t.Fatalf("another app's project: %v", got)
	}
	if got, err := appIncusProjects("manual", nil); err != nil || len(got) != 0 {
		t.Fatalf("a project Nixus does not own: %v", got)
	}
	if got, err := appIncusProjects("default", M{"incusProject": "default"}); err != nil || len(got) != 0 {
		t.Fatalf("never the default project: %v", got)
	}
}

// The CLI's `project delete --force` prompts on stdin; the API does not.
func TestDeleteIncusProjectUsesTheAPI(t *testing.T) {
	var calls []string
	fp := strings.Repeat("ab", 32)
	old := updateIncus
	defer func() { updateIncus = old }()
	updateIncus = func(_ time.Duration, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if strings.Join(args, " ") == "query /1.0/networks/"+appNetworkName("web") {
			return `{"name":"x"}`, nil
		}
		if strings.Join(args, " ") == "query /1.0/certificates?recursion=1" {
			return `[{"name":"ic-dns-web","fingerprint":"` + fp + `"},{"name":"admin","fingerprint":"` + strings.Repeat("cd", 32) + `"}]`, nil
		}
		return "", nil
	}
	if err := deleteIncusProject("web"); err != nil {
		t.Fatal(err)
	}
	want := []string{"query -X DELETE /1.0/projects/web?force=true", "query /1.0/networks/" + appNetworkName("web"),
		"query -X DELETE /1.0/networks/" + appNetworkName("web"), "query /1.0/certificates?recursion=1", "query -X DELETE /1.0/certificates/" + fp}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("%v", calls)
	}
}

func TestAppDeletionRequiresVerifiedIncusInventory(t *testing.T) {
	old := updateIncus
	defer func() { updateIncus = old }()
	for _, response := range []string{"", "null", "{}", `[{}]`} {
		updateIncus = func(time.Duration, ...string) (string, error) { return response, nil }
		if _, err := appIncusProjects("web", nil); err == nil || !strings.Contains(publicError(err), "no app files were removed") {
			t.Fatalf("accepted %q: %v", response, err)
		}
	}
	updateIncus = func(time.Duration, ...string) (string, error) { return "", Public("offline") }
	if _, err := appIncusProjects("web", nil); err == nil {
		t.Fatal("unavailable inventory accepted")
	}
	updateIncus = func(time.Duration, ...string) (string, error) { return "[]", nil }
	if got, err := appIncusProjects("web", nil); err != nil || len(got) != 0 {
		t.Fatalf("verified empty inventory: %v %v", got, err)
	}
}

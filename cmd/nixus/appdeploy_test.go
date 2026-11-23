package main

import (
	"strings"
	"testing"
)

func TestStartAppDeployValidatesRequests(t *testing.T) {
	useState(t)
	cases := []struct {
		body M
		want string
	}{
		{M{"project": "Bad Name", "kind": "nix", "declaration": "x"}, "lowercase"},
		{M{"project": "web", "kind": "source"}, "Upload or paste"},
		{M{"project": "web", "kind": "source", "stagingId": "../x", "manifestHash": strings.Repeat("a", 64)}, "Upload or paste"},
		{M{"project": "web", "kind": "nix", "declaration": "  "}, "Nix declaration"},
		{M{"project": "web", "kind": "other"}, "Choose files"},
		{M{"project": "web", "kind": "nix", "declaration": strings.Repeat("x", 70000)}, "too large"},
	}
	for _, c := range cases {
		if _, err := startAppDeploy("admin", c.body); err == nil || !strings.Contains(publicError(err), c.want) {
			t.Fatalf("%v: got %v, want %q", c.body, err, c.want)
		}
	}
}

func TestAppJobsHideDeclarationsAndTrackActivity(t *testing.T) {
	useState(t)
	old := appWorkerActive
	appWorkerActive = func(string) bool { return true }
	defer func() { appWorkerActive = old }()
	writeJSON(appJobPath("web"), M{"project": "web", "status": "building", "declaration": "{ }"})
	writeJSON(appJobPath("db"), M{"project": "db", "status": "deployed"})
	jobs := appJobs()
	if obj(jobs["web"])["declaration"] != nil || str(obj(jobs["db"])["status"]) != "deployed" {
		t.Fatalf("jobs %v", jobs)
	}
	if !appJobActive("web") || appJobActive("db") || appJobActive("none") {
		t.Fatal("activity tracking is wrong")
	}
	if _, err := startAppDeploy("admin", M{"project": "web", "kind": "nix", "declaration": "{ }"}); err == nil ||
		!strings.Contains(publicError(err), "already running") {
		t.Fatalf("started a second deployment: %v", err)
	}
}

// A saved job whose worker is gone must not block redeployment (#115), while a
// live worker still does.
func TestInterruptedAppJobDoesNotBlockRedeploy(t *testing.T) {
	useState(t)
	old := appWorkerActive
	defer func() { appWorkerActive = old }()
	writeJSON(appJobPath("web"), M{"project": "web", "status": "deploying", "startedAt": now() - 3600, "updatedAt": now() - 3600})
	appWorkerActive = func(string) bool { return true }
	if !appJobActive("web") {
		t.Fatal("a running worker must still block a second deployment")
	}
	appWorkerActive = func(string) bool { return false }
	if appJobActive("web") {
		t.Fatal("a job without a worker still blocks")
	}
	job := readObj(appJobPath("web"))
	if str(job["status"]) != "interrupted" || !strings.Contains(str(job["error"]), "Deploy again") {
		t.Fatalf("job after reconcile: %v", job)
	}
	// A job that was only just written has not started its worker yet.
	writeJSON(appJobPath("fresh"), M{"project": "fresh", "status": "queued", "startedAt": now(), "updatedAt": now()})
	if !appJobActive("fresh") {
		t.Fatal("a brand-new job must count as active")
	}
}

func TestLANModule(t *testing.T) {
	names, err := lanSetting([]any{"web", "aiostreams", "web"})
	if err != nil || strings.Join(names, ",") != "aiostreams,web" {
		t.Fatalf("%v %v", names, err)
	}
	if _, err := lanSetting([]any{"Bad Name"}); err == nil {
		t.Fatal("invalid service names are refused")
	}
	text := lanModuleText(names)
	if !strings.Contains(text, `nixus.project.network.lan.services = [ "aiostreams" "web" ];`) {
		t.Fatal(text)
	}
	if _, err := projectPatches(M{"app/modules/" + lanModule: text}); err != nil {
		t.Fatalf("the module is a valid project edit: %v", err)
	}
}

// The inventory carries the network setting; older inventories without it,
// and without "updates", stay valid.
func TestProjectNetworkValidation(t *testing.T) {
	if err := validateProjectNetwork(M{"lan": M{"services": []any{}}}); err != nil {
		t.Fatal("the default (private) is valid:", err)
	}
	if err := validateProjectNetwork(nil); err != nil {
		t.Fatal(err)
	}
	if err := validateProjectNetwork(M{"lan": M{"services": []any{"aiostreams"}}}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []any{M{"lan": M{"services": []any{"Bad Name"}}}, M{"lan": M{"services": []any{}}, "extra": true}, M{}} {
		if validateProjectNetwork(bad) == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}

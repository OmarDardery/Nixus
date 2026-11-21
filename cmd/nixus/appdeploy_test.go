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

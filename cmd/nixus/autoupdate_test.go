package main

import (
	"strings"
	"testing"
	"time"
)

func TestValidateUpdatePolicy(t *testing.T) {
	good := M{"policy": "auto", "window": "02:00-05:00", "healthSeconds": float64(60)}
	if err := validateUpdatePolicy(good); err != nil {
		t.Fatal(err)
	}
	if err := validateUpdatePolicy(nil); err != nil {
		t.Fatal("absent policy must default to manual")
	}
	for _, bad := range []M{
		{"policy": "always", "window": nil, "healthSeconds": float64(60)},
		{"policy": "auto", "window": "25:00-05:00", "healthSeconds": float64(60)},
		{"policy": "auto", "window": nil, "healthSeconds": float64(1)},
		{"policy": "auto", "window": nil},
		{"policy": "auto", "window": nil, "healthSeconds": float64(60), "extra": true},
	} {
		if validateUpdatePolicy(bad) == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	if str(projectUpdatePolicy(M{})["policy"]) != "manual" {
		t.Fatal("default policy is not manual")
	}
}

func TestInWindowWrapsMidnight(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 1, 1, h, m, 0, 0, time.Local) }
	cases := []struct {
		window string
		h, m   int
		want   bool
	}{
		{"", 12, 0, true},
		{"02:00-05:00", 3, 0, true},
		{"02:00-05:00", 5, 0, false},
		{"02:00-05:00", 1, 59, false},
		{"23:00-01:00", 23, 30, true},
		{"23:00-01:00", 0, 30, true},
		{"23:00-01:00", 1, 0, false},
		{"garbage", 3, 0, false},
	}
	for _, c := range cases {
		if got := inWindow(c.window, at(c.h, c.m)); got != c.want {
			t.Fatalf("inWindow(%q, %02d:%02d) = %v", c.window, c.h, c.m, got)
		}
	}
}

func TestRegistrySchemeOnlyLoopbackIsPlainHTTP(t *testing.T) {
	for registry, want := range map[string]string{
		"localhost:5000": "http", "127.0.0.1:5000": "http", "docker.io": "https",
		"ghcr.io": "https", "localhost.example.com:5000": "https", "10.0.0.5:5000": "https",
	} {
		if got := registrySchemeFor(registry); got != want {
			t.Fatalf("%s: got %s", registry, got)
		}
	}
}

func TestHoldsAreValidatedAndRecorded(t *testing.T) {
	useState(t)
	if _, err := setHold("admin", "alpha", "latest", true, "x"); err == nil {
		t.Fatal("accepted a tag instead of a digest")
	}
	if _, err := setHold("admin", "../x", digestA, true, "x"); err == nil {
		t.Fatal("accepted an invalid project")
	}
	if _, err := setHold("admin", "alpha", digestA, true, "broken"); err != nil {
		t.Fatal(err)
	}
	if !heldDigests("alpha")[digestA] || heldDigests("beta")[digestA] {
		t.Fatal("hold not scoped to its project")
	}
	if _, err := setHold("admin", "alpha", digestA, false, ""); err != nil || heldDigests("alpha")[digestA] {
		t.Fatal("unhold failed")
	}
}

func TestStartImageUpdateRefusesWithoutAvailableUpdate(t *testing.T) {
	useState(t)
	if _, err := startImageUpdate("admin", "alpha"); err == nil || !strings.Contains(publicError(err), "No unheld image update") {
		t.Fatalf("started without an available update: %v", err)
	}
	if _, err := startImageUpdate("admin", "../x"); err == nil {
		t.Fatal("accepted an invalid project")
	}
}

func TestPlainNamedVolumeAcceptsOnlyComposeDefaults(t *testing.T) {
	ok := []any{nil, M{}, M{"name": "web_data"}, M{"name": "web_data", "external": false}}
	for _, props := range ok {
		if !plainNamedVolume("web", "data", props) {
			t.Fatalf("rejected default volume %v", props)
		}
	}
	bad := []any{M{"name": "other"}, M{"external": true}, M{"driver": "local"}, M{"driver_opts": M{"type": "nfs"}}, "x"}
	for _, props := range bad {
		if plainNamedVolume("web", "data", props) {
			t.Fatalf("accepted unsafe volume %v", props)
		}
	}
}

func TestStartAllImageUpdatesNeedsAnUpdate(t *testing.T) {
	useState(t)
	if _, err := startAllImageUpdates("admin"); err == nil || !strings.Contains(publicError(err), "up to date") {
		t.Fatalf("started with nothing to update: %v", err)
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
)

func TestParseImageRef(t *testing.T) {
	cases := map[string]imageRef{
		"nginx:1.27@" + digestA:              {"docker.io", "library/nginx", "1.27", digestA},
		"ghcr.io/org/app:v2":                 {"ghcr.io", "org/app", "v2", ""},
		"localhost:5000/team/svc@" + digestB: {"localhost:5000", "team/svc", "", digestB},
		"redis":                              {"docker.io", "library/redis", "", ""},
	}
	for ref, want := range cases {
		got, ok := parseImageRef(ref)
		if !ok || got != want {
			t.Errorf("%s: %+v %v", ref, got, ok)
		}
	}
	for _, bad := range []string{"", "nginx:$TAG", "Nginx", "nginx@sha256:short", "a b"} {
		if _, ok := parseImageRef(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestDockerfileBasesSkipsScratchAndStages(t *testing.T) {
	text := "FROM --platform=linux/amd64 golang:1.26@" + digestA + " AS build\nRUN go build\nFROM scratch\nFROM build\nfrom debian:13\n"
	got := dockerfileBases(text)
	if strings.Join(got, ",") != "golang:1.26@"+digestA+",debian:13" {
		t.Fatalf("bases: %v", got)
	}
}

func TestImageLockAndUnpinnedBase(t *testing.T) {
	folder := t.TempDir()
	writeFile(t, filepath.Join(folder, "source", "Dockerfile"), "FROM debian:13\n")
	writeFile(t, filepath.Join(folder, "source", "compose.yaml"),
		"services:\n  db:\n    image: postgres:17@"+digestA+"\n  web:\n    build: .\n    image: ignored\n")
	files := []sourceEntry{{Path: "Dockerfile", Size: 15}, {Path: "compose.yaml", Size: 100}}
	lock := imageLock(folder, files)
	if len(lock) != 2 || !unpinnedBases(lock) {
		t.Fatalf("lock: %v", lock)
	}
	db := obj(lock[1])
	if db["service"] != "db" || db["tag"] != "17" || db["digest"] != digestA || db["pinned"] != true {
		t.Fatalf("compose entry: %v", db)
	}
}

func TestRegistryDigestFollowsAnonymousTokenChallenge(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if r.URL.Query().Get("scope") != "repository:library/nginx:pull" {
				t.Errorf("scope %q", r.URL.RawQuery)
			}
			w.Write([]byte(`{"token":"anon"}`))
		case r.Header.Get("Authorization") != "Bearer anon":
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+server.URL+`/token",service="registry",scope="repository:library/nginx:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == "HEAD" && r.URL.Path == "/v2/library/nginx/manifests/1.27":
			w.Header().Set("Docker-Content-Digest", digestB)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	oldScheme, oldClient := registryScheme, registryClient
	registryScheme, registryClient = "http", server.Client()
	defer func() { registryScheme, registryClient = oldScheme, oldClient }()
	host := strings.TrimPrefix(server.URL, "http://")
	got, err := registryDigest(imageRef{Registry: host, Repository: "library/nginx", Tag: "1.27"})
	if err != nil || got != digestB {
		t.Fatalf("digest: %q %v", got, err)
	}
	if _, err := registryDigest(imageRef{Registry: host, Repository: "library/nginx", Tag: "missing"}); err == nil {
		t.Fatal("missing tag returned a digest")
	}
}

func TestReplaceDigestsOnlyTouchesMatchingImage(t *testing.T) {
	text := "services:\n  db:\n    image: postgres:17@" + digestA + "\n  cache:\n    image: redis:7@" + digestA + "\n"
	out, n := replaceDigests(text, []M{{"repository": "library/postgres", "digest": digestA, "latest": digestB}})
	if n != 1 || !strings.Contains(out, "postgres:17@"+digestB) || !strings.Contains(out, "redis:7@"+digestA) {
		t.Fatalf("replace: %d\n%s", n, out)
	}
}

func TestPrepareImageUpdateRequiresFreshCheck(t *testing.T) {
	useState(t)
	os.Setenv("NIXUS_PROJECT_SOURCES", filepath.Join(t.TempDir(), "none"))
	defer os.Unsetenv("NIXUS_PROJECT_SOURCES")
	if _, err := prepareImageUpdate("admin", "alpha"); err == nil {
		t.Fatal("prepared an update without published source")
	}
	if _, err := prepareImageUpdate("admin", "../x"); err == nil {
		t.Fatal("accepted an invalid project")
	}
}

func TestPinTextPinsOnlyUnpinnedExternalImages(t *testing.T) {
	resolve := func(r imageRef) (string, error) {
		if r.Tag == "" {
			t.Fatal("untagged reference not defaulted to latest")
		}
		return digestB, nil
	}
	docker := "FROM node:20 AS build\nRUN make\nFROM build AS test\nFROM scratch\nFROM ghcr.io/o/app@" + digestA + "\nFROM debian\n"
	got, changes, err := pinText("Dockerfile", docker, resolve)
	if err != nil {
		t.Fatal(err)
	}
	want := "FROM node:20@" + digestB + " AS build\nRUN make\nFROM build AS test\nFROM scratch\nFROM ghcr.io/o/app@" + digestA + "\nFROM debian:latest@" + digestB + "\n"
	if got != want || len(changes) != 2 {
		t.Fatalf("got\n%s\nchanges %v", got, changes)
	}
	compose := "services:\n  db:\n    image: \"postgres:16\" # main db\n  web:\n    build: .\n"
	got, changes, err = pinText("compose.yaml", compose, resolve)
	if err != nil || got != "services:\n  db:\n    image: \"postgres:16@"+digestB+"\" # main db\n  web:\n    build: .\n" || len(changes) != 1 {
		t.Fatalf("got\n%s %v %v", got, changes, err)
	}
	if out, c, _ := pinText("README.md", "FROM x\n", resolve); out != "FROM x\n" || len(c) != 0 {
		t.Fatal("rewrote a non-source file")
	}
}

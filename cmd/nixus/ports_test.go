package main

import (
	"strings"
	"testing"
	"time"
)

func TestComposeHostPorts(t *testing.T) {
	services := []any{
		M{"ports": []any{M{"published": "3000", "target": 3000.0, "protocol": "tcp"}, M{"published": "53", "protocol": "udp"}}},
		M{"ports": []any{"8080:80", "127.0.0.1:9000:9000", "3000:3000"}},
		M{},
	}
	got := composeHostPorts(services)
	if len(got) != 3 || got[0] != 3000 || got[1] != 8080 || got[2] != 9000 {
		t.Fatalf("%v", got)
	}
}

func TestPortConflictsNameTheApp(t *testing.T) {
	old := hostListening
	defer func() { hostListening = old }()
	hostListening = func() map[int]bool { return map[int]bool{3000: true, 22: true, 8080: true} }
	incus := func(_ time.Duration, args ...string) (string, error) {
		return `[{"name":"aiostreams-1","project":"aiostreamss","expanded_devices":{"p":{"type":"proxy","listen":"tcp:0.0.0.0:3000","connect":"tcp:127.0.0.1:3000"}}},
		        {"name":"web-1","project":"mine","expanded_devices":{"p":{"type":"proxy","listen":"tcp:0.0.0.0:8080"}}}]`, nil
	}
	if msg := portConflicts(incus, "aiostreams", []int{3000}); !strings.Contains(msg, "Port 3000 is already published by app aiostreamss") {
		t.Fatalf("%q", msg)
	}
	if msg := portConflicts(incus, "aiostreams", []int{22}); !strings.Contains(msg, "a program on this server") {
		t.Fatalf("%q", msg)
	}
	if msg := portConflicts(incus, "mine", []int{8080}); msg != "" {
		t.Fatalf("the app's own port is not a conflict: %q", msg)
	}
	if msg := portConflicts(incus, "aiostreams", []int{4000}); msg != "" {
		t.Fatalf("%q", msg)
	}
	stderr := `ERR Starting resources error="Failed to listen on 0.0.0.0:3000: listen tcp 0.0.0.0:3000: bind: address already in use"`
	if msg := explainBindError(incus, "aiostreams", stderr); !strings.Contains(msg, "app aiostreamss") {
		t.Fatalf("%q", msg)
	}
}

func TestComposeDNSSidecarSettings(t *testing.T) {
	args, env, err := composeUpCommand("incus-compose", []string{"-p", "x"}, M{"services": []any{}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_ = args
	if !strings.Contains(strings.Join(env, " "), "INCUS_COMPOSE_DNS_IMAGE="+defaultDNSImage) || !strings.Contains(defaultDNSImage, "@sha256:") {
		t.Fatalf("the DNS sidecar image is pinned: %v", env)
	}
	if !isDNSSidecar("web", "web-ic-dns") || isDNSSidecar("web", "web-1") {
		t.Fatal("sidecar detection")
	}
}

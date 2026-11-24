package main

import (
	"strings"
	"testing"
	"time"
)

func TestComposeHostPorts(t *testing.T) {
	services := []any{
		M{"ports": []any{M{"published": "3000", "target": 3000.0, "protocol": "tcp"}, M{"published": "53", "protocol": "udp"}}},
		M{"ports": []any{"8080:80", "127.0.0.1:9000:9000", "3000:3000", "7000-7001:7000-7001/udp"}},
		M{},
	}
	got := composeHostPorts(services)
	want := []hostPort{
		{Port: 3000, Protocol: "tcp"},
		{Port: 53, Protocol: "udp"},
		{Port: 8080, Protocol: "tcp"},
		{HostIP: "127.0.0.1", Port: 9000, Protocol: "tcp"},
		{Port: 7000, Protocol: "udp"},
		{Port: 7001, Protocol: "udp"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestPortConflictsNameTheApp(t *testing.T) {
	old := hostListening
	defer func() { hostListening = old }()
	hostListening = func() map[hostSocket]bool {
		return map[hostSocket]bool{
			{Protocol: "tcp", Port: 3000}: true,
			{Protocol: "tcp", Port: 22}:   true,
			{Protocol: "tcp", Port: 8080}: true,
			{Protocol: "udp", Port: 53}:   true,
		}
	}
	incus := func(_ time.Duration, args ...string) (string, error) {
		return `[{"name":"aiostreams-1","project":"aiostreamss","expanded_devices":{"p":{"type":"proxy","listen":"tcp:0.0.0.0:3000","connect":"tcp:127.0.0.1:3000"}}},
		        {"name":"web-1","project":"mine","expanded_devices":{"p":{"type":"proxy","listen":"tcp:0.0.0.0:8080"}}}]`, nil
	}
	if msg := portConflicts(incus, "aiostreams", []hostPort{{Port: 3000, Protocol: "tcp"}}); !strings.Contains(msg, "Port 3000/tcp is already published by app aiostreamss") {
		t.Fatalf("%q", msg)
	}
	if msg := portConflicts(incus, "aiostreams", []hostPort{{Port: 22, Protocol: "tcp"}}); !strings.Contains(msg, "a program on this server") {
		t.Fatalf("%q", msg)
	}
	if msg := portConflicts(incus, "aiostreams", []hostPort{{Port: 53, Protocol: "udp"}}); !strings.Contains(msg, "53/udp") {
		t.Fatalf("UDP conflict should be detected: %q", msg)
	}
	if msg := portConflicts(incus, "mine", []hostPort{{Port: 8080, Protocol: "tcp"}}); msg != "" {
		t.Fatalf("the app's own port is not a conflict: %q", msg)
	}
	if msg := portConflicts(incus, "aiostreams", []hostPort{{Port: 4000, Protocol: "tcp"}}); msg != "" {
		t.Fatalf("%q", msg)
	}
	stderr := `ERR Starting resources error="Failed to listen on 0.0.0.0:3000: listen tcp 0.0.0.0:3000: bind: address already in use"`
	if msg := explainBindError(incus, "aiostreams", stderr); !strings.Contains(msg, "app aiostreamss") {
		t.Fatalf("%q", msg)
	}
}

func TestComposeSidecarSettings(t *testing.T) {
	t.Setenv("NIXUS_OCI_VM_TEST", "")
	t.Setenv("NIXUS_COMPOSE_OFFLINE", "")
	args, _, err := composeUpCommand("incus-compose", []string{"-p", "x"}, M{"services": []any{}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--no-dns") || strings.Contains(joined, "--no-healthd") {
		t.Fatalf("ic-dns and ic-healthd should be enabled by default: %v", args)
	}
	t.Setenv("NIXUS_COMPOSE_OFFLINE", "1")
	offlineArgs, _, err := composeUpCommand("incus-compose", []string{"-p", "x"}, M{"services": []any{}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(offlineArgs, " "), "--no-dns") || !strings.Contains(strings.Join(offlineArgs, " "), "--no-healthd") {
		t.Fatalf("offline mode should disable sidecars: %v", offlineArgs)
	}
	if !isComposeSidecar("web", "web-ic-dns") || !isComposeSidecar("web", "web-ic-healthd") || isComposeSidecar("web", "web-1") {
		t.Fatal("sidecar detection")
	}
}

package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	syncatomic "sync/atomic"
	"testing"
	"time"
)

func TestIncusRequestsReuseConnections(t *testing.T) {
	var connections syncatomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"type":"sync","metadata":{}}`))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	previous := incusTransport
	incusTransport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	defer func() { incusTransport.CloseIdleConnections(); incusTransport = previous }()
	for range 3 {
		if _, _, _, err := incusAPI("GET", "/1.0", nil, "", time.Second, 0); err != nil {
			t.Fatal(err)
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("opened %d connections for repeated Incus requests", connections.Load())
	}
}

func TestSettingsCacheKeyedOnInputs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "machine/settings.json"), `{"hostName": "a"}`)
	key := settingsFingerprint(root)
	settingsCache.Lock()
	settingsCache.entries[root] = settingsEntry{key, M{"hostName": "cached"}}
	settingsCache.Unlock()
	got, err := readSettings(root)
	if err != nil || got["hostName"] != "cached" {
		t.Fatalf("cache miss: %v %v", got, err)
	}
	got["hostName"] = "mutated"
	if again, _ := readSettings(root); again["hostName"] != "cached" {
		t.Fatal("callers must get a copy")
	}
	later := time.Now().Add(time.Second)
	os.Chtimes(filepath.Join(root, "machine/settings.json"), later, later)
	if settingsFingerprint(root) == key {
		t.Fatal("a settings write must invalidate the cache")
	}
}

func TestHealthIsCached(t *testing.T) {
	healthCache.Lock()
	healthCache.value, healthCache.at = M{"checkedAt": 1}, time.Now()
	healthCache.Unlock()
	if h := health(); str(h["checkedAt"]) != "1" && h["checkedAt"] != float64(1) {
		t.Fatalf("expected cached health, got %v", h["checkedAt"])
	}
	healthCache.Lock()
	healthCache.value = nil
	healthCache.Unlock()
}

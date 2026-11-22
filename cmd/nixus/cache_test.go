package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

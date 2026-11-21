package main

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTar(t *testing.T, path string, entries []tar.Header, bodies []string) {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for i, h := range entries {
		h.Size = int64(len(bodies[i]))
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := w.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(bodies[i]))
	}
	w.Close()
	os.WriteFile(path, buf.Bytes(), 0o600)
}

func TestUnpackTarStaysInsideAndRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar")
	writeTar(t, archive, []tar.Header{{Name: "../../escape.txt", Typeflag: tar.TypeReg}, {Name: "sub/ok.txt", Typeflag: tar.TypeReg}},
		[]string{"x", "y"})
	dest := filepath.Join(dir, "out")
	os.Mkdir(dest, 0o700)
	n, err := unpackTar(archive, dest)
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "escape.txt")); err != nil {
		t.Fatal("traversing entry was not confined to the destination")
	}
	if lexists(filepath.Join(dir, "escape.txt")) {
		t.Fatal("archive escaped the destination")
	}
	writeTar(t, archive, []tar.Header{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}}, []string{""})
	dest2 := filepath.Join(dir, "out2")
	os.Mkdir(dest2, 0o700)
	if _, err := unpackTar(archive, dest2); err == nil {
		t.Fatal("accepted a symlink")
	}
}

func TestDataImportValidatesAndChecksums(t *testing.T) {
	useState(t)
	sum := strings.Repeat("a", 64)
	for _, bad := range []M{
		{"project": "web", "instance": "app-1", "path": "/data/../etc", "size": float64(1), "sha256": sum},
		{"project": "web", "instance": "app-1", "path": "data", "size": float64(1), "sha256": sum},
		{"project": "web", "instance": "app-1", "path": "/data", "size": float64(5 << 30), "sha256": sum},
	} {
		if _, err := startDataImport("admin", bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	started, err := startDataImport("admin", M{"project": "web", "instance": "app-1", "path": "/data", "size": float64(3), "sha256": sum})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chunkDataImport(M{"id": started["id"], "offset": float64(1), "data": base64.StdEncoding.EncodeToString([]byte("x"))}); err == nil {
		t.Fatal("accepted an out-of-order chunk")
	}
	if _, err := chunkDataImport(M{"id": started["id"], "offset": float64(0), "data": base64.StdEncoding.EncodeToString([]byte("abc"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := finishDataImport("admin", M{"id": started["id"]}); err == nil || !strings.Contains(publicError(err), "checksum") {
		t.Fatalf("finished with a wrong checksum: %v", err)
	}
}

func TestStartRestoreRefusesAServerWithApps(t *testing.T) {
	useState(t)
	ws := filepath.Join(t.TempDir(), "projects")
	os.Mkdir(ws, 0o700)
	old := projectsWorkspace
	projectsWorkspace = ws
	defer func() { projectsWorkspace = old }()
	if _, err := startRestore("admin", M{"kind": "local", "path": "/mnt/b", "password": "x"}); err == nil ||
		!strings.Contains(publicError(err), "fresh install") {
		t.Fatalf("restored over existing apps: %v", err)
	}
}

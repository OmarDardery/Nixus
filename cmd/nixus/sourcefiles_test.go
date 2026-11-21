package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceFilesAcceptHostSecretsOnly(t *testing.T) {
	root := t.TempDir()
	write := func(name, data string) {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(data), 0o644)
	}
	write("machine/format.json", `{"version": 1}`)
	write("machine/settings.json", `{}`)
	write("machine/secrets/host.yaml", "sops: {}\n")
	write(".nixus-files.json", `["machine/format.json"]`)
	files, err := sourceFiles(root)
	if err != nil {
		t.Fatalf("installer-written host secrets rejected: %v", err)
	}
	found := false
	for _, f := range files {
		found = found || f.name == hostSecretsRelative
	}
	if !found {
		t.Fatal("host secrets missing from the managed source")
	}
	write("machine/secrets/other.yaml", "x\n")
	if _, err := sourceFiles(root); err == nil {
		t.Fatal("accepted an unknown file under machine/secrets")
	}
}

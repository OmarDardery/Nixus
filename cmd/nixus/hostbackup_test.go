package main

import (
	"path/filepath"
	"testing"
)

func TestHostBackupFilesAndPortableSettings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "machine/format.json"), `{"version": 1}`)
	writeFile(t, filepath.Join(root, "machine/settings.json"), `{"hostName": "old"}`)
	writeFile(t, filepath.Join(root, "machine/secrets/host.yaml"), "cipher")
	writeFile(t, filepath.Join(root, "machine/modules/net/a.nix"), "{ ... }: { }\n")
	files, err := hostBackupFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"host/settings.json", "host/secrets/host.yaml", "host/modules/net/a.nix"} {
		if files[want] == "" {
			t.Fatalf("missing %s in %v", want, files)
		}
	}
	hashes := M{}
	dest := t.TempDir()
	if n, err := snapshotHost(root, dest, hashes); err != nil || n != 3 || !isFile(filepath.Join(dest, "host/modules/net/a.nix")) {
		t.Fatalf("%d %v %v", n, err, hashes)
	}
	current := M{"hostName": "new", "management": M{"interface": "enp1s0"}, "system": "x86_64-linux"}
	saved := M{"hostName": "old", "management": M{"interface": "eth0"}, "system": "aarch64-linux", "adminKeys": []any{"k"}}
	got := restoredHostSettings(current, saved)
	if got["hostName"] != "old" || str(jget(got, "management", "interface")) != "enp1s0" || got["system"] != "x86_64-linux" || len(list(got["adminKeys"])) != 1 {
		t.Fatalf("%v", got)
	}
}

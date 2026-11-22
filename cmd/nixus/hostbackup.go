package main

// Host configuration in project backups: portable settings, site modules and
// the encrypted host secrets file. Restore stages them as a normal host review
// in Changes; nothing is activated without the operator.

import (
	"os"
	"path/filepath"
	"strings"
)

// portableSettings survive a move to different hardware. Network, disks,
// radios and platform fields stay as installed on the new host.
var portableSettings = []string{"hostName", "adminKeys", "guests", "cockpit", "monitoring", "maintenance"}

// hostBackupFiles maps snapshot paths under host/ to files on this host.
func hostBackupFiles(root string) (map[string]string, error) {
	files := map[string]string{}
	if p := machinePath(root, "settings"); isFile(p) && !isSymlink(p) {
		files["host/settings.json"] = p
	}
	if p := filepath.Join(root, hostSecretsRelative); isFile(p) && !isSymlink(p) {
		files["host/secrets/host.yaml"] = p
	}
	modules, err := moduleFiles(root)
	if err != nil {
		return nil, err
	}
	base := machinePath(root, "modules")
	for _, p := range modules {
		rel, err := filepath.Rel(base, p)
		if err != nil || strings.HasPrefix(rel, "..") {
			return nil, Public("Unexpected module path")
		}
		files["host/modules/"+filepath.ToSlash(rel)] = p
	}
	return files, nil
}

func snapshotHost(root, destination string, hashes M) (int, error) {
	files, err := hostBackupFiles(root)
	if err != nil {
		return 0, err
	}
	for rel, p := range files {
		data, err := os.ReadFile(p)
		if err != nil {
			return 0, err
		}
		if err := atomic(filepath.Join(destination, rel), data, 0o600, ""); err != nil {
			return 0, err
		}
		hashes[rel] = sha256hex(data)
	}
	return len(files), nil
}

// restoredHostSettings overlays the portable fields of a backed-up settings
// file onto this host's current settings.
func restoredHostSettings(current, saved M) M {
	candidate := M{}
	for k, v := range current {
		candidate[k] = v
	}
	for _, k := range portableSettings {
		if v, ok := saved[k]; ok {
			candidate[k] = v
		}
	}
	return candidate
}

// restoreHost stages backed-up host configuration for review. Failures are
// reported, never fatal: apps and data restore regardless.
func restoreHost(config string, files M, keyReport M) M {
	report := M{}
	read := func(rel string) []byte {
		if _, ok := files[rel]; !ok {
			return nil
		}
		data, err := verifiedRestoredFile(config, rel, str(files[rel]))
		if err != nil {
			return nil
		}
		return data
	}
	saved := read("host/settings.json")
	if saved == nil {
		report["settings"] = "not in this backup"
		return report
	}
	// host.yaml is only readable with the identity it was encrypted to.
	if secrets := read("host/secrets/host.yaml"); secrets != nil {
		if k := str(keyReport["hostIdentity"]); k == "restored" || k == "already present" {
			if err := atomic(filepath.Join(ROOT, hostSecretsRelative), secrets, 0o600, ""); err != nil {
				report["hostSecrets"] = publicError(err)
			} else {
				report["hostSecrets"] = "restored"
			}
		} else {
			report["hostSecrets"] = "skipped: this host has a different host key"
		}
	}
	modules := M{}
	for _, rel := range keys(files) {
		if name := strings.TrimPrefix(rel, "host/modules/"); name != rel && strings.HasSuffix(name, ".nix") {
			if data := read(rel); data != nil {
				modules[name] = string(data)
			}
		}
	}
	m := NewManager("", "")
	current, err := m.settings()
	if err != nil {
		report["settings"] = "not staged: " + publicError(err)
		return report
	}
	backedUp, err := parseObject(saved)
	if err != nil {
		report["settings"] = "not staged: unreadable settings in the backup"
		return report
	}
	candidate := restoredHostSettings(current, backedUp)
	if equalJSON(candidate, current) && len(modules) == 0 {
		report["settings"] = "matches this host"
		return report
	}
	review := func(mods M) error {
		_, err := m.review(candidate, ReviewOptions{Principal: "backup-restore", Modules: mods})
		return err
	}
	if err := review(modules); err == nil {
		report["settings"] = "staged in Changes; review and activate"
		report["modules"] = len(modules)
	} else if len(modules) > 0 && review(nil) == nil {
		report["settings"] = "staged in Changes; review and activate"
		report["modules"] = "not staged: " + publicError(err)
	} else {
		report["settings"] = "not staged: " + publicError(err)
	}
	return report
}

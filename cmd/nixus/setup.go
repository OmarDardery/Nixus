package main

// First-run checklist recomputed from root-owned state; no secrets returned.

import (
	"os"
	"path/filepath"
)

const recoveryMarker = "recovery-kit.json"

var setupItems = [][4]string{
	{"activation", "Activate the hypervisor", "Build, activate and confirm the first configuration.", "review"},
	{"incusBrowser", "Enroll this browser for the Incus web UI (optional)", "Only needed to use the Incus UI.", "system"},
	{"secretsKey", "Create the secrets encryption key", "Backups → Encryption key.", "operations"},
	{"recoveryKit", "Save and verify the encrypted recovery kit", "Download it, store it off this server, then verify it.", "operations"},
	{"sshKey", "Enroll an SSH key (optional)", "Your laptop's public key.", "system"},
	{"backup", "Set up backups (optional)", "Backups → Destination.", "operations"},
}

func identityDigest(p string) any {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return sha256hex(raw)
}

func recordRecoveryKit(identity string) bool {
	digest := identityDigest(identity)
	if digest == nil {
		return false
	}
	return writeJSON(filepath.Join(STATE, recoveryMarker), M{"version": 1, "identity": digest, "exportedAt": int(now())}) == nil
}

func browserEnrolled(state string) bool {
	registry, err := browserRegistry(state)
	if err != nil {
		return false
	}
	for _, r := range obj(registry["certificates"]) {
		if str(obj(r)["status"]) == "active" {
			return true
		}
	}
	return false
}

func setupProgress(status M) M {
	settings := obj(status["effectiveSettings"])
	if len(settings) == 0 {
		settings = obj(status["settings"])
	}
	key := identityDigest(projectsIdentity)
	marker := M{}
	if isFile(filepath.Join(STATE, recoveryMarker)) {
		marker = readObj(filepath.Join(STATE, recoveryMarker))
	}
	done := map[string]bool{
		"activation":   isTrue(status["setupComplete"]) && status["lastConfirmed"] != nil,
		"incusBrowser": browserEnrolled(STATE),
		"secretsKey":   key != nil,
		"recoveryKit":  key != nil && equalJSON(marker["identity"], key),
		"sshKey":       len(list(settings["adminKeys"])) > 0,
		"backup":       isTrue(projectBackupStatus()["enabled"]),
	}
	items := []any{}
	completed, total := 0, 0
	for _, it := range setupItems {
		required := it[0] != "sshKey" && it[0] != "backup" && it[0] != "incusBrowser"
		items = append(items, M{"id": it[0], "title": it[1], "detail": it[2], "page": it[3], "required": required, "done": done[it[0]]})
		if required {
			total++
			if done[it[0]] {
				completed++
			}
		}
	}
	return M{"version": 1, "items": items, "completed": completed, "total": total, "complete": completed == total}
}

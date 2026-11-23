package main

// Independent systemd transaction worker (build/apply/rollback) and the
// persistent rollback guard.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// hostCommand runs a host tool with output discarded; only progress is logged.
func hostCommand(argv []string, log *os.File, timeout time.Duration, checkStatus bool) (int, error) {
	if timeout == 0 {
		timeout = 7200 * time.Second
	}
	log.WriteString("\nHost command started\n")
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		log.WriteString("Host command finished with status -1\n")
		if checkStatus {
			return -1, Hidden("Host command failed")
		}
		return -1, nil
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(timeout):
		syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return -1, Hidden("Host command timed out")
	}
	code := cmd.ProcessState.ExitCode()
	log.WriteString(fmt.Sprintf("Host command finished with status %d\n", code))
	if checkStatus && code != 0 {
		return code, Hidden("Host command failed")
	}
	return code, nil
}

func updateJob(directory string, fields M) (M, error) {
	data, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
	if err != nil {
		return nil, err
	}
	for k, v := range fields {
		data[k] = v
	}
	return data, writeJSON(filepath.Join(directory, "job.json"), data)
}

func hostRoleOf(job M) (string, error) {
	role := "hypervisor"
	if v, ok := job["hostRole"]; ok {
		role = str(v)
	}
	if role != "hypervisor" && role != "bootstrap" {
		return "", Public("Unsupported host role; build a new review")
	}
	if role == "bootstrap" && str(job["principal"]) != "root-wizard-install" {
		return "", Public("Bootstrap job has no initial installer authority")
	}
	return role, nil
}

func validateEffectiveTransition(effective, disks, active, previousDisks M, initialized bool) error {
	if active != nil {
		active = mergeSettings(readObj(filepath.Join(SOURCE, "default-settings.json")), active)
	}
	for name, raw := range previousDisks {
		prev := obj(raw)
		cur := obj(disks[name])
		if cur == nil {
			return Public("Migrate active disk before removing/remapping: " + name)
		}
		for _, k := range []string{"uuid", "path", "fsType", "role"} {
			if !equalJSON(cur[k], prev[k]) {
				return Public("Migrate active disk before removing/remapping: " + name)
			}
		}
	}
	if initialized && active != nil {
		if !equalJSON(effective["storage"], active["storage"]) || !equalJSON(effective["guests"], active["guests"]) {
			return Public("Initialized Incus storage/network requires an explicit migration")
		}
		desired := map[string]any{}
		for _, m := range list(effective["mounts"]) {
			desired[str(obj(m)["name"])] = m
		}
		for _, raw := range list(active["mounts"]) {
			mount := obj(raw)
			role := str(mount["role"])
			if (role == "guests" || role == "pool") && !equalJSON(desired[str(mount["name"])], mount) {
				return Public("Migrate initialized Incus mount before removing/remapping: " + str(mount["name"]))
			}
		}
	}
	return nil
}

func nixCmd(args ...string) []string {
	return append([]string{"nix", "--extra-experimental-features", "nix-command flakes"}, args...)
}

func workerBuild(directory string) error {
	source := filepath.Join(directory, "source")
	job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
	if err != nil {
		return err
	}
	role, err := hostRoleOf(job)
	if err != nil {
		return err
	}
	oldInputs := obj(readObj(filepath.Join(source, "flake.lock"))["nodes"])
	log, err := os.OpenFile(filepath.Join(directory, "build.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if rev := str(job["platformRevision"]); rev != "" {
		changes, err := upgradePrepare(source, rev, log)
		if err != nil {
			log.Close()
			return err
		}
		if _, err := updateJob(directory, M{"platformChanges": changes}); err != nil {
			log.Close()
			return err
		}
	}
	if isTrue(job["updateInputs"]) {
		if _, err := hostCommand(nixCmd("flake", "update", "nixpkgs", "--flake", "path:"+source), log, 0, true); err != nil {
			log.Close()
			return err
		}
	}
	target := "path:" + source + "#nixosConfigurations." + role + ".config.system.build.toplevel"
	if _, err := hostCommand(nixCmd("build", target, "--out-link", filepath.Join(directory, "system")), log, 0, true); err != nil {
		log.Close()
		return err
	}
	system, _ := filepath.EvalSymlinks(filepath.Join(directory, "system"))
	if _, err := hostCommand([]string{system + "/bin/switch-to-configuration", "dry-activate"}, log, 0, true); err != nil {
		log.Close()
		return err
	}
	log.Close()
	resources := "disks = c.nixus.storage.disks; preseed = c.virtualisation.incus.preseed; instances = c.nixus.incus.desiredInstances;"
	if role == "bootstrap" {
		resources = "disks = {}; preseed = {}; instances = [];"
	}
	out, err := check(nixCmd("eval", "--json", "path:"+source+"#nixosConfigurations."+role+".config", "--apply",
		"c: { settings = c.nixus.settings; desiredSettings = c.nixus.desiredSettings or null; "+resources+" }"), nil, 120*time.Second)
	if err != nil {
		return err
	}
	projection, err := parseObject(out)
	if err != nil {
		return err
	}
	effective, disks := obj(projection["settings"]), obj(projection["disks"])
	if role == "bootstrap" && isTrue(effective["ready"]) {
		return Public("Bootstrap source marks the host configured; use the full guarded installer")
	}
	secretChanges, _ := anyStrings(job["secretChanges"])
	if _, err := readStagedSecrets(directory, secretChanges); err != nil {
		return err
	}
	validation := cloneM(effective)
	mounts := list(validation["mounts"])
	for _, k := range keys(disks) {
		mounts = append(mounts, disks[k])
	}
	validation["mounts"] = mounts
	host := hostInventory()
	if role == "bootstrap" {
		if err := validateBootstrap(validation, host); err != nil {
			return err
		}
	} else if _, err := validateSettings(validation, cloneM(validation), host, true); err != nil {
		return err
	}
	before, err := readJSON(filepath.Join(directory, "impact-base.json"), nil)
	if err != nil || before == nil {
		return Public("Candidate has no baseline inventory; build a new review")
	}
	transitionError := validateEffectiveTransition(effective, disks, obj(obj(before)["settings"]), obj(obj(before)["disks"]),
		exists("/var/lib/incus/database")) != nil
	newInputs := obj(readObj(filepath.Join(source, "flake.lock"))["nodes"])
	changedInputs := []any{}
	for _, k := range keys(newInputs) {
		value := obj(newInputs[k])
		oldLocked := jget(obj(oldInputs[k]), "locked")
		if !equalJSON(value["locked"], oldLocked) {
			changedInputs = append(changedInputs, M{"input": k, "before": jget(obj(oldInputs[k]), "locked", "rev"),
				"after": jget(value, "locked", "rev")})
		}
	}
	booted, _ := filepath.EvalSymlinks("/run/booted-system/kernel")
	kernel, _ := filepath.EvalSymlinks(filepath.Join(directory, "system/kernel"))
	reboot := booted != "" && kernel != "" && booted != kernel
	modules, _ := moduleFiles(source)
	opaque := len(modules) > 0 || len(list(job["moduleChanges"])) > 0 || str(job["platformRevision"]) != "" ||
		isTrue(job["sourcePlatformUpdated"]) || isTrue(job["updateInputs"])
	if err := impactPrepare(directory, obj(before), projection, opaque, transitionError); err != nil {
		return err
	}
	migration := obj(job["settingsMigration"])
	var overrides any
	if desired := obj(projection["desiredSettings"]); desired != nil {
		if migration != nil {
			migration = cloneM(migration)
			if v, ok := desired["schemaVersion"]; ok {
				migration["to"] = v
			} else {
				migration["to"] = 0
			}
		}
		overrides = differences(desired, effective, "")
	}
	candidateDigest, err := digestSource(source)
	if err != nil {
		return err
	}
	if _, err := updateJob(directory, M{"status": "ready", "builtAt": now(), "effectiveSettings": effective,
		"desiredSettings": projection["desiredSettings"], "candidateOverrides": overrides, "settingsMigration": migration,
		"candidateDigest": candidateDigest, "inputChanges": changedInputs, "rebootRequired": reboot}); err != nil {
		return err
	}
	audit("build-ready", M{"job": filepath.Base(directory)})
	return nil
}

func saveRecovery(directory string) error {
	recovery := filepath.Join(directory, "recovery")
	os.MkdirAll(recovery, 0o700)
	record, _ := readJobRecord(filepath.Join(directory, "job.json"), M{})
	platform := str(record["platformRevision"]) != "" || isTrue(record["sourcePlatformUpdated"])
	if platform {
		if err := snapshot(filepath.Join(recovery, "platform"), ROOT); err != nil {
			return err
		}
	}
	modules, err := moduleFiles(ROOT)
	if err != nil {
		return err
	}
	names := []any{}
	for _, p := range modules {
		name, _ := filepath.Rel(ROOT, p)
		data, _ := os.ReadFile(p)
		info, _ := os.Stat(p)
		if err := atomic(filepath.Join(recovery, "modules", name), data, info.Mode().Perm(), ""); err != nil {
			return err
		}
		names = append(names, name)
	}
	type pair struct{ path, name string }
	files := []pair{{machinePath(ROOT, "settings"), "settings.json"}, {machinePath(ROOT, "installation"), "installation.json"},
		{filepath.Join(STATE, "platform-baseline.json"), "platform-baseline.json"}, {filepath.Join(ROOT, "flake.lock"), "flake.lock"},
		{hostSecretsPath(ROOT), "host-secrets.yaml"}}
	for _, k := range keys(stringMapToM(SECRET_PATHS)) {
		files = append(files, pair{SECRET_PATHS[k], "secret-" + k})
	}
	files = append(files, pair{filepath.Join(STATE, "tls.crt"), "tls.crt"}, pair{filepath.Join(STATE, "tls.key"), "tls.key"})
	manifest := []any{}
	for _, f := range files {
		info, err := os.Stat(f.path)
		mode := 0o600
		if err == nil {
			mode = int(info.Mode().Perm())
		}
		manifest = append(manifest, M{"path": f.path, "name": f.name, "existed": err == nil, "mode": mode})
		if err == nil {
			data, _ := os.ReadFile(f.path)
			if err := atomic(filepath.Join(recovery, f.name), data, 0o600, ""); err != nil {
				return err
			}
		}
	}
	connections, _ := filepath.Glob("/run/NetworkManager/system-connections/nixus-*.nmconnection")
	for _, p := range connections {
		data, _ := os.ReadFile(p)
		atomic(filepath.Join(recovery, filepath.Base(p)), data, 0o600, "")
	}
	uuids := []any{}
	if res, err := run([]string{"nmcli", "--get-values", "GENERAL.CON-UUID", "device", "show"}, nil, 10*time.Second, nil, ""); err == nil && res.Code == 0 {
		for _, s := range strings.Split(string(res.Stdout), "\n") {
			if s = strings.TrimSpace(s); s != "" && s != "--" {
				uuids = append(uuids, s)
			}
		}
	}
	radios := []any{}
	if out, err := check([]string{"rfkill", "--json"}, nil, 10*time.Second); err == nil {
		if v, err := parseObject(out); err == nil && list(v["rfkilldevices"]) != nil {
			radios = list(v["rfkilldevices"])
		}
	}
	return writeJSON(filepath.Join(recovery, "manifest.json"), M{"files": manifest, "nmConnections": uuids, "radios": radios,
		"moduleFiles": names, "platformSnapshot": platform})
}

func stringMapToM(in map[string]string) M {
	out := M{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func restoreFiles(directory string) (M, error) {
	recovery := filepath.Join(directory, "recovery")
	manifest := readObj(filepath.Join(recovery, "manifest.json"))
	if len(manifest) == 0 {
		return nil, Public("Recovery manifest is missing")
	}
	if isTrue(manifest["platformSnapshot"]) {
		if err := upgradePublish(filepath.Join(recovery, "platform"), ROOT); err != nil {
			return nil, err
		}
	}
	if raw, ok := manifest["moduleFiles"]; ok {
		live, err := moduleFiles(ROOT)
		if err != nil {
			return nil, err
		}
		previous := map[string]bool{}
		names, _ := anyStrings(raw)
		for _, name := range names {
			if !(strings.HasPrefix(name, "site-modules/") || strings.HasPrefix(name, "machine/modules/")) || strings.Contains("/"+name+"/", "/../") {
				return nil, Public("Invalid module recovery path")
			}
			previous[name] = true
		}
		for _, p := range live {
			rel, _ := filepath.Rel(ROOT, p)
			if !previous[rel] {
				durableUnlink(p)
			}
		}
		for name := range previous {
			src := filepath.Join(recovery, "modules", name)
			data, err := os.ReadFile(src)
			if err != nil {
				return nil, err
			}
			info, _ := os.Stat(src)
			if err := atomic(filepath.Join(ROOT, name), data, info.Mode().Perm(), ""); err != nil {
				return nil, err
			}
		}
	}
	for _, raw := range list(manifest["files"]) {
		item := obj(raw)
		target := str(item["path"])
		if isTrue(item["existed"]) {
			data, err := os.ReadFile(filepath.Join(recovery, str(item["name"])))
			if err != nil {
				return nil, err
			}
			mode, _ := num(item["mode"])
			if err := atomic(target, data, os.FileMode(int(mode)), ""); err != nil {
				return nil, err
			}
		} else {
			os.Remove(target)
		}
	}
	live, _ := filepath.Glob("/run/NetworkManager/system-connections/nixus-*.nmconnection")
	for _, p := range live {
		os.Remove(p)
	}
	saved, _ := filepath.Glob(filepath.Join(recovery, "nixus-*.nmconnection"))
	for _, p := range saved {
		data, _ := os.ReadFile(p)
		atomic(filepath.Join("/run/NetworkManager/system-connections", filepath.Base(p)), data, 0o600, "")
	}
	return manifest, nil
}

func workerRollback(directory, reason string) error {
	job, err := updateJob(directory, M{"status": "rolling-back", "rollbackReason": reason})
	if err != nil {
		return err
	}
	previous := str(job["previousSystem"])
	if previous == "" || !isFile(filepath.Join(previous, "bin/switch-to-configuration")) {
		return Public("Previous OS generation is unavailable; use the bootloader recovery menu")
	}
	log, err := os.OpenFile(filepath.Join(directory, "build.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	manifest, err := restoreFiles(directory)
	if err != nil {
		log.Close()
		return err
	}
	if _, err := hostCommand([]string{"nix-env", "--profile", "/nix/var/nix/profiles/system", "--set", previous}, log, 120*time.Second, true); err != nil {
		log.Close()
		return err
	}
	if _, err := hostCommand([]string{previous + "/bin/switch-to-configuration", "switch"}, log, 900*time.Second, true); err != nil {
		log.Close()
		return err
	}
	if lookPath("rfkill") != "" {
		for _, raw := range list(manifest["radios"]) {
			radio := obj(raw)
			id := fmt.Sprint(radio["id"])
			if f, ok := num(radio["id"]); ok {
				id = fmt.Sprint(int(f))
			}
			if _, err := fmt.Sscanf(id, "%d", new(int)); err != nil {
				continue
			}
			action := "unblock"
			if radio["soft"] == "blocked" || radio["soft"] == true {
				action = "block"
			}
			hostCommand([]string{"rfkill", action, id}, log, 10*time.Second, false)
		}
	}
	if lookPath("nmcli") != "" {
		hostCommand([]string{"nmcli", "connection", "reload"}, log, 30*time.Second, false)
		existing := map[string]bool{}
		if res, err := run([]string{"nmcli", "--get-values", "UUID", "connection", "show"}, nil, 10*time.Second, nil, ""); err == nil && res.Code == 0 {
			for _, line := range strings.Split(string(res.Stdout), "\n") {
				existing[line] = true
			}
		}
		for _, raw := range list(manifest["nmConnections"]) {
			uuid := str(raw)
			if existing[uuid] {
				hostCommand([]string{"nmcli", "--wait", "30", "connection", "up", "uuid", uuid}, log, 40*time.Second, false)
			} else {
				log.WriteString("Skipped connection no longer present\n")
			}
		}
	}
	restartLoaded([]string{"nixus-admin-backend.service", "nixus-ui.service", "nginx.service", "cockpit.service"}, log)
	log.Close()
	if _, err := updateJob(directory, M{"status": "rolled-back", "rolledBackAt": now()}); err != nil {
		return err
	}
	if str(readObj(filepath.Join(STATE, "pending.json"))["id"]) == filepath.Base(directory) {
		durableUnlink(filepath.Join(STATE, "pending.json"))
	}
	removeStagedSecrets(directory)
	durableUnlink(filepath.Join(directory, "system"))
	durableUnlink(filepath.Join(directory, "previous-system"))
	audit("rolled-back", M{"job": filepath.Base(directory), "reason": reason})
	return nil
}

func restartLoaded(units []string, log *os.File) {
	for _, unit := range units {
		res, err := run([]string{"systemctl", "show", unit, "--property=LoadState", "--value"}, nil, 10*time.Second, nil, "")
		if err == nil && res.Code == 0 && strings.TrimSpace(string(res.Stdout)) == "loaded" {
			hostCommand([]string{"systemctl", "try-restart", unit}, log, 45*time.Second, false)
		}
	}
}

func recoverActivation(directory string) {
	updateJob(directory, M{"error": "Activation failed"})
	if err := workerRollback(directory, "activation failed"); err != nil {
		updateJob(directory, M{"status": "failed", "error": "Activation failed", "rollbackError": "Rollback failed; local recovery may be required"})
		if log, err := os.OpenFile(filepath.Join(directory, "build.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			log.WriteString("\nROLLBACK FAILED: local recovery may be required\n")
			log.Close()
		}
	}
}

func workerApply(directory string) error {
	job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
	if err != nil {
		return err
	}
	if err := requireFreshStagedSecrets(job); err != nil {
		return err
	}
	role, err := hostRoleOf(job)
	if err != nil {
		return err
	}
	base, err1 := digestSource(ROOT)
	candidate, err2 := digestSource(filepath.Join(directory, "source"))
	if err1 != nil || err2 != nil || base != str(job["baseDigest"]) || candidate != str(job["candidateDigest"]) {
		return Public("Source changed since review")
	}
	if err := impactRecheck(directory); err != nil {
		return err
	}
	oldSettings := readObj("/etc/nixus/effective-settings.json")
	if len(oldSettings) == 0 {
		oldSettings = readObj(machinePath(ROOT, "settings"))
	}
	effective := obj(job["effectiveSettings"])
	if effective == nil {
		effective = obj(job["settings"])
	}
	if role == "bootstrap" && (isTrue(effective["ready"]) || isTrue(oldSettings["ready"])) {
		return Public("Bootstrap cannot replace a configured host; build a full host review")
	}
	previous, _ := filepath.EvalSymlinks("/run/current-system")
	if err := saveRecovery(directory); err != nil {
		return err
	}
	if _, err := check([]string{"nix-store", "--add-root", filepath.Join(directory, "previous-system"), "--indirect", "--realise", previous}, nil, 5*time.Minute); err != nil {
		return err
	}
	if job, err = updateJob(directory, M{"previousSystem": previous}); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(STATE, "pending.json"), M{"id": filepath.Base(directory), "previousSystem": previous, "deadline": now() + 960}); err != nil {
		return err
	}
	err = func() error {
		secretChanges, _ := anyStrings(job["secretChanges"])
		staged, err := readStagedSecrets(directory, secretChanges)
		if err != nil {
			return err
		}
		for _, key := range keys(staged) {
			if err := atomicString(SECRET_PATHS[key], str(staged[key]), 0o600); err != nil {
				return err
			}
		}
		if err := removeStagedSecrets(directory); err != nil {
			return err
		}
		if str(job["platformRevision"]) != "" || isTrue(job["sourcePlatformUpdated"]) {
			if err := upgradePublish(filepath.Join(directory, "source"), ROOT); err != nil {
				return err
			}
		}
		if isTrue(job["sourceStaged"]) {
			installed := machinePath(filepath.Join(directory, "source"), "installation")
			if !isFile(installed) {
				return Public("Reviewed installer inventory is missing")
			}
			data, _ := os.ReadFile(installed)
			if err := atomic(machinePath(ROOT, "installation"), data, 0o600, ""); err != nil {
				return err
			}
			if isTrue(job["sourcePlatformUpdated"]) {
				files, err := sourceFiles(ROOT)
				if err != nil {
					return err
				}
				baseline := M{}
				for _, f := range files {
					if platformPath(f.name) {
						data, _ := os.ReadFile(f.path)
						h := sha256.Sum256(data)
						baseline[f.name] = hex.EncodeToString(h[:])
					}
				}
				if err := writeJSON(filepath.Join(STATE, "platform-baseline.json"), baseline); err != nil {
					return err
				}
			}
		}
		if err := installModules(filepath.Join(directory, "source"), ROOT); err != nil {
			return err
		}
		if err := writeJSON(machinePath(ROOT, "settings"), job["settings"]); err != nil {
			return err
		}
		if reviewed := hostSecretsPath(filepath.Join(directory, "source")); isFile(reviewed) {
			data, _ := os.ReadFile(reviewed)
			if err := atomic(hostSecretsPath(ROOT), data, 0o644, ""); err != nil {
				return err
			}
		}
		if isTrue(job["updateInputs"]) {
			data, _ := os.ReadFile(filepath.Join(directory, "source/flake.lock"))
			if err := atomic(filepath.Join(ROOT, "flake.lock"), data, 0o644, ""); err != nil {
				return err
			}
		}
		before, after := obj(oldSettings["management"]), obj(effective["management"])
		identityChanged := str(before["address"]) != str(after["address"]) || str(oldSettings["hostName"]) != str(effective["hostName"])
		if identityChanged {
			if err := issueTLS(str(after["address"]), str(effective["hostName"])); err != nil {
				return err
			}
		}
		log, err := os.OpenFile(filepath.Join(directory, "build.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer log.Close()
		system, _ := filepath.EvalSymlinks(filepath.Join(directory, "system"))
		steps := [][]string{{"nix-env", "--profile", "/nix/var/nix/profiles/system", "--set", system}}
		if _, err := hostCommand(steps[0], log, 120*time.Second, true); err != nil {
			return err
		}
		if _, err := hostCommand([]string{system + "/bin/switch-to-configuration", "switch"}, log, 900*time.Second, true); err != nil {
			return err
		}
		if err := prepareStateAccess(true); err != nil {
			return err
		}
		if role == "hypervisor" {
			if _, err := hostCommand([]string{"systemctl", "is-active", "incus.service", "nixus-instances.service"}, log, 30*time.Second, true); err != nil {
				return err
			}
			if isTrue(jget(effective, "cockpit", "enable")) {
				if _, err := hostCommand([]string{"systemctl", "is-active", "cockpit.socket"}, log, 30*time.Second, true); err != nil {
					return err
				}
				if _, err := hostCommand([]string{"systemctl", "try-restart", "cockpit.service"}, log, 45*time.Second, true); err != nil {
					return err
				}
			}
			if identityChanged {
				if _, err := hostCommand([]string{"systemctl", "try-restart", "incus.service"}, log, 120*time.Second, true); err != nil {
					return err
				}
			}
		}
		if _, err := hostCommand([]string{"systemctl", "try-restart", "nixus-admin-backend.service", "nixus-ui.service"}, log, 45*time.Second, true); err != nil {
			return err
		}
		if _, err := hostCommand([]string{"systemctl", "is-active", "nixus-admin-backend.service", "nixus-ui.service"}, log, 30*time.Second, true); err != nil {
			return err
		}
		report, err := waitReady(effective, 0)
		if err != nil {
			return err
		}
		writeJSON(filepath.Join(directory, "health.json"), report)
		seconds, _ := num(jget(effective, "setup", "confirmationSeconds"))
		deadline := now() + seconds
		if err := writeJSON(filepath.Join(STATE, "pending.json"), M{"id": filepath.Base(directory), "previousSystem": previous, "deadline": deadline}); err != nil {
			return err
		}
		if _, err := updateJob(directory, M{"status": "awaiting-confirmation", "deadline": deadline, "awaitingAt": now()}); err != nil {
			return err
		}
		audit("awaiting-confirmation", M{"job": filepath.Base(directory)})
		return nil
	}()
	if err != nil {
		recoverActivation(directory)
		return err
	}
	return nil
}

func workerJob(phase, id string) error {
	if !fullmatch(jobID, id) {
		return Public("Invalid transaction ID")
	}
	directory := filepath.Join(STATE, "jobs", id)
	if !isDir(directory) {
		return Public("Unknown transaction")
	}
	var err error
	switch phase {
	case "build":
		err = workerBuild(directory)
	case "apply":
		err = locked(true, func() error { return workerApply(directory) })
	case "rollback":
		err = locked(true, func() error { return workerRollback(directory, "requested") })
	default:
		err = Public("Unsupported transaction action")
	}
	if err == nil {
		return nil
	}
	var review *ReviewRequired
	if errors.As(err, &review) {
		updateJob(directory, M{"status": "ready", "error": "Review the updated impact plan before applying"})
		audit("impact-review-required", M{"job": id})
		return nil
	}
	if current, rerr := readJobRecord(filepath.Join(directory, "job.json"), nil); rerr == nil && str(current["status"]) != "rolled-back" {
		updateJob(directory, M{"status": "failed", "error": "Transaction failed; inspect host status before retrying"})
	}
	if log, lerr := os.OpenFile(filepath.Join(directory, "build.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); lerr == nil {
		log.WriteString("\nFAILED: transaction did not complete\n")
		log.Close()
	}
	audit("transaction-failed", M{"job": id, "phase": phase})
	return Public("Transaction failed; inspect host status before retrying")
}

// guard rolls back expired activations and sweeps protected credentials.
func guard() error {
	failed := false
	pendingPath := filepath.Join(STATE, "pending.json")
	pending := readObj(pendingPath)
	if deadline, ok := num(pending["deadline"]); ok && now() >= deadline {
		err := locked(true, func() error {
			pending := readObj(pendingPath)
			if len(pending) == 0 {
				return nil
			}
			id := str(pending["id"])
			job, _ := readJobRecord(filepath.Join(STATE, "jobs", id, "job.json"), M{})
			if str(job["status"]) == "confirmed" {
				return durableUnlink(pendingPath)
			}
			if d, _ := num(pending["deadline"]); now() >= d {
				return workerRollback(filepath.Join(STATE, "jobs", id), "confirmation timed out")
			}
			return nil
		})
		if err != nil {
			failed = true
		}
	}
	err := locked(false, func() error {
		for _, cleanup := range []func() error{
			func() error { return cleanupTerminalSecrets(STATE) },
			browserCleanupPrivate,
			func() error { return browserExpireOwned(STATE) },
		} {
			if cleanup() != nil {
				failed = true
			}
		}
		return nil
	})
	if err != nil && publicError(err) != (BusyError{}).Error() {
		failed = true
	}
	if failed {
		return Public("Protected credential cleanup failed; inspect pending recovery, transaction storage, browser identities and host clock")
	}
	return nil
}

package main

// Declarative project backups driven by the reviewed workspace backups.nix:
// a hash-manifested configuration snapshot of every included project
// (workspace Nix, SOPS ciphertext and published Dockerfile/Compose sources),
// optional Incus data exports through the existing exporter, encrypted
// off-host restic (including rclone Google Drive), verification and a
// GitHub configuration mirror over a dedicated deploy key. Each phase keeps
// its own status; a later phase never hides an earlier failure.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var projectBackupRoot = envPath("NIXUS_PROJECT_BACKUPS", "/var/lib/nixus/project-backups")

// GitHub's published SSH host keys; pinned so a first push cannot be redirected.

var resticRepository = re(`(?:rclone:[A-Za-z0-9_-]+:[A-Za-z0-9._/-]+|sftp:[A-Za-z0-9._@:/-]+|s3:[A-Za-z0-9._:/-]+|b2:[A-Za-z0-9._:/-]+|rest:https://[A-Za-z0-9._:/-]+|/[A-Za-z0-9._/-]+)`)
var runtimeFile = re(`/(?:var/lib|run|etc)/[A-Za-z0-9._/-]+`)

func validateBackupPolicy(raw any) (M, error) {
	if raw == nil {
		return nil, nil
	}
	fail := Public("Invalid project backup policy")
	p := obj(raw)
	if !exactKeys(p, "enable", "includeProjects", "schedule", "data", "retention", "verification", "restic") {
		return nil, fail
	}
	for _, k := range []string{"enable", "data"} {
		if _, ok := p[k].(bool); !ok {
			return nil, fail
		}
	}
	if s := str(p["includeProjects"]); s != "all" {
		names, ok := anyStrings(p["includeProjects"])
		if !ok || p["includeProjects"] == "all" {
			return nil, fail
		}
		for _, n := range names {
			if !fullmatch(projectName, n) {
				return nil, fail
			}
		}
	}
	switch str(p["schedule"]) {
	case "hourly", "daily", "weekly":
	default:
		return nil, fail
	}
	switch str(p["verification"]) {
	case "none", "metadata", "full":
	default:
		return nil, fail
	}
	retention := obj(p["retention"])
	if !exactKeys(retention, "daily", "weekly", "monthly") {
		return nil, fail
	}
	for _, k := range []string{"daily", "weekly", "monthly"} {
		if n, ok := intValue(retention[k]); !ok || n < 0 || n > 365 || (k == "daily" && n < 1) {
			return nil, fail
		}
	}
	restic := obj(p["restic"])
	if !exactKeys(restic, "repository", "passwordFile", "environmentFile", "rcloneConfigFile", "initialize") ||
		!fullmatch(resticRepository, str(restic["repository"])) || !fullmatch(runtimeFile, str(restic["passwordFile"])) {
		return nil, fail
	}
	for _, k := range []string{"environmentFile", "rcloneConfigFile"} {
		if restic[k] != nil && !fullmatch(runtimeFile, str(restic[k])) {
			return nil, fail
		}
	}
	if strings.HasPrefix(str(restic["repository"]), "rclone:") && restic["rcloneConfigFile"] == nil {
		return nil, Public("rclone repositories need a root-owned rcloneConfigFile")
	}
	if _, ok := restic["initialize"].(bool); !ok {
		return nil, fail
	}
	return p, nil
}

// publishedProjectPolicy returns the policy and inventory of the last
// published, still-live reviewed workspace revision.
func publishedProjectPolicy(t *ProjectTransactions) (M, M, error) {
	id := str(readObj(filepath.Join(t.state, "project-last.json"))["id"])
	if id == "" {
		return nil, nil, nil
	}
	record, err := t.record(id)
	if err != nil {
		return nil, nil, err
	}
	if str(record["status"]) != "published-source" {
		return nil, nil, nil
	}
	live, err := validateWorkspace(t.workspace, true)
	if err != nil || (str(live["sourceHash"]) != str(record["candidateHash"]) && !approvedSecretChanges(t, id, live)) {
		return nil, nil, Public("The live project workspace differs from its published review; re-review before backups run")
	}
	dir, _ := t.job(id)
	inventory := readObj(filepath.Join(dir, "inventory.json"))
	policy, err := validateBackupPolicy(inventory["backups"])
	if err != nil {
		return nil, nil, err
	}
	return policy, inventory, nil
}

// Accept secret publications only when their durable authenticated index matches
// the changed bytes. All other workspace bytes must still match the review.
func approvedSecretChanges(t *ProjectTransactions, id string, live M) bool {
	dir, err := t.job(id)
	if err != nil {
		return false
	}
	baseline, err := validateWorkspace(filepath.Join(dir, "source"), true)
	if err != nil {
		return false
	}
	expected := cloneM(obj(baseline["files"]))
	actual := obj(live["files"])
	for _, name := range keys(obj(live["projects"])) {
		index := readObj(filepath.Join(t.state, "project-secrets", "projects", name, "index.json"))
		cipherPath := name + "/secrets.enc.yaml"
		if str(obj(actual[cipherPath])["sha256"]) != str(index["revision"]) || str(index["revision"]) == "" {
			continue
		}
		expected[cipherPath] = actual[cipherPath]
		policyPath := name + "/.sops.yaml"
		recipients, ok := anyStrings(index["recipients"])
		if ok && str(obj(actual[policyPath])["sha256"]) == sha256hex(sopsPolicy(recipients)) {
			expected[policyPath] = actual[policyPath]
		}
	}
	return equalJSON(expected, actual)
}

func includedProjects(policy, inventory M) []string {
	all := keys(obj(inventory["projects"]))
	if str(policy["includeProjects"]) == "all" {
		return all
	}
	wanted, _ := anyStrings(policy["includeProjects"])
	present := map[string]bool{}
	for _, n := range all {
		present[n] = true
	}
	var out []string
	for _, n := range wanted {
		if present[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func scheduleSeconds(s string) float64 {
	switch s {
	case "hourly":
		return 3600
	case "weekly":
		return 7 * 86400
	}
	return 86400
}

func projectBackupStatusPath() string { return filepath.Join(STATE, "project-backup-status.json") }

func projectBackupStatus() M {
	status := readObj(projectBackupStatusPath())
	if status["phases"] == nil {
		status["phases"] = M{}
	}
	return status
}

// projectBackupHealth: disabled, never, ok, failed (last run had failed
// phases) or overdue (no success for two schedule periods).
func projectBackupHealth() string {
	status := projectBackupStatus()
	if !isTrue(status["enabled"]) {
		return "disabled"
	}
	last, _ := num(status["lastSuccess"])
	attempt, _ := num(status["lastAttempt"])
	period := scheduleSeconds(str(status["schedule"]))
	switch {
	case last == 0:
		return "never"
	case attempt > last:
		return "failed"
	case now()-last > 2*period:
		return "overdue"
	}
	return "ok"
}

func setPhase(status M, phase, state, detail string) {
	obj(status["phases"])[phase] = M{"state": state, "at": now(), "detail": detail}
	writeJSONMode(projectBackupStatusPath(), status, 0o640, "")
}

// coverage states, per project, what is actually protected.
func projectCoverage(project M, data bool) M {
	if !data {
		return M{"config": true, "data": "not-selected", "unknowns": []any{"instance and volume data are excluded by policy"}}
	}
	unknowns := []any{}
	if str(project["backend"]) == "incus-compose" {
		unknowns = append(unknowns, "host bind mounts outside Incus volumes are not exported")
	}
	if !isTrue(project["enable"]) {
		unknowns = append(unknowns, "project disabled; existing Incus resources are still exported if present")
	}
	return M{"config": true, "data": "incus-export", "incusProject": project["incusProject"], "unknowns": unknowns}
}

// configSnapshot copies reviewed bytes only and records a hash manifest.
func configSnapshot(t *ProjectTransactions, policy, inventory M, destination string) (M, error) {
	workspace, err := validateWorkspace(t.workspace, true)
	if err != nil {
		return nil, err
	}
	included := includedProjects(policy, inventory)
	keep := map[string]bool{}
	for _, name := range included {
		keep[str(jget(inventory, "projects", name, "source"))] = true
	}
	hashes := M{}
	files := obj(workspace["files"])
	for _, rel := range keys(files) {
		top := strings.SplitN(rel, "/", 2)[0]
		if strings.Contains(rel, "/") && !keep[top] {
			continue
		}
		data, err := safeBytes(t.workspace, rel, obj(files[rel]))
		if err != nil {
			return nil, err
		}
		target := filepath.Join(destination, "workspace", rel)
		if err := atomic(target, data, 0o600, ""); err != nil {
			return nil, err
		}
		hashes["workspace/"+rel] = sha256hex(data)
	}
	publisher := NewPublishedSources("")
	projects := M{}
	for _, name := range included {
		project := obj(jget(inventory, "projects", name))
		entry := projectCoverage(project, isTrue(policy["data"]))
		current, err := publisher.current(name)
		if err != nil {
			return nil, err
		}
		if current != nil {
			revision := str(current["revision"])
			if _, err := publisher.attestOpts(name, revision, true); err != nil {
				return nil, err
			}
			folder := filepath.Join(publisher.root, name, "revisions", revision)
			manifest := readObj(filepath.Join(folder, "manifest.json"))
			sourceFiles, err := checkFiles(manifest["files"])
			if err != nil {
				return nil, err
			}
			for _, f := range sourceFiles {
				data, err := os.ReadFile(filepath.Join(folder, "source", f.Path))
				if err != nil || sha256hex(data) != f.SHA256 {
					return nil, Public("Published source for " + name + " changed during the snapshot")
				}
				rel := "sources/" + name + "/" + f.Path
				if err := atomic(filepath.Join(destination, rel), data, 0o600, ""); err != nil {
					return nil, err
				}
				hashes[rel] = f.SHA256
			}
			entry["sourceRevision"] = revision
		} else if str(project["backend"]) == "incus-compose" {
			entry["unknowns"] = append(list(entry["unknowns"]), "no published Dockerfile/Compose source; the project cannot be rebuilt from backup")
		}
		projects[name] = entry
	}
	hostFiles, err := snapshotHost(ROOT, destination, hashes)
	if err != nil {
		return nil, err
	}
	manifest := M{"format": 1, "hostFiles": hostFiles, "workspaceSourceHash": workspace["sourceHash"], "projects": projects, "files": hashes,
		"excludes": "builder caches, OCI layers and the Nix store are not included; age identities and backup credentials are added only inside the encrypted restic snapshot"}
	if err := writeJSON(filepath.Join(destination, "MANIFEST.json"), manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func resticEnv(policy M) ([]string, error) {
	restic := obj(policy["restic"])
	path := os.Getenv("PATH")
	env := []string{"PATH=" + path, "HOME=/var/empty", "RESTIC_REPOSITORY=" + str(restic["repository"]),
		"RESTIC_PASSWORD_FILE=" + str(restic["passwordFile"]), "RESTIC_CACHE_DIR=" + filepath.Join(projectBackupRoot, ".restic-cache")}
	if !isFile(str(restic["passwordFile"])) {
		return nil, Public("The restic password file is missing; create it as a root-only runtime file")
	}
	if f := str(restic["rcloneConfigFile"]); f != "" {
		if !isFile(f) {
			return nil, Public("The rclone configuration file is missing; enroll the remote first")
		}
		env = append(env, "RCLONE_CONFIG="+f)
	}
	if f := str(restic["environmentFile"]); f != "" {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, Public("The restic environment file is unreadable")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, _, ok := strings.Cut(line, "=")
			if !ok || !ENV_KEYS[k] {
				return nil, Public("The restic environment file has an unsupported variable")
			}
			env = append(env, line)
		}
	}
	return env, nil
}

var resticRun = func(env []string, timeout time.Duration, args ...string) error {
	res, err := run(append([]string{"restic"}, args...), nil, timeout, env, "")
	if err != nil || res.Code != 0 {
		return cmdFailed("restic "+args[0]+" failed; check the destination, credentials and quota", res, err)
	}
	return nil
}

func backupHostID() (string, error) {
	path := filepath.Join(STATE, "backup-host-id")
	if raw, err := os.ReadFile(path); err == nil && fullmatch(jobID, strings.TrimSpace(string(raw))) {
		return strings.TrimSpace(string(raw)), nil
	}
	id := tokenHex(16)
	if err := atomic(path, []byte(id), 0o600, ""); err != nil {
		return "", err
	}
	return id, nil
}

func offHostBackup(policy M, paths []string) error {
	env, err := resticEnv(policy)
	if err != nil {
		return err
	}
	if resticRun(env, 2*time.Minute, "cat", "config") != nil {
		if !isTrue(jget(policy, "restic", "initialize")) {
			return Public("The restic repository is unreachable or uninitialized; set restic.initialize = true for a new repository")
		}
		if err := resticRun(env, 5*time.Minute, "init"); err != nil {
			return err
		}
	}
	host, err := backupHostID()
	if err != nil {
		return err
	}
	if err := resticRun(env, 12*time.Hour, append([]string{"backup", "--tag", "nixus-project", "--tag", "nixus-project-complete", "--host", host}, paths...)...); err != nil {
		return err
	}
	r := obj(policy["retention"])
	return resticRun(env, 2*time.Hour, "forget", "--tag", "nixus-project", "--host", host, "--group-by", "host", "--prune",
		"--keep-daily", fmt.Sprint(r["daily"]), "--keep-weekly", fmt.Sprint(r["weekly"]), "--keep-monthly", fmt.Sprint(r["monthly"]))
}

func verifyOffHost(policy M) error {
	env, err := resticEnv(policy)
	if err != nil {
		return err
	}
	args := []string{"check"}
	if str(policy["verification"]) == "full" {
		args = append(args, "--read-data")
	}
	return resticRun(env, 12*time.Hour, args...)
}

func pruneSnapshots(keep int) {
	dir := filepath.Join(projectBackupRoot, "config")
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		os.RemoveAll(filepath.Join(dir, names[0]))
		names = names[1:]
	}
}

// runProjectBackup executes every enabled phase; force ignores the schedule.
func runProjectBackup(force bool) (M, error) {
	t := NewProjectTransactions("", "")
	policy, inventory, err := publishedProjectPolicy(t)
	if err != nil {
		return nil, err
	}
	status := projectBackupStatus()
	if policy == nil || !isTrue(policy["enable"]) {
		status["enabled"] = false
		writeJSONMode(projectBackupStatusPath(), status, 0o640, "")
		return status, nil
	}
	last, _ := num(status["lastSuccess"])
	if !force && now()-last < scheduleSeconds(str(policy["schedule"]))-300 {
		return M{"due": false, "nextAfter": last + scheduleSeconds(str(policy["schedule"]))}, nil
	}
	os.MkdirAll(projectBackupRoot, 0o700)
	generation := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	status["enabled"], status["generation"], status["phases"], status["schedule"] = true, generation, M{}, str(policy["schedule"])
	snapshot := filepath.Join(projectBackupRoot, "config", generation)
	ok := true
	manifest, err := configSnapshot(t, policy, inventory, snapshot)
	if err != nil {
		setPhase(status, "config", "failed", publicError(err))
		return status, err
	}
	setPhase(status, "config", "complete", fmt.Sprintf("%d files", len(obj(manifest["files"]))))
	if keys := presentKeyFiles(); len(keys) > 0 {
		setPhase(status, "keys", "complete", "age identity and credentials included in the encrypted snapshot")
	} else {
		setPhase(status, "keys", "skipped", "no age identity or credentials on this host yet")
	}
	status["coverage"] = manifest["projects"]
	paths := append([]string{snapshot}, presentKeyFiles()...)
	if isTrue(policy["data"]) {
		err := func() error {
			release, err := lockFile(incusLock, true)
			if err != nil {
				return err
			}
			defer release()
			selected := map[string]bool{}
			for _, name := range includedProjects(policy, inventory) {
				selected[str(jget(inventory, "projects", name, "incusProject"))] = true
			}
			return runSelectedBackup(selected)
		}()
		if err != nil {
			ok = false
			setPhase(status, "data", "failed", publicError(err))
		} else {
			latest := str(readObj(filepath.Join(backupRoot, "latest.json"))["generation"])
			if latest != "" {
				paths = append(paths, filepath.Join(backupRoot, "generations", latest))
			}
			setPhase(status, "data", "complete", "Incus exports staged locally; not off-host until uploaded")
		}
	} else {
		setPhase(status, "data", "skipped", "data excluded by policy")
	}
	if !ok {
		status["lastAttempt"] = now()
		setPhase(status, "offHost", "skipped", "required data export failed")
		return status, Public("Required data export failed; no partial snapshot uploaded")
	}
	if err := offHostBackup(policy, paths); err != nil {
		ok = false
		setPhase(status, "offHost", "failed", publicError(err))
		setPhase(status, "verification", "skipped", "no completed upload to verify")
	} else {
		setPhase(status, "offHost", "complete", "encrypted restic snapshot uploaded")
		if str(policy["verification"]) == "none" {
			setPhase(status, "verification", "skipped", "verification disabled by policy")
		} else if err := verifyOffHost(policy); err != nil {
			ok = false
			setPhase(status, "verification", "failed", publicError(err))
		} else {
			setPhase(status, "verification", "complete", str(policy["verification"])+" check passed; not an application restore test")
		}
	}
	pruneSnapshots(2)
	status["restoreTest"] = "not performed; run an isolated restore drill to qualify recovery"
	completed := now()
	if ok {
		status["lastSuccess"] = completed
	}
	status["lastAttempt"] = completed
	writeJSONMode(projectBackupStatusPath(), status, 0o640, "")
	audit("project-backup-finished", M{"generation": generation, "success": ok})
	if !ok {
		return status, Public("Project backup finished with failed phases; inspect nixus-admin project-backup status")
	}
	return status, nil
}

func projectBackupCLI(args []string) error {
	if len(args) == 0 {
		return Public("usage: nixus-admin project-backup {tick|run|status|check-destination|restore}")
	}
	switch args[0] {
	case "tick", "run":
		status, err := runProjectBackup(args[0] == "run")
		if status != nil {
			printJSON(status)
		}
		return err
	case "status":
		printJSON(projectBackupStatus())
		return nil
	case "restore":
		return projectRestoreCLI(args[1:])
	case "check-destination":
		policy, _, err := publishedProjectPolicy(NewProjectTransactions("", ""))
		if err != nil {
			return err
		}
		if policy == nil {
			return Public("No published backups.nix policy")
		}
		env, err := resticEnv(policy)
		if err != nil {
			return err
		}
		if err := resticRun(env, 2*time.Minute, "cat", "config"); err != nil {
			return err
		}
		fmt.Println("Restic destination reachable and unlocked.")
		return nil
	}
	return Public("Unknown project-backup command")
}

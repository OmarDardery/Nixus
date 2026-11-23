package main

// Cold-host project restore (#44). Rebuilds an empty Nixus host from one
// encrypted restic snapshot written by runProjectBackup: the reviewed project
// workspace, every published Dockerfile/Compose source revision (byte for
// byte), and the Incus projects, custom volumes and instances exported by the
// data phase. Nothing that already exists is overwritten: any collision stops
// the restore before Incus is changed.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var restoreRoot = envPath("NIXUS_RESTORE_DIRECTORY", "/var/lib/nixus/restores")

type restoreOptions struct {
	Repository, PasswordFile, RcloneConfig, EnvironmentFile, Snapshot string
}

func restoreEnv(o restoreOptions) ([]string, error) {
	if !fullmatch(resticRepository, o.Repository) || !fullmatch(runtimeFile, o.PasswordFile) || !isFile(o.PasswordFile) {
		return nil, Public("Give the restic repository and a root-only password file")
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=/var/empty", "RESTIC_REPOSITORY=" + o.Repository,
		"RESTIC_PASSWORD_FILE=" + o.PasswordFile, "RESTIC_CACHE_DIR=" + filepath.Join(restoreRoot, ".restic-cache")}
	if o.RcloneConfig != "" {
		if !fullmatch(runtimeFile, o.RcloneConfig) || !isFile(o.RcloneConfig) {
			return nil, Public("The rclone configuration file is missing")
		}
		env = append(env, "RCLONE_CONFIG="+o.RcloneConfig)
	}
	if o.EnvironmentFile != "" {
		raw, err := os.ReadFile(o.EnvironmentFile)
		if err != nil || !fullmatch(runtimeFile, o.EnvironmentFile) {
			return nil, Public("The credentials file is unreadable")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if k, _, ok := strings.Cut(line, "="); !ok || !ENV_KEYS[k] {
				return nil, Public("The credentials file has an unsupported variable")
			}
			env = append(env, line)
		}
	}
	return env, nil
}

// findOne returns the newest directory under root that contains marker and
// whose path contains part.
func findOne(root, part, marker string) string {
	var found []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == marker && strings.Contains(p, part) && d.Type().IsRegular() {
			found = append(found, filepath.Dir(p))
		}
		return nil
	})
	sort.Strings(found)
	if len(found) == 0 {
		return ""
	}
	return found[len(found)-1]
}

func verifiedRestoredFile(base, rel, want string) ([]byte, error) {
	p := filepath.Join(base, rel)
	if strings.Contains("/"+rel+"/", "/../") || isSymlink(p) {
		return nil, Public("Backup contains an unsafe path")
	}
	data, err := os.ReadFile(p)
	if err != nil || sha256hex(data) != want {
		return nil, Public("Backup file " + rel + " is missing or does not match its recorded hash")
	}
	return data, nil
}

func restoreWorkspace(t *ProjectTransactions, config string, files M) (int, error) {
	if lexists(t.workspace) {
		return 0, Public("A project workspace already exists on this host; restore only onto an empty host")
	}
	parent := filepath.Dir(t.workspace)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return 0, err
	}
	scratch, err := os.MkdirTemp(parent, ".nixus-restore-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(scratch)
	count := 0
	for _, rel := range keys(files) {
		if !strings.HasPrefix(rel, "workspace/") {
			continue
		}
		data, err := verifiedRestoredFile(config, rel, str(files[rel]))
		if err != nil {
			return 0, err
		}
		if err := atomic(filepath.Join(scratch, strings.TrimPrefix(rel, "workspace/")), data, 0o600, ""); err != nil {
			return 0, err
		}
		count++
	}
	if _, err := validateWorkspace(scratch, true); err != nil {
		return 0, err
	}
	if err := os.Rename(scratch, t.workspace); err != nil {
		return 0, err
	}
	fsyncDir(parent)
	return count, nil
}

func restoreSources(config string, manifest M) (M, error) {
	files := obj(manifest["files"])
	restored := M{}
	publisher := NewPublishedSources("")
	for _, project := range keys(obj(manifest["projects"])) {
		want := str(obj(obj(manifest["projects"])[project])["sourceRevision"])
		if want == "" {
			continue
		}
		if current, _ := publisher.current(project); current != nil {
			return nil, Public("Published source for " + project + " already exists on this host")
		}
		prefix := "sources/" + project + "/"
		contents := map[string][]byte{}
		var entries []any
		var sourceFiles []sourceEntry
		for _, rel := range keys(files) {
			if !strings.HasPrefix(rel, prefix) {
				continue
			}
			data, err := verifiedRestoredFile(config, rel, str(files[rel]))
			if err != nil {
				return nil, err
			}
			name := strings.TrimPrefix(rel, prefix)
			contents[name] = data
			entry := sourceEntry{Path: name, Size: int64(len(data)), SHA256: sha256hex(data)}
			sourceFiles = append(sourceFiles, entry)
			entries = append(entries, entry.M())
		}
		staged, err := stageFiles("restore", project, entries, sourceFiles, contents)
		if err != nil {
			return nil, err
		}
		got, err := publishStaged("restore", staged)
		if err != nil {
			return nil, err
		}
		if got != want {
			return nil, Public("Restored source for " + project + " does not reproduce revision " + want)
		}
		restored[project] = got
	}
	return restored, nil
}

// restoreIncus recreates Incus projects, then imports custom volumes and
// instances from one verified export generation.
func restoreIncus(incus incusFunc, generation string) (M, error) {
	inventory := readObj(filepath.Join(generation, "inventory.json"))
	sums := obj(inventory["archiveSHA256"])
	if inventory == nil || sums == nil {
		return nil, Public("The backup's Incus export inventory is missing")
	}
	for _, name := range keys(sums) {
		if !fullmatch(archiveRe, name) {
			return nil, Public("The Incus export inventory names an unexpected archive")
		}
		if digest, err := fileSHA256(filepath.Join(generation, name)); err != nil || digest != str(sums[name]) {
			return nil, Public("Incus export " + name + " is missing or damaged")
		}
	}
	// Refuse every collision before changing anything.
	pools := map[string]bool{}
	if out, err := incus(0, "storage", "list", "--format=json"); err == nil {
		for _, raw := range list(must(parseJSON([]byte(out)))) {
			pools[str(obj(raw)["name"])] = true
		}
	}
	for _, raw := range list(inventory["customVolumes"]) {
		v := obj(raw)
		if !pools[str(v["pool"])] {
			return nil, Public("Storage pool " + str(v["pool"]) + " does not exist on this host; create it first")
		}
		if incusQueryObj(incus, "/1.0/storage-pools/"+str(v["pool"])+"/volumes/custom/"+str(v["name"])+"?project="+str(v["project"])) != nil {
			return nil, Public("Volume " + str(v["project"]) + "/" + str(v["name"]) + " already exists on this host")
		}
	}
	for _, raw := range list(inventory["guests"]) {
		g := obj(raw)
		if incusQueryObj(incus, "/1.0/instances/"+str(g["name"])+"?project="+str(g["project"])) != nil {
			return nil, Public("Instance " + str(g["project"]) + "/" + str(g["name"]) + " already exists on this host")
		}
	}
	created := []any{}
	for _, raw := range list(inventory["projects"]) {
		p := obj(raw)
		name := str(p["name"])
		if name == "default" || incusQueryObj(incus, "/1.0/projects/"+name) != nil {
			continue
		}
		args := []string{"project", "create", name}
		config := obj(p["config"])
		for _, k := range keys(config) {
			args = append(args, "-c", k+"="+str(config[k]))
		}
		if _, err := incus(0, args...); err != nil {
			return nil, Failed("Could not recreate Incus project "+name, err)
		}
		created = append(created, name)
	}
	networks, err := restoreNetworks(incus, inventory)
	if err != nil {
		return nil, err
	}
	volumes, instances, started := []any{}, []any{}, []any{}
	for _, raw := range list(inventory["customVolumes"]) {
		v := obj(raw)
		if _, err := incus(0, "storage", "volume", "import", str(v["pool"]), filepath.Join(generation, str(v["archive"])), str(v["name"]),
			"--project", str(v["project"])); err != nil {
			return nil, Failed("Could not import volume "+str(v["name"]), err)
		}
		volumes = append(volumes, str(v["project"])+"/"+str(v["pool"])+"/"+str(v["name"]))
	}
	for _, raw := range list(inventory["guests"]) {
		g := obj(raw)
		if _, err := incus(0, "import", filepath.Join(generation, str(g["archive"])), str(g["name"]), "--project", str(g["project"])); err != nil {
			return nil, Failed("Could not import instance "+str(g["name"]), err)
		}
		instances = append(instances, str(g["project"])+"/"+str(g["name"]))
	}
	for _, raw := range list(inventory["guests"]) {
		g := obj(raw)
		if str(g["status"]) != "Running" {
			continue
		}
		if _, err := incus(0, "start", str(g["name"]), "--project", str(g["project"])); err != nil {
			return nil, Failed("Imported instance "+str(g["name"])+" did not start", err)
		}
		started = append(started, str(g["project"])+"/"+str(g["name"]))
	}
	return M{"generation": filepath.Base(generation), "projectsCreated": created, "networks": networks, "volumes": volumes,
		"instances": instances, "started": started}, nil
}

// restoreNetworks recreates managed bridge networks the exported instances use
// (incus-compose gives each project its own), in the project that owns them,
// without the host-specific volatile keys. Existing networks are kept.
func restoreNetworks(incus incusFunc, inventory M) ([]any, error) {
	ownNetworks := map[string]bool{}
	for _, raw := range list(inventory["projects"]) {
		p := obj(raw)
		if str(obj(p["config"])["features.networks"]) == "true" {
			ownNetworks[str(p["name"])] = true
		}
	}
	byProject := obj(inventory["networks"])
	created := []any{}
	seen := map[string]bool{}
	for _, project := range keys(byProject) {
		owner := "default"
		if ownNetworks[project] {
			owner = project
		}
		for _, raw := range list(byProject[project]) {
			n := obj(raw)
			name := str(n["name"])
			if !isTrue(n["managed"]) || str(n["type"]) != "bridge" || seen[owner+"/"+name] || !fullmatch(re(`[A-Za-z0-9][A-Za-z0-9_.-]{0,14}`), name) {
				continue
			}
			seen[owner+"/"+name] = true
			if incusQueryObj(incus, "/1.0/networks/"+name+"?project="+owner) != nil {
				continue
			}
			args := []string{"network", "create", name, "--type", "bridge", "--project", owner}
			config := obj(n["config"])
			for _, k := range keys(config) {
				if !strings.HasPrefix(k, "volatile.") {
					args = append(args, k+"="+str(config[k]))
				}
			}
			if _, err := incus(0, args...); err != nil {
				return nil, Failed("Could not recreate network "+name, err)
			}
			created = append(created, owner+"/"+name)
		}
	}
	return created, nil
}

func projectRestore(o restoreOptions) (M, error) {
	env, err := restoreEnv(o)
	if err != nil {
		return nil, err
	}
	snapshot := o.Snapshot
	if snapshot == "" {
		snapshot = "latest"
	}
	if snapshot != "latest" && !fullmatch(re(`[0-9a-f]{8,64}`), snapshot) {
		return nil, Public("Invalid restic snapshot identifier")
	}
	t := NewProjectTransactions("", "")
	if lexists(t.workspace) {
		return nil, Public("A project workspace already exists on this host; restore only onto an empty host")
	}
	os.MkdirAll(restoreRoot, 0o700)
	target := filepath.Join(restoreRoot, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.Mkdir(target, 0o700); err != nil {
		return nil, err
	}
	report := M{"format": 1, "startedAt": now(), "snapshot": snapshot, "repository": o.Repository, "status": "restoring"}
	writeReport := func() { writeJSONMode(filepath.Join(STATE, "project-restore-report.json"), report, 0o640, "") }
	writeReport()
	failWith := func(stage string, err error) (M, error) {
		report["status"], report["failedStage"], report["error"] = "failed", stage, publicError(err)
		writeReport()
		fmt.Fprintln(os.Stderr, "nixus: project restore failed at", stage+":", err)
		audit("project-restore-failed", M{"stage": stage})
		return report, err
	}
	args := []string{"restore", snapshot, "--target", target}
	if snapshot == "latest" {
		// Only a backup that fulfilled its policy is restored by default; a
		// partial one needs an explicit snapshot ID.
		args = append(args, "--tag", snapshotComplete)
	}
	if err := resticRun(env, 12*time.Hour, args...); err != nil {
		if snapshot == "latest" {
			return failWith("download", Public("No complete backup was found to restore. Choose a snapshot ID to restore a partial or older backup. "+publicError(err)))
		}
		return failWith("download", err)
	}
	config := findOne(target, "/config/", "MANIFEST.json")
	if config == "" {
		return failWith("download", Public("The snapshot holds no Nixus project configuration"))
	}
	manifest := readObj(filepath.Join(config, "MANIFEST.json"))
	files := obj(manifest["files"])
	for _, rel := range keys(files) {
		if _, err := verifiedRestoredFile(config, rel, str(files[rel])); err != nil {
			return failWith("verify", err)
		}
	}
	report["verifiedFiles"] = len(files)
	count, err := restoreWorkspace(t, config, files)
	if err != nil {
		return failWith("workspace", err)
	}
	report["workspaceFiles"] = count
	sources, err := restoreSources(config, manifest)
	if err != nil {
		return failWith("sources", err)
	}
	report["sources"] = sources
	keysReport, err := restoreKeys(target)
	if err != nil {
		return failWith("keys", err)
	}
	report["keys"] = keysReport
	report["host"] = restoreHost(config, files, keysReport)
	if generation := findOne(target, "/generations/", "inventory.json"); generation != "" {
		incusReport, err := restoreIncus(updateIncus, generation)
		if err != nil {
			return failWith("incus", err)
		}
		report["incus"] = incusReport
		if delivered, err := deliverAllSecrets(); err != nil {
			report["secretDelivery"] = M{"error": publicError(err)}
		} else {
			report["secretDelivery"] = delivered["projects"]
		}
	} else {
		report["incus"] = M{"skipped": "the snapshot holds no Incus data export"}
	}
	report["status"], report["completedAt"] = "restored", now()
	report["next"] = []any{
		"Redeploy each app from the Apps page so its images are rebuilt on this host.",
		"Check each app's data.",
	}
	writeReport()
	os.RemoveAll(target)
	audit("project-restore-completed", M{"sources": len(sources)})
	return report, nil
}

func projectRestoreCLI(args []string) error {
	fs := flag.NewFlagSet("project-backup restore", flag.ContinueOnError)
	var o restoreOptions
	fs.StringVar(&o.Repository, "repository", "", "restic repository")
	fs.StringVar(&o.PasswordFile, "password-file", "", "root-only restic password file")
	fs.StringVar(&o.RcloneConfig, "rclone-config", "", "rclone configuration file for rclone: repositories")
	fs.StringVar(&o.EnvironmentFile, "environment-file", "", "KEY=VALUE credentials for S3/B2")
	fs.StringVar(&o.Snapshot, "snapshot", "latest", "restic snapshot ID")
	if err := fs.Parse(args); err != nil {
		return Public("usage: nixus-admin project-backup restore --repository REPO --password-file FILE [--rclone-config FILE] [--snapshot ID]")
	}
	report, err := projectRestore(o)
	if report != nil {
		printJSON(report)
	}
	return err
}

// restoreKeys installs the age identities and backup credentials from the
// snapshot. Existing keys on this host are never replaced.
func restoreKeys(target string) (M, error) {
	report := M{}
	install := func(name, from, to string) error {
		data, err := os.ReadFile(from)
		if err != nil {
			return nil
		}
		if existing, err := os.ReadFile(to); err == nil {
			if string(existing) == string(data) {
				report[name] = "already present"
			} else {
				report[name] = "kept the existing one on this host"
			}
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			return err
		}
		if err := atomic(to, data, 0o600, ""); err != nil {
			return err
		}
		report[name] = "restored"
		return nil
	}
	// The projects identity goes through the normal enrollment checks.
	if data, err := os.ReadFile(filepath.Join(target, projectsIdentity)); err == nil {
		if lexists(projectsIdentity) {
			existing, _ := os.ReadFile(projectsIdentity)
			if string(existing) == string(data) {
				report["projectsIdentity"] = "already present"
			} else {
				report["projectsIdentity"] = "kept the existing one on this host"
			}
		} else if _, err := NewSecrets("", "", "").enrollIdentity("restore", "restore", strings.TrimSpace(string(data)), true); err != nil {
			return nil, err
		} else {
			report["projectsIdentity"] = "restored"
		}
	} else {
		report["projectsIdentity"] = "not in this backup"
	}
	if err := install("hostIdentity", filepath.Join(target, hostKeyFile), hostKeyFile); err != nil {
		return nil, err
	}
	credentials := filepath.Join(target, "/var/lib/nixus-secrets")
	entries, _ := os.ReadDir(credentials)
	for _, e := range entries {
		if e.Type().IsRegular() && fullmatch(re(`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`), e.Name()) {
			if err := install("credential:"+e.Name(), filepath.Join(credentials, e.Name()), filepath.Join("/var/lib/nixus-secrets", e.Name())); err != nil {
				return nil, err
			}
		}
	}
	return report, nil
}

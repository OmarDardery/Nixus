package main

// Allowlisted Incus guest operations and durable jobs; no browser shell or
// arbitrary paths.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const lastAppliedKey = "user.nixus.last-applied"

var operationActions = map[string]bool{"start": true, "stop": true, "restart": true, "snapshot": true, "snapshot-copy": true,
	"export": true, "restore": true, "backup": true, "backup-check": true, "release-restore": true}
var localName = re(`[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}`)
var hwaddrKey = re(`volatile\.[A-Za-z0-9_.-]+\.hwaddr`)

func opName(v any) (string, error) {
	s, ok := v.(string)
	if !ok || !fullmatch(localName, s) {
		return "", Public("Use a local project/instance/snapshot name without remote prefixes or paths")
	}
	return s, nil
}

func opIncus(timeout time.Duration, args ...string) (string, error) {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	out, err := incusRun(args, timeout, 4096)
	if err != nil {
		return "", Public("Incus operation failed")
	}
	return out, nil
}

func listGuests(projectArg any) ([]any, error) {
	project, err := opName(projectArg)
	if err != nil {
		return nil, err
	}
	out, err := opIncus(0, "list", "--project", project, "--format=json")
	if err != nil {
		return nil, err
	}
	items := list(must(parseJSON([]byte(out))))
	declared, _ := readJSON("/etc/nixus/desired-instances.json", []any{})
	result := []any{}
	for _, raw := range items {
		guest := obj(raw)
		addresses := []any{}
		for _, network := range obj(jget(guest, "state", "network")) {
			for _, a := range list(obj(network)["addresses"]) {
				if str(obj(a)["scope"]) == "global" {
					addresses = append(addresses, obj(a)["address"])
				}
			}
		}
		config := obj(guest["expanded_config"])
		if config == nil {
			config = obj(guest["config"])
		}
		drift := ""
		if str(jget(guest, "config", OWNER)) == "true" {
			for _, d := range list(declared) {
				spec := obj(d)
				if str(spec["project"]) == project && str(spec["name"]) == str(guest["name"]) {
					if update, err := reconcilePlan(guest, spec); err != nil {
						drift = publicError(err)
					} else if update != nil {
						drift = "Declared fields differ from runtime state"
					}
				}
			}
		}
		snapshots := []any{}
		for _, s := range list(guest["snapshots"]) {
			n := str(obj(s)["name"])
			snapshots = append(snapshots, n[strings.LastIndex(n, "/")+1:])
		}
		result = append(result, M{"name": guest["name"], "project": project, "type": guest["type"], "status": guest["status"],
			"addresses": addresses, "managed": str(config[OWNER]) == "true", "restoreReview": str(config["user.nixus.restore-review"]) == "required",
			"cpu": str(config["limits.cpu"]), "memory": str(config["limits.memory"]), "drift": drift, "snapshots": snapshots})
	}
	return result, nil
}

func incusInstance(project, guest string) (M, error) {
	out, err := opIncus(0, "query", instancePath(project, guest))
	if err != nil {
		return nil, err
	}
	return parseObject([]byte(out))
}

func resetRestoreMACs(project, guest string) error {
	current, err := incusInstance(project, guest)
	if err != nil {
		return err
	}
	if str(current["status"]) != "Stopped" {
		return Public("The restored instance must remain stopped while resetting generated NIC identities")
	}
	for _, k := range keys(obj(current["config"])) {
		if fullmatch(hwaddrKey, k) {
			if _, err := opIncus(0, "config", "unset", guest, k, "--project", project); err != nil {
				return err
			}
		}
	}
	return nil
}

func macAddresses(current M) map[string]bool {
	config := obj(current["expanded_config"])
	if config == nil {
		config = obj(current["config"])
	}
	out := map[string]bool{}
	for k, v := range config {
		if fullmatch(hwaddrKey, k) && str(v) != "" {
			out[strings.ToLower(str(v))] = true
		}
	}
	for _, d := range obj(current["expanded_devices"]) {
		dev := obj(d)
		if str(dev["type"]) == "nic" && str(dev["hwaddr"]) != "" {
			out[strings.ToLower(str(dev["hwaddr"]))] = true
		}
	}
	return out
}

func checkConfigIdle(state string) error {
	active := readObj(filepath.Join(state, "active.json"))
	id := str(active["id"])
	if id == "" {
		id = "-"
	}
	job, _ := readJobRecord(filepath.Join(state, "jobs", id, "job.json"), M{})
	pending, _ := readJSON(filepath.Join(state, "pending.json"), nil)
	switch str(job["status"]) {
	case "building", "applying", "awaiting-confirmation", "rolling-back":
		pending = true
	}
	if pending != nil && !equalJSON(pending, M{}) {
		return Public("Finish the configuration transaction before changing guest state")
	}
	if str(readObj(filepath.Join(state, "project-deploy-active.json"))["id"]) != "" {
		return Public("Finish or recover the project deployment before changing guest state")
	}
	return nil
}

type Operations struct{ root, state, directory string }

func NewOperations() *Operations {
	o := &Operations{ROOT, STATE, filepath.Join(STATE, "operations")}
	os.MkdirAll(o.directory, 0o700)
	return o
}

func (o *Operations) path(id string) (string, error) { return jobDirectory(o.directory, id, "operation") }

func (o *Operations) status(limit int) []any {
	entries, _ := os.ReadDir(o.directory)
	type item struct {
		mtime time.Time
		name  string
	}
	var items []item
	for _, e := range entries {
		info, err := os.Lstat(filepath.Join(o.directory, e.Name()))
		if err == nil {
			items = append(items, item{info.ModTime(), e.Name()})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mtime.After(items[j].mtime) })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	records := []any{}
	for _, it := range items {
		dir := filepath.Join(o.directory, it.name)
		if isSymlink(dir) || !isDir(dir) || !fullmatch(jobID, it.name) {
			continue
		}
		record, _ := readJobRecord(filepath.Join(dir, "job.json"), M{})
		created, _ := num(record["created"])
		if s := str(record["status"]); (s == "queued" || s == "running") && now()-created > 30 {
			if active, err := workerActive("nixus-operation-" + it.name); err == nil && !active {
				record["status"] = "failed"
				record["error"] = "Worker interrupted. Inspect guest state and recovery intent before retrying"
				writeJSON(filepath.Join(dir, "job.json"), record)
			}
		}
		records = append(records, record)
	}
	return records
}

func (o *Operations) archives() []any {
	result := []any{}
	for _, raw := range o.status(0) {
		job := obj(raw)
		if str(job["action"]) == "export" && str(job["status"]) == "complete" {
			available := false
			if p, err := o.archivePath(job, false); err == nil {
				available = isFile(p) && !isSymlink(p)
			}
			size := job["size"]
			if size == nil {
				size = 0
			}
			result = append(result, M{"id": job["id"], "name": job["name"], "project": job["project"], "available": available,
				"size": size, "sha256": job["sha256"], "created": job["created"]})
		}
	}
	for _, job := range o.generationArchives() {
		available := false
		if p, err := o.archivePath(job, false); err == nil {
			available = isFile(p)
		}
		item := M{"available": available}
		for _, k := range []string{"id", "name", "project", "sha256", "created", "generation"} {
			item[k] = job[k]
		}
		result = append(result, item)
	}
	return result
}

func (o *Operations) archiveSettings() (M, error) {
	settings := readObj("/etc/nixus/effective-settings.json")
	if len(settings) == 0 {
		settings = readObj(machinePath(o.root, "settings"))
	}
	staging := str(jget(settings, "backup", "stagingDirectory"))
	if staging == "" {
		return nil, Hidden("No backup settings")
	}
	var mount any
	for _, m := range list(settings["mounts"]) {
		if str(obj(m)["role"]) == "backup" {
			mount = m
			break
		}
	}
	return M{"archiveRoot": filepath.Join(staging, "on-demand"), "archiveMount": mount}, nil
}

var archiveFileRe = re(`instance-[0-9a-f]{64}\.tar\.gz`)

func (o *Operations) generationArchives() []M {
	settings, err := o.archiveSettings()
	if err != nil {
		return nil
	}
	root := filepath.Dir(str(settings["archiveRoot"]))
	var result []M
	for _, g := range backupGenerations(root) {
		generation := str(obj(g)["id"])
		manifest := readObj(filepath.Join(root, "generations", generation, "inventory.json"))
		for _, raw := range list(manifest["guests"]) {
			guest := obj(raw)
			filename := str(guest["archive"])
			if !fullmatch(archiveFileRe, filename) || !fullmatch(localName, str(guest["name"])) || !fullmatch(localName, str(guest["project"])) {
				continue
			}
			id := sha256str(generation + "\x00" + str(guest["project"]) + "\x00" + str(guest["name"]))[:32]
			result = append(result, M{"id": id, "name": guest["name"], "project": guest["project"], "generation": generation,
				"archiveFile": filename, "archiveRoot": root, "archiveMount": settings["archiveMount"],
				"sha256": obj(manifest["archiveSHA256"])[filename], "created": manifest["created"]})
		}
	}
	return result
}

func (o *Operations) archivePath(job M, create bool) (string, error) {
	if str(job["archiveRoot"]) == "" {
		dir, err := o.path(str(job["id"]))
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "guest.tar.gz"), nil
	}
	parent := str(job["archiveRoot"])
	if resolved, _ := filepath.EvalSymlinks(parent); !filepath.IsAbs(parent) || (exists(parent) && resolved != parent) {
		return "", Public("Archive storage cannot traverse symlinks")
	}
	if mount := obj(job["archiveMount"]); mount != nil {
		res, err := run([]string{"findmnt", "--mountpoint", str(mount["path"]), "--noheadings", "--output", "UUID"}, nil, 10*time.Second, nil, "")
		if err != nil || res.Code != 0 || !strings.EqualFold(strings.TrimSpace(string(res.Stdout)), str(mount["uuid"])) {
			return "", Public("The selected backup filesystem is missing or has the wrong UUID")
		}
	}
	if create {
		os.MkdirAll(parent, 0o700)
		info, err := os.Stat(parent)
		if err != nil || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
			return "", Public("Archive storage must be root-owned and not writable by other users")
		}
	}
	if generation := str(job["generation"]); generation != "" {
		if !fullmatch(generationRe, generation) || !fullmatch(archiveFileRe, str(job["archiveFile"])) {
			return "", Public("Invalid generation archive identity")
		}
		p := filepath.Join(parent, "generations", generation, str(job["archiveFile"]))
		if resolved, _ := filepath.EvalSymlinks(p); exists(p) && resolved != p {
			return "", Public("Generation archive cannot traverse symlinks")
		}
		return p, nil
	}
	return filepath.Join(parent, str(job["id"])+".tar.gz"), nil
}

func readSettingsFallback(root string) M {
	settings := readObj("/etc/nixus/effective-settings.json")
	if len(settings) == 0 {
		settings = readObj(machinePath(root, "settings"))
	}
	return settings
}

func (o *Operations) submit(request M, principal string) (M, error) {
	allowed := map[string]bool{"action": true, "project": true, "name": true, "snapshot": true, "target": true, "archive": true, "acknowledge": true}
	for k := range request {
		if !allowed[k] {
			return nil, Public("Unknown guest-operation fields")
		}
	}
	action := str(request["action"])
	if !operationActions[action] {
		return nil, Public("Unsupported guest operation")
	}
	projectArg, ok := request["project"]
	if !ok {
		projectArg = "lab"
	}
	project, err := opName(projectArg)
	if err != nil {
		return nil, err
	}
	nameArg := request["name"]
	if (action == "backup" || action == "backup-check") && nameArg == nil {
		nameArg = "all"
	}
	guest, err := opName(nameArg)
	if err != nil {
		return nil, err
	}
	settings := readSettingsFallback(o.root)
	if !isTrue(settings["ready"]) {
		return nil, Public("Complete host setup before managing guests")
	}
	if (action == "backup" || action == "backup-check") && !isTrue(jget(settings, "backup", "enable")) {
		return nil, Public("Configure an independent backup destination first")
	}
	switch action {
	case "stop", "restart", "export", "restore", "snapshot-copy", "release-restore", "backup":
		if !isTrue(request["acknowledge"]) {
			return nil, Public("Acknowledge downtime or isolated restore before running this operation")
		}
	}
	parameters := M{"action": action, "project": project, "name": guest}
	if action == "snapshot" || action == "snapshot-copy" {
		if parameters["snapshot"], err = opName(request["snapshot"]); err != nil {
			return nil, err
		}
	}
	if action == "restore" || action == "snapshot-copy" {
		target, err := opName(request["target"])
		if err != nil {
			return nil, err
		}
		if target == guest {
			return nil, Public("Restore to a new instance name")
		}
		parameters["target"] = target
	}
	if action == "restore" {
		archiveID := str(request["archive"])
		var known M
		for _, a := range o.archives() {
			if str(obj(a)["id"]) == archiveID {
				known = obj(a)
				break
			}
		}
		if known == nil || !isTrue(known["available"]) || str(known["project"]) != project || str(known["name"]) != guest {
			return nil, Public("Choose an existing completed export for this project and instance")
		}
		parameters["archive"] = archiveID
		for _, a := range o.generationArchives() {
			if str(a["id"]) == archiveID {
				parameters["archiveRecord"] = a
			}
		}
	}
	var id string
	err = locked(false, func() error {
		if err := checkConfigIdle(o.state); err != nil {
			return err
		}
		for _, j := range o.status(0) {
			if s := str(obj(j)["status"]); s == "queued" || s == "running" {
				return Public("Finish the active guest operation first")
			}
		}
		id = tokenHex(16)
		directory := filepath.Join(o.directory, id)
		if err := os.Mkdir(directory, 0o700); err != nil {
			return err
		}
		record := cloneM(parameters)
		record["id"], record["status"], record["created"], record["principal"] = id, "queued", now(), principal
		if action == "export" {
			extra, err := o.archiveSettings()
			if err != nil {
				return err
			}
			for k, v := range extra {
				record[k] = v
			}
		}
		if err := writeJSON(filepath.Join(directory, "job.json"), record); err != nil {
			return err
		}
		exe, _ := os.Executable()
		if _, err := check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-operation-" + id,
			"--property=RuntimeMaxSec=43200", "--setenv=NIXUS_ROOT=" + o.root, "--setenv=NIXUS_STATE=" + o.state,
			"--setenv=PATH=" + os.Getenv("PATH"), exe, "admin", "operation-job", id}, nil, time.Minute); err != nil {
			record["status"], record["error"] = "failed", "Could not start operation worker"
			writeJSON(filepath.Join(directory, "job.json"), record)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	audit("guest-operation-requested", M{"operation": id, "actionName": action, "project": project, "name": guest})
	return M{"id": id}, nil
}

func devicesOf(current M) M {
	if d := obj(current["expanded_devices"]); d != nil {
		return d
	}
	return M{}
}

func (o *Operations) perform(job M) (M, error) {
	if err := requireNormal(); err != nil {
		return nil, err
	}
	action := str(job["action"])
	project, err := opName(job["project"])
	if err != nil {
		return nil, err
	}
	guest, err := opName(job["name"])
	if err != nil {
		return nil, err
	}
	if action == "backup" || action == "backup-check" {
		unit := "restic-backups-nixus.service"
		if action == "backup-check" {
			unit = "nixus-backup-check.service"
		}
		_, err := check([]string{"systemctl", "start", unit}, nil, 43200*time.Second)
		return M{}, err
	}
	if action == "export" {
		os.MkdirAll(filepath.Dir(backupPending), 0o755)
		if err := backupRecover(); err != nil {
			return nil, err
		}
	}
	current := M{}
	if action != "restore" {
		if current, err = incusInstance(project, guest); err != nil {
			return nil, err
		}
	}
	if (action == "start" || action == "restart") && str(jget(current, "config", "user.nixus.restore-review")) == "required" {
		return nil, Public("Review restored networking, disks and credentials, then release the restore before starting it")
	}
	switch action {
	case "start", "stop", "restart":
		args := []string{action, guest, "--project", project}
		if action != "start" {
			args = append(args, "--timeout", "180")
		}
		_, err := opIncus(240*time.Second, args...)
		return M{}, err
	case "snapshot":
		_, err := opIncus(3600*time.Second, "snapshot", "create", guest, str(job["snapshot"]), "--project", project)
		return M{}, err
	case "restore", "snapshot-copy":
		target, err := opName(job["target"])
		if err != nil {
			return nil, err
		}
		existing, err := listGuests(project)
		if err != nil {
			return nil, err
		}
		for _, g := range existing {
			if str(obj(g)["name"]) == target {
				return nil, Public("Restore target already exists; no instance is overwritten")
			}
		}
		overrides := []string{"--config", "boot.autostart=false", "--config", OWNER + "=false", "--config", lastAppliedKey + "=",
			"--config", "user.nixus.restore-review=required"}
		if action == "snapshot-copy" {
			args := append([]string{"copy", guest + "/" + str(job["snapshot"]), target, "--project", project, "--stateless"}, overrides...)
			if _, err := opIncus(43200*time.Second, args...); err != nil {
				return nil, err
			}
		} else {
			archiveJob := obj(job["archiveRecord"])
			if archiveJob == nil {
				dir, err := o.path(str(job["archive"]))
				if err != nil {
					return nil, err
				}
				if archiveJob, err = readJobRecord(filepath.Join(dir, "job.json"), nil); err != nil {
					return nil, err
				}
			}
			archive, err := o.archivePath(archiveJob, false)
			if err != nil {
				return nil, err
			}
			digest, herr := fileSHA256(archive)
			if isSymlink(archive) || !isFile(archive) || herr != nil || digest != str(archiveJob["sha256"]) {
				return nil, Public("Export checksum changed; refusing import")
			}
			args := append([]string{"import", archive, target, "--project", project}, overrides...)
			if _, err := opIncus(43200*time.Second, args...); err != nil {
				return nil, err
			}
		}
		if err := resetRestoreMACs(project, target); err != nil {
			return nil, err
		}
		return M{"restoredInstance": target, "requiresReview": true}, nil
	case "release-restore":
		addresses := map[string]bool{}
		writable := map[string]bool{}
		for _, d := range devicesOf(current) {
			dev := obj(d)
			if a := str(dev["ipv4.address"]); a != "" {
				addresses[a] = true
			}
			if str(dev["type"]) == "disk" && str(dev["path"]) != "/" && str(dev["source"]) != "" && str(dev["readonly"]) != "true" {
				writable[str(dev["pool"])+"\x00"+str(dev["source"])] = true
			}
		}
		out, err := opIncus(0, "list", "--project", project, "--format=json")
		if err != nil {
			return nil, err
		}
		mine := macAddresses(current)
		for _, raw := range list(must(parseJSON([]byte(out)))) {
			other := obj(raw)
			if str(other["name"]) == guest {
				continue
			}
			for mac := range macAddresses(other) {
				if mine[mac] {
					return nil, Public("A restored MAC address conflicts with another instance; change the explicit NIC identity before release")
				}
			}
			for _, d := range devicesOf(other) {
				dev := obj(d)
				if a := str(dev["ipv4.address"]); a != "" && addresses[a] {
					return nil, Public("A restored fixed address conflicts with another instance; change its NIC configuration first")
				}
				if str(dev["type"]) == "disk" && str(dev["path"]) != "/" && str(dev["source"]) != "" && writable[str(dev["pool"])+"\x00"+str(dev["source"])] {
					return nil, Public("A writable restored data volume is shared with another instance; clone or detach it before release")
				}
			}
		}
		_, err = opIncus(0, "config", "set", guest, "user.nixus.restore-review=complete", "--project", project)
		return M{}, err
	case "export":
		target, err := o.archivePath(job, true)
		if err != nil {
			return nil, err
		}
		temporary := strings.TrimSuffix(target, ".tar.gz") + ".partial.tar.gz"
		status := str(current["status"])
		if status != "Running" && status != "Stopped" {
			return nil, Public("Export requires a running or stopped instance")
		}
		running := status == "Running"
		pending := []any{}
		if running {
			pending = append(pending, M{"name": guest, "project": project})
		}
		if err := saveRestartPending(pending); err != nil {
			return nil, err
		}
		defer func() {
			os.Remove(temporary)
			backupRecover()
		}()
		if running {
			if _, err := opIncus(240*time.Second, "stop", guest, "--project", project, "--timeout", "180"); err != nil {
				return nil, err
			}
		}
		if _, err := opIncus(43200*time.Second, "export", guest, temporary, "--project", project, "--compression", "gzip"); err != nil {
			return nil, err
		}
		info, err := os.Stat(temporary)
		if err != nil || info.Size() == 0 {
			return nil, Public("Export is empty")
		}
		os.Chmod(temporary, 0o600)
		if err := os.Rename(temporary, target); err != nil {
			return nil, err
		}
		digest, err := fileSHA256(target)
		if err != nil {
			return nil, err
		}
		final, _ := os.Stat(target)
		return M{"sha256": digest, "size": final.Size()}, nil
	}
	return M{}, nil
}

func (o *Operations) registerArchive(source, projectArg, guestArg string) (M, error) {
	abs, _ := filepath.Abs(source)
	resolved, _ := filepath.EvalSymlinks(abs)
	info, err := os.Stat(abs)
	if resolved != abs || err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, Public("Select a nonempty regular export file without symlink traversal")
	}
	project, err := opName(projectArg)
	if err != nil {
		return nil, err
	}
	guest, err := opName(guestArg)
	if err != nil {
		return nil, err
	}
	return lockedValue(false, func() (M, error) {
		if err := checkConfigIdle(o.state); err != nil {
			return nil, err
		}
		id := tokenHex(16)
		directory := filepath.Join(o.directory, id)
		if err := os.Mkdir(directory, 0o700); err != nil {
			return nil, err
		}
		job := M{"id": id, "action": "export", "project": project, "name": guest, "status": "importing", "created": now(), "principal": "root"}
		extra, err := o.archiveSettings()
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			job[k] = v
		}
		writeJSON(filepath.Join(directory, "job.json"), job)
		target, err := o.archivePath(job, true)
		if err != nil {
			return nil, err
		}
		temporary := strings.TrimSuffix(target, ".tar.gz") + ".partial.tar.gz"
		defer func() {
			os.Remove(temporary)
			writeJSON(filepath.Join(directory, "job.json"), job)
		}()
		err = func() error {
			if freeBytes(filepath.Dir(target)) < info.Size()+100<<20 {
				return Public("Insufficient free staging space for this archive")
			}
			in, err := os.Open(abs)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			out.Close()
			digest, err := fileSHA256(temporary)
			if err != nil {
				return err
			}
			if err := os.Rename(temporary, target); err != nil {
				return err
			}
			final, _ := os.Stat(target)
			job["status"], job["completed"], job["sha256"], job["size"] = "complete", now(), digest, final.Size()
			return nil
		}()
		if err != nil {
			job["status"], job["error"] = "failed", "Archive staging failed; original file was not modified"
			return nil, err
		}
		audit("guest-export-registered", M{"operation": id, "project": project, "name": guest})
		return job, nil
	})
}

func (o *Operations) run(id string) error {
	directory, err := o.path(id)
	if err != nil {
		return err
	}
	job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
	if err != nil {
		return err
	}
	if str(job["status"]) != "queued" {
		return Public("Operation was already executed")
	}
	job["status"], job["started"] = "running", now()
	writeJSON(filepath.Join(directory, "job.json"), job)
	defer func() {
		writeJSON(filepath.Join(directory, "job.json"), job)
		audit("guest-operation-finished", M{"operation": id, "status": job["status"]})
	}()
	perform := func() (M, error) {
		action := str(job["action"])
		if action == "backup" || action == "backup-check" {
			return o.perform(job)
		}
		return lockedValue(true, func() (M, error) {
			release, err := lockFile(incusLock, true)
			if err != nil {
				return nil, err
			}
			defer release()
			return o.perform(job)
		})
	}
	result, err := perform()
	if err != nil {
		msg := err.Error()
		if len(msg) > 4096 {
			msg = msg[len(msg)-4096:]
		}
		job["status"], job["completed"], job["error"] = "failed", now(), msg
		return err
	}
	job["status"], job["completed"] = "complete", now()
	for k, v := range result {
		job[k] = v
	}
	return nil
}

func (o *Operations) recoverInterrupted() {
	locked(false, func() error {
		release, err := lockFile(incusLock, false)
		if err != nil {
			return nil
		}
		defer release()
		for _, raw := range o.status(0) {
			record := obj(raw)
			if str(record["status"]) == "importing" {
				record["status"] = "failed"
				record["error"] = "Archive registration interrupted; register the original file again"
				if dir, err := o.path(str(record["id"])); err == nil {
					writeJSON(filepath.Join(dir, "job.json"), record)
				}
			}
			if str(record["action"]) == "export" && str(record["status"]) == "failed" {
				if p, err := o.archivePath(record, false); err == nil {
					os.Remove(strings.TrimSuffix(p, ".tar.gz") + ".partial.tar.gz")
				}
			}
		}
		var pending []any
		if raw, err := readJSON(backupPending, []any{}); err == nil {
			pending = list(raw)
		}
		if len(pending) > 0 {
			backupRecover()
		}
		return nil
	})
}

var _ = fmt.Sprint

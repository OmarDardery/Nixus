package main

// Portable configuration kits, separately encrypted secrets, bounded health
// diagnostics and offline-material recovery into a stopped quarantine project.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

var healthUnits = []string{"incus.service", "incus-preseed.service", "nixus-kvm-check.service", "nixus-instances.service",
	"cockpit.socket", "cockpit.service", "nginx.service", "nixus-admin-backend.service", "nixus-ui.service",
	"restic-backups-nixus.service", "nixus-storage.target", "nixus-rollback-guard.service", "smartd.service"}

func effectiveSettingsFile() M {
	if v, err := readJSON("/etc/nixus/effective-settings.json", nil); err == nil && obj(v) != nil {
		return obj(v)
	}
	return readObj(machinePath(ROOT, "settings"))
}

func health() M {
	result := M{"checkedAt": int(now()), "release": upgradeMetadata(ROOT), "lastBackupSuccess": nil, "clock": clockStatus(now())}
	services := []any{}
	for _, unit := range healthUnits {
		services = append(services, systemctlShow(unit, "Id,LoadState,ActiveState,SubState,Result,ExecMainStatus"))
	}
	result["services"] = services
	certificates := M{}
	for _, name := range []string{"tls.crt", "ca.crt"} {
		p := filepath.Join(STATE, name)
		if !isFile(p) {
			certificates[name] = M{"present": false}
			continue
		}
		end, _ := run([]string{"openssl", "x509", "-in", p, "-noout", "-enddate"}, nil, 10*time.Second, nil, "")
		soon, _ := run([]string{"openssl", "x509", "-in", p, "-noout", "-checkend", "2592000"}, nil, 10*time.Second, nil, "")
		certificates[name] = M{"present": true, "expires": strings.TrimSpace(string(end.Stdout)), "expiresWithin30Days": soon.Code != 0}
	}
	result["certificates"] = certificates
	if raw, err := os.ReadFile("/var/lib/nixus/last-backup-success"); err == nil {
		if v, ok := intValue(strings.TrimSpace(string(raw))); ok {
			result["lastBackupSuccess"] = v
		}
	}
	pending, _ := readJSON("/var/lib/nixus/restart-pending.json", []any{})
	result["guestsAwaitingRestart"] = len(list(pending))
	var fs syscall.Statfs_t
	if syscall.Statfs("/", &fs) == nil {
		result["rootStorage"] = M{"totalBytes": int64(fs.Blocks) * fs.Frsize, "availableBytes": int64(fs.Bavail) * fs.Frsize}
	} else {
		result["rootStorage"] = nil
	}
	status := readObj("/var/lib/nixus/backup-status.json")
	backup := M{}
	for _, k := range []string{"phase", "updated", "generation", "group", "groups", "members", "excluded", "coverage", "capacity", "restore"} {
		if v, ok := status[k]; ok {
			backup[k] = v
		}
	}
	settings := effectiveSettingsFile()
	enabled := isTrue(jget(settings, "backup", "enable"))
	backup["health"] = backupHealth(enabled)
	backup["verification"] = verificationStatus(enabled, "", "", str(jget(settings, "backup", "repository")))
	result["backup"] = backup
	return result
}

// secretSource follows configured SOPS links, then returns the regular target.
func secretSource(p string) string {
	source, _ := filepath.Abs(p)
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return ""
	}
	info, err := os.Lstat(source)
	if err != nil || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return ""
	}
	owner := func(uid uint32) bool { return uid == 0 || int(uid) == os.Geteuid() }
	for _, start := range []string{source, resolved} {
		for parent := filepath.Dir(start); ; parent = filepath.Dir(parent) {
			l, err1 := os.Lstat(parent)
			s, err2 := os.Stat(parent)
			if err1 != nil || err2 != nil {
				return ""
			}
			st := s.Sys().(*syscall.Stat_t)
			if !owner(l.Sys().(*syscall.Stat_t).Uid) || !owner(st.Uid) || (st.Mode&0o022 != 0 && st.Mode&0o1000 == 0) {
				return ""
			}
			if parent == "/" {
				break
			}
		}
	}
	s, err := os.Stat(resolved)
	if err == nil && s.Mode().IsRegular() && int(s.Sys().(*syscall.Stat_t).Uid) == os.Geteuid() && s.Mode().Perm()&0o022 == 0 {
		return resolved
	}
	return ""
}

func secretFiles() map[string]string {
	files := map[string]string{}
	for _, name := range []string{"auth.json", "users.json", "bootstrap-state.json", "browser-certificates.json", "ca.key", "ca.crt", "tls.key", "tls.crt"} {
		files["admin/"+name] = filepath.Join(STATE, name)
	}
	for name, p := range SECRET_PATHS {
		files["runtime/"+name] = p
	}
	configured := effectiveSettingsFile()
	for _, pair := range [][2]string{{"backup", "passwordFile"}, {"backup", "environmentFile"}, {"tunnel", "credentialsFile"}} {
		if v := str(jget(configured, pair[0], pair[1])); v != "" {
			files["runtime/"+pair[0]+"-"+pair[1]] = v
		}
	}
	if hook := str(readObj("/etc/nixus/notification-settings.json")["webhookFile"]); hook != "" {
		files["runtime/notification-url"] = hook
	}
	key := str(jget(configured, "secrets", "ageKeyFile"))
	if key == "" {
		key = "/var/lib/sops-nix/key.txt"
	}
	if isFile(key) {
		files["sops/age-key.txt"] = key
	}
	filepath.WalkDir("/var/lib/nixus-secrets", func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			rel, _ := filepath.Rel("/var/lib/nixus-secrets", p)
			files["runtime-files/"+rel] = p
		}
		return nil
	})
	for _, parent := range []string{"/etc/NetworkManager/system-connections", "/run/NetworkManager/system-connections"} {
		matches, _ := filepath.Glob(filepath.Join(parent, "*.nmconnection"))
		for _, p := range matches {
			files["network/"+filepath.Base(p)] = p
		}
	}
	result := map[string]string{}
	for name, p := range files {
		if s := secretSource(p); s != "" {
			result[name] = s
		}
	}
	return result
}

func recoveryCoverage() M {
	configured := effectiveSettingsFile()
	required := map[string]string{}
	for _, pair := range [][2]string{{"backup", "passwordFile"}, {"backup", "environmentFile"}, {"tunnel", "credentialsFile"}} {
		if v := str(jget(configured, pair[0], pair[1])); v != "" && isTrue(jget(configured, pair[0], "enable")) {
			required[pair[0]+"-"+pair[1]] = v
		}
	}
	if isTrue(jget(configured, "secrets", "enable")) {
		key := str(jget(configured, "secrets", "ageKeyFile"))
		if key == "" {
			key = "/var/lib/sops-nix/key.txt"
		}
		required["sops-age-key"] = key
	}
	if isTrue(jget(configured, "setup", "enable")) {
		for _, name := range []string{"ca.key", "ca.crt", "tls.key", "tls.crt"} {
			required["management-"+name] = filepath.Join(STATE, name)
		}
		account := "auth.json"
		if exists(filepath.Join(STATE, "users.json")) {
			account = "users.json"
		}
		required["management-account"] = filepath.Join(STATE, account)
		if registry := filepath.Join(STATE, "browser-certificates.json"); lexists(registry) {
			required["browser-identity-ownership"] = registry
		}
	}
	files := secretFiles()
	archived := map[string]bool{}
	for _, p := range files {
		archived[p] = true
	}
	missing := []string{}
	for name, p := range required {
		if s := secretSource(p); s == "" || !archived[s] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return M{"format": 1, "complete": len(missing) == 0, "missing": strings2any(missing),
		"included": strings2any(sortedKeys(boolSet(files))), "restore": "unverified"}
}

func writeRecoveryArchive(w io.Writer, files map[string]string, kind string) error {
	manifest := M{"format": 1, "kind": kind, "created": now(), "release": upgradeMetadata(ROOT)}
	hashes := M{}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	if len(files) >= 10000 {
		return Public("Recovery kit has too many files")
	}
	var total int64
	for _, name := range sortedKeys(boolSet(files)) {
		p := files[name]
		if !isFile(p) || isSymlink(p) {
			return Public("Recovery source changed or is a symlink")
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		data, _ := io.ReadAll(io.LimitReader(f, 16<<20+1))
		f.Close()
		total += int64(len(data))
		if len(data) > 16<<20 || total > 100<<20 {
			return Public("Recovery kit exceeds size limits")
		}
		hashes[name] = sha256hex(data)
		tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0o600, Typeflag: tar.TypeReg, Format: tar.FormatGNU})
		tw.Write(data)
	}
	manifest["files"] = hashes
	body := jsonFile(manifest)
	tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(body)), Mode: 0o600, Typeflag: tar.TypeReg, Format: tar.FormatGNU})
	tw.Write(body)
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

var ageRecipientLoose = re(`age1[0-9a-z]{50,100}`)

func recoveryExport(directory, recipient string, includeSecrets bool) (M, error) {
	if includeSecrets && !fullmatch(ageRecipientLoose, recipient) {
		return nil, Public("Supply an age public recipient for the separate secret archive")
	}
	directory, _ = filepath.Abs(directory)
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(directory)); err == nil && filepath.Join(resolved, filepath.Base(directory)) != directory {
		return nil, Public("Recovery destination cannot traverse symlinks")
	}
	if isSymlink(directory) {
		return nil, Public("Recovery destination cannot traverse symlinks")
	}
	os.MkdirAll(directory, 0o700)
	info, err := os.Stat(directory)
	if err != nil || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		return nil, Public("Recovery destination must be owned by root and not writable by other users")
	}
	config := filepath.Join(directory, "nixus-config.tar.gz")
	sources, err := sourceFiles(ROOT)
	if err != nil {
		return nil, err
	}
	files := map[string]string{}
	for _, f := range sources {
		if f.name != ".nixus-files.json" {
			files["config/"+f.name] = f.path
		}
	}
	var buf bytes.Buffer
	if err := writeRecoveryArchive(&buf, files, "configuration"); err != nil {
		return nil, err
	}
	if err := atomic(config, buf.Bytes(), 0o600, ""); err != nil {
		return nil, err
	}
	result := M{"configuration": config, "sha256": sha256hex(buf.Bytes())}
	if includeSecrets {
		output := filepath.Join(directory, "nixus-secrets.tar.gz.age")
		os.Remove(output)
		cmd := exec.Command("age", "--encrypt", "--recipient", recipient, "--output", output)
		stdin, _ := cmd.StdinPipe()
		if err := cmd.Start(); err != nil {
			return nil, Public("Secret encryption failed; verify the age recipient and retry")
		}
		werr := writeRecoveryArchive(stdin, secretFiles(), "secrets")
		stdin.Close()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		var cerr error
		select {
		case cerr = <-done:
		case <-time.After(60 * time.Second):
			cmd.Process.Kill()
			cerr = <-done
		}
		if werr != nil || cerr != nil {
			os.Remove(output)
			if werr != nil {
				return nil, werr
			}
			return nil, Public("Secret encryption failed; verify the age recipient and retry")
		}
		os.Chmod(output, 0o600)
		result["encryptedSecrets"] = output
	}
	return result, nil
}

// recoveryBackup runs under the backup prepare lock; restic encrypts off-host.
func recoveryBackup(directory string) error {
	if !isTrue(recoveryCoverage()["complete"]) {
		return Public("Required recovery credentials are missing or unsafe; run nixus-admin recovery coverage")
	}
	if _, err := recoveryExport(directory, "", false); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := writeRecoveryArchive(&buf, secretFiles(), "secrets"); err != nil {
		return err
	}
	return atomic(filepath.Join(directory, "nixus-secrets.tar.gz"), buf.Bytes(), 0o600, "")
}

var recoveryRoots = map[string]bool{"config": true, "admin": true, "runtime": true, "runtime-files": true, "sops": true, "network": true}

func recoveryInspect(archive string) (M, map[string][]byte, error) {
	unsafe := Public("Recovery kit contains unsafe paths, types, duplicates or excessive data")
	f, err := os.Open(archive)
	if err != nil {
		return nil, nil, Public("Recovery kit unavailable")
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, unsafe
	}
	tr := tar.NewReader(gz)
	entries := map[string][]byte{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, unsafe
		}
		clean := filepath.ToSlash(filepath.Clean(h.Name))
		total += h.Size
		_, dup := entries[h.Name]
		if (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA) || clean != h.Name || strings.HasPrefix(h.Name, "/") ||
			strings.Contains("/"+h.Name+"/", "/../") || dup || len(entries) >= 10000 || total > 100<<20 {
			return nil, nil, unsafe
		}
		if h.Name != "manifest.json" && !recoveryRoots[strings.SplitN(h.Name, "/", 2)[0]] {
			return nil, nil, Public("Unexpected recovery member")
		}
		data, _ := io.ReadAll(io.LimitReader(tr, h.Size))
		entries[h.Name] = data
	}
	raw, ok := entries["manifest.json"]
	if !ok {
		return nil, nil, Public("Recovery manifest missing")
	}
	delete(entries, "manifest.json")
	manifest, err := parseObject(raw)
	if kind := str(manifest["kind"]); err != nil || !equalJSON(manifest["format"], 1) || (kind != "configuration" && kind != "secrets") {
		return nil, nil, Public("Unsupported recovery kit format")
	}
	hashes := M{}
	for name, data := range entries {
		hashes[name] = sha256hex(data)
	}
	if !equalJSON(hashes, manifest["files"]) {
		return nil, nil, Public("Recovery kit checksum mismatch")
	}
	return manifest, entries, nil
}

func recoveryStage(archive, destination string) (M, error) {
	destination, _ = filepath.Abs(destination)
	if lexists(destination) {
		return nil, Public("Recovery staging destination must not exist")
	}
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(destination)); err != nil || filepath.Join(resolved, filepath.Base(destination)) != destination {
		return nil, Public("Recovery staging cannot traverse symlinks")
	}
	manifest, entries, err := recoveryInspect(archive)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return nil, err
	}
	for name, data := range entries {
		if err := atomic(filepath.Join(destination, name), data, 0o600, ""); err != nil {
			return nil, err
		}
	}
	return manifest, writeJSON(filepath.Join(destination, "manifest.json"), manifest)
}

func recoveryDownload(recipient string) (M, error) {
	return lockedValue(false, func() (M, error) {
		folder, err := os.MkdirTemp(STATE, "recovery-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(folder)
		result, err := recoveryExport(folder, recipient, recipient != "")
		if err != nil {
			return nil, err
		}
		config, _ := os.ReadFile(str(result["configuration"]))
		if recipient == "" {
			return M{"files": M{"nixus-config.tar.gz": base64.StdEncoding.EncodeToString(config)}}, nil
		}
		secrets, _ := os.ReadFile(str(result["encryptedSecrets"]))
		var envelope bytes.Buffer
		tw := tar.NewWriter(&envelope)
		for _, item := range []struct {
			name string
			data []byte
		}{{"nixus-config.tar.gz", config}, {"nixus-secrets.tar.gz.age", secrets}} {
			tw.WriteHeader(&tar.Header{Name: item.name, Size: int64(len(item.data)), Mode: 0o600, Typeflag: tar.TypeReg, Format: tar.FormatGNU})
			tw.Write(item.data)
		}
		tw.Close()
		return M{"files": M{"nixus-recovery-kit.tar": base64.StdEncoding.EncodeToString(envelope.Bytes())}}, nil
	})
}

// --- replacement-host recovery -------------------------------------------------

const recoveryModeFile = "/etc/nixus/recovery-mode"
const recoveryToken = "user.nixus.recovery-id"

func replacementJournal() string { return filepath.Join(STATE, "replacement-recovery.json") }

func boundedJSON(p string) (any, error) {
	p, _ = filepath.Abs(p)
	resolved, err := filepath.EvalSymlinks(p)
	info, err2 := os.Stat(p)
	if err != nil || err2 != nil || resolved != p || !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return nil, Public("Expected a bounded regular JSON file without symlinks")
	}
	raw, _ := os.ReadFile(p)
	v, err := parseJSON(raw)
	if err != nil {
		return nil, Public("Expected a bounded regular JSON file without symlinks")
	}
	return v, nil
}

var recoveryArchive = re(`(?:instance-[0-9a-f]{64}|volume-[0-9a-f]{64}|nixus-config|nixus-secrets)\.tar\.gz`)

func recoveryMaterial(directory string) (string, M, error) {
	directory, _ = filepath.Abs(directory)
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory || !isDir(directory) {
		return "", nil, Public("Recovery material cannot traverse symlinks")
	}
	info, _ := os.Stat(directory)
	if int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Mode().Perm()&0o077 != 0 {
		return "", nil, Public("Recovery material must be owned by root in a mode-0700 directory")
	}
	for parent := filepath.Dir(directory); ; parent = filepath.Dir(parent) {
		s, _ := os.Stat(parent)
		st := s.Sys().(*syscall.Stat_t)
		if (st.Uid != 0 && int(st.Uid) != os.Geteuid()) || (st.Mode&0o022 != 0 && st.Mode&0o1000 == 0) {
			return "", nil, Public("Recovery material has an untrusted or writable parent directory")
		}
		if parent == "/" {
			break
		}
	}
	trusted := func(p string) bool {
		s, err := os.Lstat(p)
		return err == nil && s.Mode().IsRegular() && int(s.Sys().(*syscall.Stat_t).Uid) == os.Geteuid() && s.Mode().Perm()&0o022 == 0
	}
	inventoryFile := filepath.Join(directory, "inventory.json")
	if !trusted(inventoryFile) {
		return "", nil, Public("Recovery inventory must be root-owned and not writable by others")
	}
	raw, err := boundedJSON(inventoryFile)
	if err != nil {
		return "", nil, err
	}
	inventory := obj(raw)
	checksums := obj(inventory["archiveSHA256"])
	if !equalJSON(inventory["format"], 2) || checksums == nil {
		return "", nil, Public("Use a complete version-2 backup generation with archive checksums")
	}
	for name, expected := range checksums {
		if !fullmatch(recoveryArchive, name) {
			return "", nil, Public("Unsupported recovery archive name")
		}
		p := filepath.Join(directory, name)
		digest, _ := fileSHA256(p)
		if !trusted(p) || !fullmatch(sha64, str(expected)) || digest != str(expected) {
			return "", nil, Public("Recovery archive missing or checksum mismatch")
		}
	}
	for _, name := range []string{"nixus-config.tar.gz", "nixus-secrets.tar.gz"} {
		if _, ok := checksums[name]; !ok {
			return "", nil, Public("Recovery generation lacks configuration/secrets; provide independent recovery material first")
		}
		if _, _, err := recoveryInspect(filepath.Join(directory, name)); err != nil {
			return "", nil, err
		}
	}
	return directory, inventory, nil
}

var sha64 = re(`[0-9a-f]{64}`)

func recoveryAPI(p string) (any, error) {
	out, err := opIncus(0, "query", p)
	if err != nil {
		return nil, err
	}
	return parseJSON([]byte(out))
}

func recoveryAPIObj(p string) M {
	v, _ := recoveryAPI(p)
	return obj(v)
}

func q(s string) string { return url.PathEscape(s) }

func rProjectPath(project string) string { return "/1.0/projects/" + q(project) }
func rGuestPath(project, name string) string {
	return "/1.0/instances/" + q(name) + "?project=" + url.QueryEscape(project)
}
func rVolumePath(project, pool, name string) string {
	return "/1.0/storage-pools/" + q(pool) + "/volumes/custom/" + q(name) + "?project=" + url.QueryEscape(project)
}

func collectionHas(p, name string) (bool, error) {
	v, err := recoveryAPI(p)
	if err != nil {
		return false, err
	}
	for _, item := range list(v) {
		if str(obj(item)["name"]) == name {
			return true, nil
		}
	}
	return false, nil
}

func recoveryIdentifier(kind string, parts ...string) string {
	return kind + "-" + sha256hex([]byte(canonicalSpaced(strings2any(parts))))[:16]
}

func poolFingerprint(pool M) string {
	return sha256hex([]byte(canonicalSpaced(M{"driver": pool["driver"], "config": pool["config"]})))
}

func replacementPlan(directory string, mapping M) (M, error) {
	if exists(replacementJournal()) {
		return nil, Public("A recovery journal already exists; inspect status and resume it")
	}
	directory, inventory, err := recoveryMaterial(directory)
	if err != nil {
		return nil, err
	}
	if !exactKeys(mapping, "pool", "interfaces", "disks") {
		return nil, Public("Mappings require pool, interfaces and disks; preserve replacement boot/storage configuration")
	}
	pool, err := opName(mapping["pool"])
	if err != nil {
		return nil, err
	}
	for kind, parent := range map[string]string{"interfaces": "/sys/class/net", "disks": "/dev/disk/by-uuid"} {
		m, ok := mapping[kind].(M)
		if !ok {
			return nil, Public("Mapped replacement interfaces/disks must exist on this host")
		}
		for _, v := range m {
			n, ok := v.(string)
			if !ok || strings.Contains(n, "/") || n == "" || n == "." || n == ".." || !exists(filepath.Join(parent, n)) {
				return nil, Public("Mapped replacement interfaces/disks must exist on this host")
			}
		}
	}
	poolState := recoveryAPIObj("/1.0/storage-pools/" + q(pool))
	switch str(poolState["driver"]) {
	case "dir", "zfs", "btrfs", "lvm":
	default:
		return nil, Public("This recovery increment supports local dir/zfs/btrfs/lvm pools; review other backends manually")
	}
	id := tokenHex(16)
	project, bridge := "recovery-"+id[:12], "nlr-"+id[:10]
	p1, err1 := collectionHas("/1.0/projects?recursion=1", project)
	n1, err2 := collectionHas("/1.0/networks?recursion=1", bridge)
	if err1 != nil || err2 != nil || p1 || n1 {
		return nil, Public("Quarantine name collision; no existing resource is adopted")
	}
	namespaces := map[string]string{}
	for _, p := range list(inventory["projects"]) {
		pm := obj(p)
		namespaces[str(pm["name"])] = "default"
		if str(jget(pm, "config", "features.storage.volumes")) == "true" {
			namespaces[str(pm["name"])] = str(pm["name"])
		}
	}
	checksums := obj(inventory["archiveSHA256"])
	volumes := []any{}
	for _, raw := range list(inventory["customVolumes"]) {
		v := obj(raw)
		for _, k := range []string{"project", "pool", "name"} {
			if _, err := opName(v[k]); err != nil {
				return nil, err
			}
		}
		if _, ok := checksums[str(v["archive"])]; !ok {
			return nil, Public("Volume archive is not checksummed")
		}
		volumes = append(volumes, M{"project": v["project"], "pool": v["pool"], "name": v["name"], "archive": v["archive"],
			"target": recoveryIdentifier("volume", str(v["project"]), str(v["pool"]), str(v["name"]))})
	}
	guests := []any{}
	profiles := map[string]bool{"default": true}
	seen := map[string]bool{}
	for _, raw := range list(inventory["guests"]) {
		g := obj(raw)
		for _, k := range []string{"project", "name"} {
			if _, err := opName(g[k]); err != nil {
				return nil, err
			}
		}
		if _, ok := checksums[str(g["archive"])]; !ok {
			return nil, Public("Guest archive is not checksummed")
		}
		if t := str(g["type"]); t != "container" && t != "virtual-machine" {
			return nil, Public("Unsupported guest type")
		}
		config := obj(g["expanded_config"])
		if _, ok := g["expanded_config"]; !ok {
			config = obj(g["config"])
		}
		for k, v := range config {
			if (k == "security.privileged" && str(v) == "true") || (strings.HasPrefix(k, "raw.") && str(v) != "") {
				return nil, Public("Privileged/raw guest settings require a separate recovery review")
			}
		}
		devices := obj(g["expanded_devices"])
		if _, ok := g["expanded_devices"]; !ok {
			devices = obj(g["devices"])
		}
		hasRoot := false
		imported := M{}
		for name, rawDevice := range devices {
			if _, err := opName(name); err != nil {
				return nil, err
			}
			d := obj(rawDevice)
			typ := str(d["type"])
			switch {
			case typ == "disk" && str(d["path"]) == "/":
				hasRoot = true
				if str(d["source"]) != "" {
					return nil, Public("Raw root-disk sources require a separate recovery review")
				}
				c := cloneM(d)
				c["pool"] = pool
				imported[name] = c
			case typ == "nic" && str(d["network"]) != "", typ == "none":
				imported[name] = M{"type": "none"}
			case typ == "disk" && str(d["pool"]) != "" && str(d["source"]) != "":
				ns := namespaces[str(g["project"])]
				if ns == "" {
					ns = "default"
				}
				identity := ns + "\x00" + str(d["pool"]) + "\x00" + strings.TrimPrefix(str(d["source"]), "custom/")
				var target string
				for _, rv := range volumes {
					v := obj(rv)
					if str(v["project"])+"\x00"+str(v["pool"])+"\x00"+str(v["name"]) == identity {
						target = str(v["target"])
					}
				}
				if target == "" {
					return nil, Public("Attached custom volume is missing from recovery coverage")
				}
				c := cloneM(d)
				c["pool"], c["source"] = pool, target
				imported[name] = c
			default:
				return nil, Public("External disks, unmanaged NICs and passthrough require a separate recovery review")
			}
		}
		if !hasRoot {
			return nil, Public("Guest root storage information is incomplete")
		}
		for _, p := range list(g["profiles"]) {
			n, err := opName(p)
			if err != nil {
				return nil, err
			}
			profiles[n] = true
		}
		key := str(g["project"]) + "/" + str(g["name"])
		if seen[key] {
			return nil, Public("Duplicate recovery identities are not supported")
		}
		seen[key] = true
		guests = append(guests, M{"project": g["project"], "name": g["name"], "archive": g["archive"],
			"target": recoveryIdentifier("guest", str(g["project"]), str(g["name"])), "devices": imported, "originalDevices": devices})
	}
	if len(guests) == 0 {
		return nil, Public("No recoverable guests are present")
	}
	targets := map[string]bool{}
	for _, v := range volumes {
		targets[str(obj(v)["target"])] = true
	}
	if len(targets) != len(volumes) {
		return nil, Public("Duplicate recovery identities are not supported")
	}
	configuration, files, err := recoveryInspect(filepath.Join(directory, "nixus-config.tar.gz"))
	if err != nil {
		return nil, err
	}
	sourceRevision := str(jget(configuration, "release", "revision"))
	if !fullmatch(sha40, sourceRevision) {
		sourceRevision = "unknown"
	}
	sourceInputs := "unknown"
	if lock, ok := files["config/flake.lock"]; ok {
		sourceInputs = digestJSON(strings.TrimSpace(string(lock)))
	}
	inventoryDigest, _ := fileSHA256(filepath.Join(directory, "inventory.json"))
	_, hasDetails := inventory["coverageDetails"]
	assessment := "unknown-legacy"
	if hasDetails {
		assessment = "source-inventory"
	}
	record := M{"format": 1, "id": id, "phase": "planned", "created": now(), "source": directory, "inventorySHA256": inventoryDigest,
		"mapping": mapping, "poolFingerprint": poolFingerprint(poolState), "project": project, "bridge": bridge,
		"profiles": strings2any(sortedKeys(profiles)), "guests": guests, "volumes": volumes, "completed": []any{}, "running": nil,
		"coverage":      M{"complete": jget(inventory, "coverageDetails", "complete") == true, "assessment": assessment},
		"backupCreated": inventory["created"], "restore": "unverified", "sourceRevision": sourceRevision, "sourceInputsDigest": sourceInputs}
	if err := writeJSON(replacementJournal(), record); err != nil {
		return nil, err
	}
	return replacementStatus(record)
}

func loadJournal() (M, error) {
	v, err := boundedJSON(replacementJournal())
	if err != nil {
		return nil, err
	}
	return obj(v), nil
}

func replacementStatus(record M) (M, error) {
	if record == nil {
		var err error
		if record, err = loadJournal(); err != nil {
			return nil, err
		}
	}
	out := M{}
	for _, k := range []string{"format", "id", "phase", "created", "project", "bridge", "mapping", "completed", "running", "coverage",
		"backupCreated", "restore", "durationSeconds", "error", "sourceRevision", "sourceInputsDigest"} {
		out[k] = record[k]
	}
	guests, volumes := []any{}, []any{}
	for _, g := range list(record["guests"]) {
		gm := obj(g)
		guests = append(guests, M{"source": str(gm["project"]) + "/" + str(gm["name"]), "target": gm["target"]})
	}
	for _, v := range list(record["volumes"]) {
		vm := obj(v)
		volumes = append(volumes, M{"source": str(vm["project"]) + "/" + str(vm["pool"]) + "/" + str(vm["name"]), "target": vm["target"]})
	}
	out["guests"], out["volumes"] = guests, volumes
	return out, nil
}

// replacementReport shares provenance without guest names or hardware IDs.
func replacementReport() (M, error) {
	record, err := loadJournal()
	if err != nil {
		return nil, err
	}
	evidence := "unverified"
	if str(record["phase"]) == "complete" {
		evidence = "operator-attestation"
	}
	out := M{"format": 1, "evidenceType": evidence, "coverage": M{"complete": jget(record, "coverage", "complete") == true}}
	for _, k := range []string{"phase", "restore", "sourceRevision", "sourceInputsDigest", "backupCreated", "verifiedAt", "durationSeconds"} {
		out[k] = record[k]
	}
	return out, nil
}

func recoveryEdit(args []string, document M) error {
	res, err := run(append([]string{"incus", "--force-local"}, args...), []byte(canonicalSpaced(document)), 60*time.Second, nil, "")
	if err != nil || res.Code != 0 {
		return Public("Recovery metadata edit failed; inspect the stopped target locally")
	}
	return nil
}

func replacementResume(confirmed bool) (M, error) {
	if !confirmed {
		return nil, Public("Explicit --confirm is required for recovery imports")
	}
	if raw, err := os.ReadFile(recoveryModeFile); err != nil || strings.TrimSpace(string(raw)) != "1" {
		return nil, Public("Enable nixus.recovery.enable on the replacement host before importing")
	}
	record, err := loadJournal()
	if err != nil {
		return nil, err
	}
	if str(record["phase"]) == "complete" {
		return nil, Public("Recovery was released; no imports are repeated")
	}
	source, _, err := recoveryMaterial(str(record["source"]))
	if err != nil {
		return nil, err
	}
	if d, _ := fileSHA256(filepath.Join(source, "inventory.json")); d != str(record["inventorySHA256"]) {
		return nil, Public("Recovery inventory changed; inspect the journal and original material")
	}
	pool := str(jget(record, "mapping", "pool"))
	if poolFingerprint(recoveryAPIObj("/1.0/storage-pools/"+q(pool))) != str(record["poolFingerprint"]) {
		return nil, Public("Replacement pool configuration changed after review")
	}
	id, project, bridge := str(record["id"]), str(record["project"]), str(record["bridge"])
	save := func() { writeJSON(replacementJournal(), record) }
	completed := func(key string) bool {
		for _, c := range list(record["completed"]) {
			if str(c) == key {
				return true
			}
		}
		return false
	}
	step := func(key string, action func() error) error {
		if completed(key) {
			return nil
		}
		record["running"], record["phase"], record["error"] = key, "importing", nil
		save()
		if err := action(); err != nil {
			return err
		}
		record["completed"] = append(list(record["completed"]), key)
		record["running"] = nil
		save()
		return nil
	}
	owned := func(m M) bool { return str(jget(m, "config", recoveryToken)) == id }
	verifyCompleted := func() error {
		if completed("project") && !owned(recoveryAPIObj(rProjectPath(project))) {
			return Public("Quarantine project changed after checkpoint")
		}
		if completed("isolated-bridge") {
			network := recoveryAPIObj("/1.0/networks/" + bridge)
			config := obj(network["config"])
			bad := !owned(network) || str(config["bridge.external_interfaces"]) != ""
			for _, k := range []string{"ipv4.address", "ipv6.address"} {
				if v := str(config[k]); v != "none" && v != "" {
					bad = true
				}
			}
			if bad {
				return Public("Quarantine network changed after checkpoint")
			}
		}
		for _, raw := range list(record["volumes"]) {
			item := obj(raw)
			if completed("volume/"+str(item["target"])) && !owned(recoveryAPIObj(rVolumePath(project, pool, str(item["target"])))) {
				return Public("Recovered volume changed after checkpoint")
			}
		}
		for _, raw := range list(record["guests"]) {
			item := obj(raw)
			if completed("guest/" + str(item["target"])) {
				current := recoveryAPIObj(rGuestPath(project, str(item["target"])))
				if str(current["status"]) != "Stopped" || !equalJSON(jget(current, "config", "volatile.uuid"), item["uuid"]) ||
					!equalJSON(current["devices"], item["devices"]) || len(list(current["profiles"])) > 0 {
					return Public("Recovered guest changed after checkpoint; stop and inspect it")
				}
			}
		}
		return nil
	}
	createProject := func() error {
		has, err := collectionHas("/1.0/projects?recursion=1", project)
		if err != nil {
			return err
		}
		if has {
			if !owned(recoveryAPIObj(rProjectPath(project))) {
				return Public("Existing project is not owned by this recovery")
			}
			return nil
		}
		_, err = opIncus(0, "project", "create", project, "-c", recoveryToken+"="+id, "-c", "features.profiles=true",
			"-c", "features.storage.volumes=true", "-c", "features.networks=false")
		return err
	}
	createBridge := func() error {
		has, err := collectionHas("/1.0/networks?recursion=1", bridge)
		if err != nil {
			return err
		}
		if has {
			if !owned(recoveryAPIObj("/1.0/networks/" + bridge)) {
				return Public("Existing network is not owned by this recovery")
			}
			return nil
		}
		_, err = opIncus(0, "network", "create", bridge, recoveryToken+"="+id, "ipv4.address=none", "ipv6.address=none",
			"ipv4.nat=false", "ipv6.nat=false", "ipv4.routing=false", "ipv6.routing=false")
		return err
	}
	stageKit := func(name string) error {
		destination := filepath.Join(STATE, "recovery-"+id, name)
		archive := filepath.Join(source, "nixus-"+name+".tar.gz")
		if !exists(destination) {
			_, err := recoveryStage(archive, destination)
			return err
		}
		manifest, entries, err := recoveryInspect(archive)
		if err != nil {
			return err
		}
		staged, err := boundedJSON(filepath.Join(destination, "manifest.json"))
		if err != nil || !equalJSON(staged, manifest) {
			return Public("Staged recovery material changed; no files are overwritten")
		}
		for key, value := range entries {
			p := filepath.Join(destination, key)
			d, _ := fileSHA256(p)
			if isSymlink(p) || !isFile(p) || d != sha256hex(value) {
				return Public("Staged recovery material changed; no files are overwritten")
			}
		}
		return nil
	}
	profile := func(name string) error {
		existing, err := recoveryAPI("/1.0/profiles?recursion=1&project=" + url.QueryEscape(project))
		if err != nil {
			return err
		}
		var item M
		for _, p := range list(existing) {
			if str(obj(p)["name"]) == name {
				item = obj(p)
			}
		}
		if item != nil && !owned(item) && (name != "default" || len(obj(item["config"])) > 0 || len(obj(item["devices"])) > 0) {
			return Public("Unexpected existing profile; no metadata is overwritten")
		}
		if item == nil {
			if _, err := opIncus(0, "profile", "create", name, "--project", project); err != nil {
				return err
			}
		}
		return recoveryEdit([]string{"profile", "edit", name, "--project", project},
			M{"config": M{recoveryToken: id}, "devices": M{"root": M{"type": "disk", "path": "/", "pool": pool}}})
	}
	volume := func(item M) error {
		existing, err := recoveryAPI("/1.0/storage-pools/" + pool + "/volumes/custom?recursion=1&project=" + project)
		if err != nil {
			return err
		}
		for _, v := range list(existing) {
			if str(obj(v)["name"]) == str(item["target"]) {
				if !owned(obj(v)) {
					return Public("Volume import outcome needs operator verification; refusing overwrite or automatic adoption")
				}
				return nil
			}
		}
		if _, err := opIncus(12*time.Hour, "storage", "volume", "import", pool, filepath.Join(source, str(item["archive"])), str(item["target"]), "--project", project); err != nil {
			return err
		}
		_, err = opIncus(0, "storage", "volume", "set", pool, str(item["target"]), recoveryToken+"="+id, "--project", project)
		return err
	}
	guest := func(item M) error {
		target := str(item["target"])
		existing, err := recoveryAPI("/1.0/instances?recursion=1&project=" + project)
		if err != nil {
			return err
		}
		var current M
		for _, g := range list(existing) {
			if str(obj(g)["name"]) == target {
				current = obj(g)
			}
		}
		if current == nil {
			overrides := []string{"--config", "boot.autostart=false", "--config", OWNER + "=false", "--config", LAST_APPLIED + "=",
				"--config", "user.nixus.restore-review=required", "--config", recoveryToken + "=" + id}
			original := obj(item["originalDevices"])
			for _, name := range keys(original) {
				d := obj(original[name])
				if str(d["type"]) == "nic" {
					for _, kv := range [][2]string{{"type", "nic"}, {"network", bridge}, {"ipv4.address", ""}, {"ipv6.address", ""}} {
						overrides = append(overrides, "--device", name+","+kv[0]+"="+kv[1])
					}
				} else if str(d["type"]) == "disk" && str(d["path"]) != "/" {
					dev := obj(jget(item, "devices", name))
					for _, k := range keys(dev) {
						overrides = append(overrides, "--device", name+","+k+"="+str(dev[k]))
					}
				}
			}
			args := append([]string{"import", filepath.Join(source, str(item["archive"])), target, "--project", project, "--storage", pool}, overrides...)
			if _, err := opIncus(12*time.Hour, args...); err != nil {
				return err
			}
			current = recoveryAPIObj(rGuestPath(project, target))
		}
		if !owned(current) || str(current["status"]) != "Stopped" {
			return Public("Unexpected or running guest; refusing automatic recovery changes")
		}
		config := cloneM(obj(current["config"]))
		config["boot.autostart"], config["snapshots.schedule"], config["user.nixus.restore-review"] = "false", "", "required"
		for k := range config {
			if fullmatch(hwaddrKey, k) {
				delete(config, k)
			}
		}
		if err := recoveryEdit([]string{"config", "edit", target, "--project", project},
			M{"config": config, "devices": item["devices"], "profiles": []any{}, "description": "Isolated replacement-host recovery"}); err != nil {
			return err
		}
		item["uuid"] = jget(recoveryAPIObj(rGuestPath(project, target)), "config", "volatile.uuid")
		return nil
	}
	err = func() error {
		if err := verifyCompleted(); err != nil {
			return err
		}
		if err := step("configuration-staged", func() error { return stageKit("config") }); err != nil {
			return err
		}
		if err := step("credentials-staged", func() error { return stageKit("secrets") }); err != nil {
			return err
		}
		if err := step("project", createProject); err != nil {
			return err
		}
		if err := step("isolated-bridge", createBridge); err != nil {
			return err
		}
		for _, name := range list(record["profiles"]) {
			n := str(name)
			if err := step("profile/"+n, func() error { return profile(n) }); err != nil {
				return err
			}
		}
		for _, raw := range list(record["volumes"]) {
			item := obj(raw)
			if err := step("volume/"+str(item["target"]), func() error { return volume(item) }); err != nil {
				return err
			}
		}
		for _, raw := range list(record["guests"]) {
			item := obj(raw)
			if err := step("guest/"+str(item["target"]), func() error { return guest(item) }); err != nil {
				return err
			}
		}
		return nil
	}()
	if err != nil {
		record["phase"], record["error"] = "blocked", "Recovery stopped safely; inspect the running checkpoint and destination before resuming"
		save()
		return nil, err
	}
	created, _ := num(record["created"])
	record["phase"], record["durationSeconds"], record["error"] = "isolated", now()-created, nil
	save()
	return replacementStatus(record)
}

func replacementRelease(confirmed, dataVerified, acknowledgeExclusions bool) (M, error) {
	if !confirmed || !dataVerified {
		return nil, Public("Release requires --confirm and --data-verified after an independent application-data drill")
	}
	record, err := loadJournal()
	if err != nil {
		return nil, err
	}
	if str(record["phase"]) != "isolated" {
		return nil, Public("Complete isolated imports before release")
	}
	complete := isTrue(jget(record, "coverage", "complete"))
	if !complete && !acknowledgeExclusions {
		return nil, Public("Coverage is incomplete or unknown; review it and explicitly --acknowledge-exclusions for a selected-data recovery")
	}
	if !isFile(hostDesired) {
		return nil, Public("Evaluate the reviewed desired-instance inventory before release")
	}
	desired, err := readJSON(hostDesired, nil)
	items, ok := desired.([]any)
	if err != nil || !ok {
		return nil, Public("Invalid desired-instance inventory")
	}
	restored := map[string]bool{}
	for _, g := range list(record["guests"]) {
		restored[str(obj(g)["project"])+"/"+str(obj(g)["name"])] = true
	}
	for _, raw := range items {
		item := obj(raw)
		if !isTrue(item["manageExistingOnly"]) && !restored[str(item["project"])+"/"+str(item["name"])] {
			return nil, Public("Desired configuration would create empty guests; reconcile the source inventory before release")
		}
	}
	for _, raw := range list(record["guests"]) {
		item := obj(raw)
		current := recoveryAPIObj(rGuestPath(str(item["project"]), str(item["name"])))
		if str(current["status"]) != "Stopped" || !equalJSON(jget(current, "config", "volatile.uuid"), item["uuid"]) ||
			str(jget(current, "config", recoveryToken)) != str(record["id"]) {
			return nil, Public("Move verified guests to their reviewed original project/name, stopped, before release")
		}
	}
	restore := "operator-attested-selected"
	if complete {
		restore = "operator-attested"
	}
	created, _ := num(record["created"])
	record["phase"], record["restore"], record["verifiedAt"], record["durationSeconds"] = "complete", restore, now(), now()-created
	writeJSON(replacementJournal(), record)
	return replacementStatus(record)
}

// --- commissioning evidence --------------------------------------------------------

var commissioningChecks = [][2]string{
	{"clock", "Plausible synchronized host clock at evidence collection"},
	{"management", "Local management endpoints and service health"},
	{"kvm", "Usable KVM API"},
	{"container", "Running unprivileged Incus container"},
	{"install-resume", "Installation or upgrade and interrupted retry"},
	{"management-auth", "Authenticated remote SSH, Cockpit and Incus access"},
	{"reboots", "Healthy management across two deliberate reboots"},
	{"network-recovery", "Actual network loss and confirmation rollback"},
	{"offhost-restore", "Independent off-host restore with verified application data"},
	{"hardware-reconnect", "Configured physical device disconnect/reconnect"},
}
var automaticChecks = map[string]bool{"clock": true, "management": true, "kvm": true, "container": true}
var evidenceStatuses = map[string]bool{"passed": true, "failed": true, "skipped": true, "unsupported": true, "unknown": true}
var environments = map[string]bool{"installed-host": true, "automated-fixture": true, "nested-integration": true}
var contextFields = []string{"revision", "version", "sourceDigest", "inputsDigest", "settingsDigest", "system", "kernel", "incus",
	"hardwareDigest", "scope", "architecture", "hardwareDevices", "mode", "environment"}

const commissioningMaxAge = 30 * 86400

func isCheck(name string) bool {
	for _, c := range commissioningChecks {
		if c[0] == name {
			return true
		}
	}
	return false
}

func readText(p string) string {
	raw, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func probeCommand(args ...string) (string, error) {
	res, err := run(args, nil, 15*time.Second, nil, "")
	if err != nil || res.Code != 0 || len(res.Stdout) > 2<<20 {
		return "", Public("Probe unavailable")
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

func virtScope() string {
	if res, err := run([]string{"systemd-detect-virt", "--container", "--quiet"}, nil, 15*time.Second, nil, ""); err == nil && res.Code == 0 {
		return "container"
	}
	res, err := run([]string{"systemd-detect-virt"}, nil, 5*time.Second, nil, "")
	out := strings.TrimSpace(string(res.Stdout))
	switch {
	case err == nil && res.Code == 1 && out == "none":
		return "physical-host"
	case err == nil && res.Code == 0 && out != "":
		return "virtual-machine"
	}
	return "unknown"
}

func machineArch() string {
	var u syscall.Utsname
	syscall.Uname(&u)
	b := []byte{}
	for _, c := range u.Machine {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func kernelRelease() string {
	var u syscall.Utsname
	syscall.Uname(&u)
	b := []byte{}
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

var incusVersion = regexp.MustCompile(`(?:Client|Server) version:\s*([0-9][a-zA-Z0-9.+-]*)`)

func commissioningContext(settings M, mode, environment string) M {
	release := upgradeMetadata(ROOT)
	hardware := []any{readText("/etc/machine-id"), machineArch(), readText("/sys/class/dmi/id/sys_vendor"), readText("/sys/class/dmi/id/product_name")}
	for _, directory := range []string{"/sys/class/net", "/sys/class/block"} {
		matches, _ := filepath.Glob(filepath.Join(directory, "*"))
		for _, device := range matches {
			if !exists(filepath.Join(device, "device")) {
				continue
			}
			hardware = append(hardware, []any{filepath.Base(device), readText(filepath.Join(device, "device/vendor")),
				readText(filepath.Join(device, "device/device")), readText(filepath.Join(device, "size"))})
		}
	}
	incus := "unknown"
	if out, err := probeCommand("incus", "--force-local", "version"); err == nil {
		if m := incusVersion.FindAllStringSubmatch(out, -1); len(m) == 2 {
			incus = m[0][1] + "_" + m[1][1]
		}
	}
	revision := str(release["revision"])
	if !fullmatch(sha40, revision) {
		revision = "unknown"
	}
	version := str(release["version"])
	if version == "" {
		version = "unknown"
	}
	system := "unknown"
	if p, err := filepath.EvalSymlinks("/run/current-system"); err == nil {
		system = p
	}
	sourceDigest, _ := digestSource(ROOT)
	return M{"revision": revision, "version": version, "sourceDigest": sourceDigest,
		"inputsDigest": digestJSON(readText(filepath.Join(ROOT, "flake.lock"))), "settingsDigest": digestJSON(settings),
		"system": system, "kernel": kernelRelease(), "incus": incus, "hardwareDigest": digestJSON(hardware), "scope": virtScope(),
		"architecture": machineArch(), "hardwareDevices": isTrue(jget(settings, "hardware", "serialAliases")) || len(obj(jget(settings, "hardware", "serialAliases"))) > 0,
		"mode": mode, "environment": environment}
}

func commissioningBoot() string {
	if v := readText("/proc/sys/kernel/random/boot_id"); v != "" {
		return digestJSON(v)
	}
	return "unknown"
}

var contextValue = re(`[a-zA-Z0-9/_.:+-]{1,256}`)
var fingerprintValue = re(`[0-9a-f]{64}|unknown`)

func validateReport(report M) error {
	if !exactKeys(report, "format", "context", "evidence") || !equalJSON(report["format"], 1) || !isInt(report["format"]) {
		return Public("Unsupported commissioning report")
	}
	ctx := obj(report["context"])
	if !exactKeys(ctx, contextFields...) {
		return Public("Invalid commissioning context")
	}
	if _, ok := ctx["hardwareDevices"].(bool); !ok {
		return Public("Invalid capability")
	}
	for _, k := range contextFields {
		if k != "hardwareDevices" && !fullmatch(contextValue, str(ctx[k])) {
			return Public("Invalid context value")
		}
	}
	scope, mode := str(ctx["scope"]), str(ctx["mode"])
	if (scope != "physical-host" && scope != "virtual-machine" && scope != "container" && scope != "unknown") ||
		(mode != "fresh" && mode != "upgrade") || !environments[str(ctx["environment"])] {
		return Public("Invalid commissioning scope or mode")
	}
	for _, k := range []string{"sourceDigest", "inputsDigest", "settingsDigest", "hardwareDigest"} {
		if !fullmatch(sha64, str(ctx[k])) {
			return Public("Invalid context digest")
		}
	}
	if str(ctx["revision"]) != "unknown" && !fullmatch(sha40, str(ctx["revision"])) {
		return Public("Invalid source revision")
	}
	evidence, ok := report["evidence"].([]any)
	if !ok || len(evidence) > 400 {
		return Public("Too many evidence records; start a new report")
	}
	for _, raw := range evidence {
		item := obj(raw)
		if !exactKeys(item, "check", "status", "type", "contextDigest", "time", "boot", "procedure") {
			return Public("Invalid evidence record")
		}
		for k, v := range item {
			if _, ok := v.(string); k != "time" && !ok {
				return Public("Invalid evidence value")
			}
		}
		check, typ := str(item["check"]), str(item["type"])
		if !isCheck(check) || !evidenceStatuses[str(item["status"])] || (typ != "automated-probe" && typ != "manual-attestation") {
			return Public("Invalid check, status or evidence type")
		}
		if typ == "automated-probe" && !automaticChecks[check] {
			return Public("Manual procedure cannot be an automated probe")
		}
		if typ == "manual-attestation" && automaticChecks[check] {
			return Public("Probe results must be collected, not attested")
		}
		if t, ok := num(item["time"]); !ok || !isInt(item["time"]) || t < 0 {
			return Public("Invalid evidence timestamp")
		}
		if !fullmatch(fingerprintValue, str(item["contextDigest"])) || !fullmatch(fingerprintValue, str(item["boot"])) {
			return Public("Invalid evidence fingerprint")
		}
		want := "probe-v1"
		if typ == "manual-attestation" {
			want = "commissioning-v1"
		}
		if str(item["procedure"]) != want {
			return Public("Unsupported evidence procedure")
		}
	}
	return nil
}

func recordEvidence(report, ctx M, check, status, typ string) error {
	report["context"] = ctx
	procedure := "probe-v1"
	if typ == "manual-attestation" {
		procedure = "commissioning-v1"
	}
	report["evidence"] = append(list(report["evidence"]), M{"check": check, "status": status, "type": typ,
		"contextDigest": digestJSON(ctx), "time": int(now()), "boot": commissioningBoot(), "procedure": procedure})
	return validateReport(report)
}

func collectEvidence(report, ctx, settings M) error {
	probes := []struct {
		name string
		fn   func() (bool, error)
	}{
		{"clock", func() (bool, error) {
			switch str(clockStatus(now())["state"]) {
			case "synchronized":
				return true, nil
			case "invalid-clock":
				return false, nil
			}
			return false, Public("Clock synchronization is not confirmed")
		}},
		{"management", func() (bool, error) {
			result, err := probe(settings)
			if err != nil || !isTrue(result["ok"]) {
				return false, err
			}
			out, err := probeCommand("systemctl", "is-active", "incus.service", "nixus-instances.service", "nixus-management-health.service")
			return err == nil && out == "active\nactive\nactive", err
		}},
		{"kvm", func() (bool, error) {
			f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
			if err != nil {
				return false, err
			}
			defer f.Close()
			v, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0xAE00, 0)
			if errno != 0 {
				return false, errno
			}
			return v == 12, nil
		}},
		{"container", func() (bool, error) {
			out, err := probeCommand("incus", "--force-local", "list", "--all-projects", "--format=json")
			if err != nil {
				return false, err
			}
			guests, err := parseJSON([]byte(out))
			if err != nil {
				return false, err
			}
			for _, raw := range list(guests) {
				g := obj(raw)
				config := obj(g["expanded_config"])
				if _, ok := g["expanded_config"]; !ok {
					config = obj(g["config"])
				}
				if str(g["type"]) == "container" && str(g["status"]) == "Running" && str(config["security.privileged"]) != "true" {
					return true, nil
				}
			}
			return false, nil
		}},
	}
	for _, p := range probes {
		ok, err := p.fn()
		status := "failed"
		switch {
		case err != nil && os.IsNotExist(err):
			status = "unsupported"
		case err != nil:
			status = "unknown"
		case ok:
			status = "passed"
		}
		if err := recordEvidence(report, ctx, p.name, status, "automated-probe"); err != nil {
			return err
		}
	}
	return nil
}

func summarizeEvidence(report, current M, revision string) (M, error) {
	if err := validateReport(report); err != nil {
		return nil, err
	}
	at := now()
	ctx := current
	if ctx == nil {
		ctx = obj(report["context"])
	}
	fingerprint := digestJSON(ctx)
	evidence := list(report["evidence"])
	rows := []any{}
	allPassed := true
	for _, c := range commissioningChecks {
		check := c[0]
		required := !(check == "hardware-reconnect" && !isTrue(ctx["hardwareDevices"]))
		var latest M
		for _, e := range evidence {
			if str(obj(e)["check"]) == check {
				latest = obj(e)
			}
		}
		status := "unknown"
		if latest != nil {
			t, _ := num(latest["time"])
			if str(latest["contextDigest"]) != fingerprint || at-t < 0 || at-t > commissioningMaxAge {
				status = "stale"
			} else {
				status = str(latest["status"])
			}
		} else if !required {
			status = "skipped"
		}
		if check == "reboots" && status == "passed" {
			boots := map[string]bool{}
			for _, raw := range evidence {
				e := obj(raw)
				t, _ := num(e["time"])
				if str(e["check"]) == "management" && str(e["status"]) == "passed" && str(e["contextDigest"]) == fingerprint &&
					str(e["boot"]) != "unknown" && at-t >= 0 && at-t <= commissioningMaxAge {
					boots[str(e["boot"])] = true
				}
			}
			if len(boots) < 3 {
				status = "unknown"
			}
		}
		var typ, observed any
		if latest != nil {
			typ, observed = latest["type"], latest["time"]
		}
		rows = append(rows, M{"check": check, "title": c[1], "required": required, "status": status, "evidenceType": typ, "observedAt": observed})
		if required && status != "passed" {
			allPassed = false
		}
	}
	eligible := str(ctx["scope"]) == "physical-host" && str(ctx["environment"]) == "installed-host" && str(ctx["architecture"]) == "x86_64" &&
		str(ctx["revision"]) != "unknown" && str(ctx["system"]) != "unknown" && str(ctx["incus"]) != "unknown" &&
		(revision == "" || str(ctx["revision"]) == revision) && allPassed
	qualification := "unqualified"
	if eligible {
		qualification = "ready-for-review"
	}
	return M{"format": 1, "revision": ctx["revision"], "mode": ctx["mode"], "scope": ctx["scope"], "environment": ctx["environment"],
		"profile": "core", "qualification": qualification, "checks": rows}, nil
}

func loadReport(p string) (M, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if info.Size() > 2<<20 {
		return nil, Public("Oversized report")
	}
	raw, _ := os.ReadFile(p)
	report, err := parseObject(raw)
	if err != nil {
		return nil, Public("Unsupported commissioning report")
	}
	return report, validateReport(report)
}

func evidenceMatrix(paths []string, revision string) (string, error) {
	if !fullmatch(sha40, revision) {
		return "", Public("Use a full release revision")
	}
	lines := []string{"# Single-host qualification evidence", "", "Source revision: `" + revision + "`.", "",
		"Reports are operator evidence, not a security certification. Ready-for-review still requires release review.", "",
		"| Target fingerprint | Mode | Profile | Scope | Environment | Evidence |", "|---|---|---|---|---|---|"}
	for _, p := range paths {
		report, err := loadReport(p)
		if err != nil {
			return "", err
		}
		summary, err := summarizeEvidence(report, nil, revision)
		if err != nil {
			return "", err
		}
		lines = append(lines, "| "+strings.Join([]string{str(jget(report, "context", "hardwareDigest"))[:12], str(summary["mode"]),
			str(summary["profile"]), str(summary["scope"]), str(summary["environment"]), str(summary["qualification"])}, " | ")+" |")
	}
	if len(paths) == 0 {
		lines = append(lines, "| No submitted evidence | — | — | — | — | unqualified |")
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func commissioningRun(action, mode, environment, check, status string, acknowledge bool) (any, error) {
	if os.Geteuid() != 0 {
		return nil, Public("Use sudo for local commissioning evidence")
	}
	if action == "record" && !acknowledge {
		return nil, Public("Perform the commissioning procedure first, then use --acknowledge to record an operator attestation")
	}
	if action == "record" && (automaticChecks[check] || !isCheck(check) || !evidenceStatuses[status]) {
		return nil, Public("Invalid check, status or evidence type")
	}
	settingsRaw, err := readJSON("/etc/nixus/effective-settings.json", nil)
	settings := obj(settingsRaw)
	if err != nil || settings == nil {
		return nil, Public("Install and activate Nixus before commissioning")
	}
	ctx := commissioningContext(settings, mode, environment)
	directory := filepath.Join(STATE, "commissioning")
	os.MkdirAll(directory, 0o700)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, Public("Commissioning directory must be root-owned, mode 0700")
	}
	release, err := lockFile(filepath.Join(directory, "report.lock"), true)
	if err != nil {
		return nil, err
	}
	defer release()
	p := filepath.Join(directory, environment+"-"+mode+".json")
	if isSymlink(p) {
		return nil, Public("Report cannot be a symlink")
	}
	report := M{"format": 1, "context": ctx, "evidence": []any{}}
	if exists(p) {
		if report, err = loadReport(p); err != nil {
			return nil, err
		}
	}
	switch action {
	case "collect":
		err = collectEvidence(report, ctx, settings)
	case "record":
		err = recordEvidence(report, ctx, check, status, "manual-attestation")
	case "export":
		report["context"] = ctx
		return report, validateReport(report)
	}
	if err != nil {
		return nil, err
	}
	if action == "collect" || action == "record" {
		if err := writeJSON(p, report); err != nil {
			return nil, err
		}
	}
	return summarizeEvidence(report, ctx, "")
}

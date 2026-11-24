package main

// Backups page actions: list snapshots, restore an empty host from the
// console, and import data into an app.

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// backupSnapshots lists the Nixus snapshots in the configured repository.
func backupSnapshots() (M, error) {
	policy, _, err := publishedProjectPolicy(NewProjectTransactions("", ""))
	if err != nil || policy == nil {
		return M{"snapshots": []any{}, "configured": false}, err
	}
	env, err := resticEnv(policy)
	if err != nil {
		return nil, err
	}
	res, err := run([]string{"restic", "snapshots", "--json", "--tag", snapshotTag}, nil, 2*time.Minute, env, "")
	if err != nil || res.Code != 0 {
		return nil, cmdFailed("Could not list snapshots; check the destination and credentials", res, err)
	}
	out := []any{}
	for _, raw := range list(must(parseJSON(res.Stdout))) {
		s := obj(raw)
		complete := false
		for _, tag := range list(s["tags"]) {
			complete = complete || str(tag) == snapshotComplete
		}
		out = append(out, M{"id": s["short_id"], "time": s["time"], "complete": complete})
	}
	return M{"snapshots": out, "configured": true, "repository": jget(policy, "restic", "repository")}, nil
}

var restoreReportPath = func() string { return filepath.Join(STATE, "project-restore-report.json") }

// startRestore writes the destination credentials and starts a cold-host
// restore worker. Only for a host without a project workspace.
func startRestore(actor string, body M) (M, error) {
	// Retrying a failed restore is allowed: its journal lets it resume.
	if lexists(NewProjectTransactions("", "").workspace) && !isFile(restoreJournalPath()) {
		return nil, Public("This server already has apps; restore onto a fresh install")
	}
	if s := str(readObj(restoreReportPath())["status"]); s == "restoring" || s == "starting" {
		return nil, Public("A restore is already running")
	}
	repository, env, rcloneConf, err := backupDestination(body)
	if err != nil {
		return nil, err
	}
	password := str(body["password"])
	snapshot := strings.TrimSpace(str(body["snapshot"]))
	if password == "" || strings.ContainsAny(password, "\n\r\x00") {
		return nil, Public("Enter the backup repository password")
	}
	if snapshot != "" && !fullmatch(re(`[0-9a-f]{8,64}`), snapshot) {
		return nil, Public("Invalid snapshot ID")
	}
	if err := writeSecretFile(backupPasswordPth, []byte(password+"\n")); err != nil {
		return nil, err
	}
	args := []string{"--repository", repository, "--password-file", backupPasswordPth}
	if len(env) > 0 {
		if err := writeSecretFile(backupEnvPath, []byte(strings.Join(env, "\n")+"\n")); err != nil {
			return nil, err
		}
		args = append(args, "--environment-file", backupEnvPath)
	}
	if strings.HasPrefix(repository, "rclone:") {
		if rcloneConf != "" {
			if err := writeSecretFile(backupRclonePath, []byte(rcloneConf)); err != nil {
				return nil, err
			}
		}
		args = append(args, "--rclone-config", backupRclonePath)
	}
	if snapshot != "" {
		args = append(args, "--snapshot", snapshot)
	}
	writeJSONMode(restoreReportPath(), M{"format": 1, "status": "starting", "startedAt": now(), "repository": repository}, 0o640, "")
	cmd := append([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-project-restore",
		"--property=RuntimeMaxSec=43200", "--setenv=NIXUS_STATE=" + STATE, "--setenv=PATH=" + os.Getenv("PATH"), "--setenv=INCUS_COMPOSE_HEALTHD_IMAGE=" + os.Getenv("INCUS_COMPOSE_HEALTHD_IMAGE"), "--setenv=INCUS_COMPOSE_DNS_IMAGE=" + os.Getenv("INCUS_COMPOSE_DNS_IMAGE"), "--setenv=INCUS_COMPOSE_SLEEP_IMAGE=" + os.Getenv("INCUS_COMPOSE_SLEEP_IMAGE"),
		adminLauncher(), "admin", "project-backup", "restore"}, args...)
	if _, err := check(cmd, nil, 20*time.Second); err != nil {
		writeJSONMode(restoreReportPath(), M{"format": 1, "status": "failed", "error": "Could not start the restore"}, 0o640, "")
		return nil, Failed("Could not start the restore", err)
	}
	audit("project-restore-requested", M{"principal": actor})
	return M{"started": true}, nil
}

// --- data import ---------------------------------------------------------------------

const maxImportBytes = 4 << 30

var importRoot = func() string { return filepath.Join(STATE, "data-imports") }
var importID = re(`[0-9a-f]{32}`)
var importPath = re(`/[A-Za-z0-9._/-]{0,255}`)

func importDir(id any) (string, M, error) {
	s, ok := id.(string)
	if !ok || !fullmatch(importID, s) {
		return "", nil, Public("Unknown import")
	}
	dir := filepath.Join(importRoot(), s)
	record := readObj(filepath.Join(dir, "import.json"))
	if record == nil {
		return "", nil, Public("Unknown import")
	}
	return dir, record, nil
}

// startDataImport records where a tar archive will be unpacked.
func startDataImport(actor string, body M) (M, error) {
	project, instance, target := str(body["project"]), str(body["instance"]), str(body["path"])
	size, ok := intValue(body["size"])
	if !fullmatch(projectName, project) || !fullmatch(re(`[A-Za-z0-9][A-Za-z0-9-]{0,62}`), instance) ||
		!fullmatch(importPath, target) || strings.Contains(target+"/", "/../") || !ok || size < 1 || size > maxImportBytes ||
		!fullmatch(hex64, str(body["sha256"])) {
		return nil, Public("Choose an app instance, a target folder and a .tar or .tar.gz file up to 4 GiB")
	}
	id := tokenHex(16)
	dir := filepath.Join(importRoot(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	record := M{"id": id, "project": project, "instance": instance, "path": target, "size": size, "sha256": body["sha256"],
		"actor": actor, "status": "uploading", "createdAt": now()}
	writeJSON(filepath.Join(dir, "import.json"), record)
	return M{"id": id}, nil
}

func chunkDataImport(body M) (M, error) {
	dir, record, err := importDir(body["id"])
	if err != nil {
		return nil, err
	}
	offset, ok := intValue(body["offset"])
	data, derr := base64.StdEncoding.DecodeString(str(body["data"]))
	size, _ := intValue(record["size"])
	if str(record["status"]) != "uploading" || !ok || derr != nil || offset < 0 || offset+len(data) > size {
		return nil, Public("Invalid import chunk")
	}
	f, err := os.OpenFile(filepath.Join(dir, "data"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, _ := f.Stat(); info.Size() != int64(offset) {
		return nil, Public("Upload chunks out of order")
	}
	if _, err := f.WriteAt(data, int64(offset)); err != nil {
		return nil, err
	}
	return M{"offset": offset + len(data)}, nil
}

// unpackTar safely extracts regular files and directories into dest.
func unpackTar(archive, dest string) (int, error) {
	f, err := os.Open(archive)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var reader io.Reader = f
	head := make([]byte, 2)
	if n, _ := f.Read(head); n == 2 && head[0] == 0x1f && head[1] == 0x8b {
		f.Seek(0, 0)
		gz, err := gzip.NewReader(f)
		if err != nil {
			return 0, Public("Invalid .tar.gz file")
		}
		reader = gz
	} else {
		f.Seek(0, 0)
	}
	tr := tar.NewReader(reader)
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return count, Public("Invalid tar archive")
		}
		name := filepath.Clean("/" + h.Name)
		if name == "/" {
			continue
		}
		target := filepath.Join(dest, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return count, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return count, err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(h.Mode)&0o777)
			if err != nil {
				return count, Public("Duplicate or invalid path in archive: " + h.Name)
			}
			if _, err := io.Copy(out, io.LimitReader(tr, h.Size)); err != nil {
				out.Close()
				return count, err
			}
			out.Close()
			count++
		default:
			return count, Public("Archives may contain only files and folders: " + h.Name)
		}
	}
}

// finishDataImport verifies the upload, unpacks it on the host and pushes the
// files into the instance.
func finishDataImport(actor string, body M) (M, error) {
	dir, record, err := importDir(body["id"])
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	digest, err := fileSHA256(filepath.Join(dir, "data"))
	if err != nil || digest != str(record["sha256"]) {
		return nil, Public("The uploaded file does not match its checksum")
	}
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0o700); err != nil {
		return nil, err
	}
	count, err := unpackTar(filepath.Join(dir, "data"), tree)
	if err != nil {
		return nil, err
	}
	// Push file by file to exact paths: a recursive push nests differently
	// depending on whether the target folder already exists.
	target := strings.TrimRight(str(record["path"]), "/")
	err = filepath.WalkDir(tree, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, _ := filepath.Rel(tree, p)
		info, _ := d.Info()
		if _, err := updateIncus(30*time.Minute, "file", "push", "--create-dirs", "--mode", fmt.Sprintf("%04o", info.Mode().Perm()),
			p, str(record["instance"])+target+"/"+filepath.ToSlash(rel), "--project", str(record["project"])); err != nil {
			return Public("Could not copy " + filepath.ToSlash(rel) + " into " + str(record["instance"]))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	audit("app-data-imported", M{"principal": actor, "project": record["project"], "instance": record["instance"], "files": count})
	return M{"files": count}, nil
}

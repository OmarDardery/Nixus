package main

// Root-owned transaction storage, certificate issuance and fixed secret
// destinations.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ROOT   = envPath("NIXUS_ROOT", "/var/lib/nixus/config")
	STATE  = envPath("NIXUS_STATE", "/var/lib/nixus-admin")
	SOURCE = envPath("NIXUS_SOURCE", defaultSource())
)

func envPath(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// defaultSource is the packaged share directory holding static assets, docs
// and helper metadata next to the binary (bin/../share/nixus).
func defaultSource() string {
	exe, err := os.Executable()
	if err != nil {
		return "/run/current-system/sw/share/nixus"
	}
	exe, _ = filepath.EvalSymlinks(exe)
	return filepath.Join(filepath.Dir(filepath.Dir(exe)), "share", "nixus")
}

var SECRET_PATHS = map[string]string{
	"cockpitPassword": "/var/lib/nixus-secrets/cockpit-operator-password",
	"wifiPassword":    "/var/lib/nixus-secrets/wifi.env",
}

var ENV_KEYS = map[string]bool{"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true,
	"AWS_DEFAULT_REGION": true, "B2_ACCOUNT_ID": true, "B2_ACCOUNT_KEY": true, "AZURE_ACCOUNT_NAME": true,
	"AZURE_ACCOUNT_KEY": true, "RESTIC_REST_USERNAME": true, "RESTIC_REST_PASSWORD": true}

// pinWorkerRuntime keeps the launcher closure alive while a job references it.
func pinWorkerRuntime(directory string) error {
	launcher := os.Getenv("NIXUS_WORKER_RUNTIME")
	if launcher == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil
		}
		exe, _ = filepath.EvalSymlinks(exe)
		launcher = exe
		for filepath.Dir(launcher) != "/nix/store" && launcher != "/" {
			launcher = filepath.Dir(launcher)
		}
		if launcher == "/" {
			return nil
		}
	} else if filepath.Dir(launcher) != "/nix/store" {
		return Hidden("Worker runtime must be a Nix store output")
	}
	_, err := check([]string{"nix-store", "--add-root", filepath.Join(directory, "worker-runtime"),
		"--indirect", "--realise", launcher}, nil, 30*time.Second)
	return err
}

// atomic writes data via a synced temporary file and directory fsync.
func atomic(path string, data []byte, mode os.FileMode, group string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path))
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if group != "" {
		if g, err := user.LookupGroup(group); err == nil {
			gid, _ := strconv.Atoi(g.Gid)
			if err := os.Chown(name, -1, gid); err != nil {
				tmp.Close()
				return err
			}
		} else if os.Getenv("NIXUS_TEST") != "1" {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return fsyncDir(dir)
}

func atomicString(path, data string, mode os.FileMode) error {
	return atomic(path, []byte(data), mode, "")
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// jsonFile encodes like Python json.dumps(indent=2, sort_keys=True).
func jsonFile(v any) []byte {
	raw, _ := json.MarshalIndent(normalize(v), "", "  ")
	return append(raw, '\n')
}

func writeJSON(path string, v any) error { return atomic(path, jsonFile(v), 0o600, "") }

func writeJSONMode(path string, v any, mode os.FileMode, group string) error {
	return atomic(path, jsonFile(v), mode, group)
}

func durableUnlink(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func lexists(path string) bool { _, err := os.Lstat(path); return err == nil }

func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

func isDir(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir()
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// readJSON returns fallback when the file does not exist.
func readJSON(path string, fallback any) (any, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fallback, nil
	}
	if err != nil {
		return nil, err
	}
	return parseJSON(raw)
}

// readObj reads an object, or fallback (nil means empty object) when absent.
func readObj(path string) M {
	v, err := readJSON(path, nil)
	if err != nil {
		return M{}
	}
	if m := obj(v); m != nil {
		return m
	}
	return M{}
}

func mustReadObj(path string) (M, error) {
	v, err := readJSON(path, nil)
	if err != nil {
		return nil, err
	}
	m := obj(v)
	if m == nil {
		return nil, Hidden("Missing or invalid JSON object: " + filepath.Base(path))
	}
	return m, nil
}

var jobID = re(`[0-9a-f]{32}`)

func jobDirectory(base, id, label string) (string, error) {
	if !fullmatch(jobID, id) {
		return "", Public("Invalid " + label + " ID")
	}
	dir := filepath.Join(base, id)
	if isSymlink(dir) || !isDir(dir) {
		return "", Public("Unknown " + label)
	}
	return dir, nil
}

const jobRecordLimit = 32 * 1024 * 1024

// openJobFile opens a regular, singly linked, owner-only-writable file.
func openJobFile(path string, private bool) (*os.File, int64, error) {
	dir, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	fd, err := syscall.Openat(int(dir.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	dir.Close()
	if err != nil {
		return nil, 0, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, 0, err
	}
	mask := uint32(0o022)
	if private {
		mask = 0o077
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != os.Geteuid() || st.Nlink > 1 || st.Mode&mask != 0 {
		f.Close()
		return nil, 0, Hidden("unsafe job file")
	}
	return f, st.Size, nil
}

// readJobRecord reads a bounded job object. A nil fallback means required.
func readJobRecord(path string, fallback M) (M, error) {
	f, size, err := openJobFile(path, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			if fallback != nil {
				return fallback, nil
			}
			return nil, Public("Job record is missing; inspect the transaction from the host console")
		}
		return nil, Public("Job record is invalid or unreadable; inspect the transaction from the host console")
	}
	defer f.Close()
	if size > jobRecordLimit {
		return nil, Public("Job record is invalid or unreadable; inspect the transaction from the host console")
	}
	raw, err := io.ReadAll(io.LimitReader(f, jobRecordLimit+1))
	if err != nil || len(raw) > jobRecordLimit {
		return nil, Public("Job record is invalid or unreadable; inspect the transaction from the host console")
	}
	m, err := parseObject(raw)
	if err != nil {
		return nil, Public("Job record is invalid or unreadable; inspect the transaction from the host console")
	}
	return m, nil
}

func tailLog(path string, limit int64) (string, error) {
	f, size, err := openJobFile(path, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			return "", nil
		}
		return "", Public("Job log is invalid or unreadable; inspect the transaction from the host console")
	}
	defer f.Close()
	if size > limit {
		f.Seek(size-limit, io.SeekStart)
	}
	raw, _ := io.ReadAll(io.LimitReader(f, limit))
	return strings.ToValidUTF8(string(raw), "�"), nil
}

var progressStatus = re(`Host command finished with status -?[0-9]{1,3}`)

func publicProgress(text string) string {
	fixed := map[string]bool{"Host command started": true, "ROLLBACK FAILED: local recovery may be required": true,
		"FAILED: transaction did not complete": true}
	var b strings.Builder
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if fixed[line] || fullmatch(progressStatus, line) {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

var workerUnit = re(`nixus-(?:build|apply|rollback|operation|deploy|project-deploy|oci-build)-[0-9a-f]{32}`)

func workerActive(unit string) (bool, error) {
	if !fullmatch(workerUnit, unit) {
		return false, Hidden("Invalid worker unit")
	}
	res, err := run([]string{"systemctl", "is-active", "--quiet", unit}, nil, 10*time.Second, nil, "")
	if err != nil || (res.Code != 0 && res.Code != 3 && res.Code != 4) {
		return false, Public("Worker state unavailable; retry status or inspect systemd from the host console")
	}
	return res.Code == 0, nil
}

// --- staged credentials ----------------------------------------------------

const stagedSecretLifetime = 24 * 60 * 60

var stagedTemp = re(`\.secrets\.json(?:[a-z0-9_]{8}|-[0-9a-f]{32})`)

// stagedDirectory opens dir after no-follow, ownership-checked ancestor lookups.
func stagedDirectory(directory string) (int, error) {
	abs, err := filepath.Abs(directory)
	if err != nil || strings.Contains("/"+abs+"/", "/../") {
		return -1, Hidden("Staged credential storage is not protected")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	euid := uint32(os.Geteuid())
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != euid) || st.Mode&0o022 != 0 {
		syscall.Close(fd)
		return -1, Hidden("Staged credential storage is not protected")
	}
	for _, part := range strings.Split(strings.Trim(abs, "/"), "/") {
		if part == "" {
			continue
		}
		child, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return -1, &os.PathError{Op: "open", Path: abs, Err: err}
		}
		fd = child
		if syscall.Fstat(fd, &st) != nil {
			syscall.Close(fd)
			return -1, Hidden("Staged credential storage is not protected")
		}
		sticky := st.Uid == 0 && st.Mode&syscall.S_ISVTX != 0
		if (st.Uid != 0 && st.Uid != euid) || (st.Mode&0o022 != 0 && !sticky) {
			syscall.Close(fd)
			return -1, Hidden("Staged credential storage is not protected")
		}
	}
	if st.Uid != euid || st.Mode&0o022 != 0 {
		syscall.Close(fd)
		return -1, Hidden("Staged credential storage is not protected")
	}
	return fd, nil
}

func listFD(fd int) ([]string, error) {
	dup, err := syscall.Dup(fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "dir")
	defer f.Close()
	f.Seek(0, io.SeekStart)
	names, err := f.Readdirnames(-1)
	sort.Strings(names)
	return names, err
}

func stagedTemporaryNames(fd int) []string {
	names, _ := listFD(fd)
	var out []string
	for _, n := range names {
		if fullmatch(stagedTemp, n) {
			out = append(out, n)
		}
	}
	return out
}

func unlinkStaged(fd int, name string) error {
	if err := syscall.Unlinkat(fd, name); err != nil && err != syscall.ENOENT {
		return err
	}
	return syscall.Fsync(fd)
}

func stageSecrets(directory string, values M) error {
	for k, v := range values {
		if _, ok := SECRET_PATHS[k]; !ok || !isStr(v) {
			return Hidden("Invalid staged credential fields")
		}
	}
	if len(values) == 0 {
		return nil
	}
	data := []byte(canonicalSpaced(values) + "\n")
	if len(data) > 1024*1024 {
		return Hidden("Staged credential input is too large")
	}
	fail := Public("Staged credential publication failed; inspect protected transaction storage and retry")
	fd, err := stagedDirectory(directory)
	if err != nil {
		return fail
	}
	defer syscall.Close(fd)
	temporary := ".secrets.json-" + tokenHex(16)
	wfd, err := syscall.Openat(fd, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return fail
	}
	defer unlinkStaged(fd, temporary)
	f := os.NewFile(uintptr(wfd), temporary)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fail
	}
	if f.Sync() != nil || f.Close() != nil {
		return fail
	}
	if unix.Linkat(fd, temporary, fd, "secrets.json", 0) != nil || syscall.Fsync(fd) != nil {
		return fail
	}
	return nil
}

// canonicalSpaced matches Python json.dumps(sort_keys=True) default spacing.
func canonicalSpaced(v any) string {
	raw, _ := json.Marshal(normalize(v))
	var out strings.Builder
	inString, escaped := false, false
	for _, c := range string(raw) {
		out.WriteRune(c)
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case ',', ':':
			out.WriteRune(' ')
		}
	}
	return out.String()
}

func stagedSecretsExpired(job M, at float64) (bool, error) {
	created, ok := num(job["created"])
	if at == 0 {
		at = now()
	}
	if !ok || created <= 0 || math.IsInf(at, 0) || at < created {
		return false, Public("Staged credential age is unknown; check the host clock and review the change again")
	}
	return at-created >= stagedSecretLifetime, nil
}

func requireFreshStagedSecrets(job M) error {
	if len(list(job["secretChanges"])) > 0 {
		expired, err := stagedSecretsExpired(job, 0)
		if err != nil {
			return err
		}
		if expired {
			return Public("Staged credentials expired; review the change again")
		}
	}
	return nil
}

func readStagedSecrets(directory string, expected []string) (M, error) {
	invalid := Public("Staged credentials are invalid or unreadable; review the change again")
	fd, err := stagedDirectory(directory)
	if err != nil {
		return nil, invalid
	}
	defer syscall.Close(fd)
	rfd, err := syscall.Openat(fd, "secrets.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT {
		if len(expected) == 0 {
			return M{}, nil
		}
		return nil, Public("Staged credentials are missing; review the change again")
	}
	if err != nil {
		return nil, invalid
	}
	f := os.NewFile(uintptr(rfd), "secrets.json")
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(rfd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != os.Geteuid() ||
		st.Nlink != 1 || st.Mode&0o077 != 0 || st.Size > 1024*1024 {
		return nil, invalid
	}
	raw, _ := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	record, err := parseObject(raw)
	if err != nil {
		return nil, invalid
	}
	got := keys(record)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		return nil, invalid
	}
	for k, v := range record {
		if _, ok := SECRET_PATHS[k]; !ok || !isStr(v) {
			return nil, invalid
		}
	}
	return record, nil
}

func removeStagedSecrets(directory string) error {
	fail := Public("Staged credential cleanup failed; inspect Nixus transaction storage and retry")
	fd, err := stagedDirectory(directory)
	if err != nil {
		return fail
	}
	defer syscall.Close(fd)
	for _, name := range append([]string{"secrets.json"}, stagedTemporaryNames(fd)...) {
		if unlinkStaged(fd, name) != nil {
			return fail
		}
	}
	return nil
}

// cleanupTerminalSecrets sweeps staged credentials of finished transactions.
func cleanupTerminalSecrets(state string) error {
	pending, err := readJobRecord(filepath.Join(state, "pending.json"), M{})
	if err != nil || (len(pending) > 0 && !fullmatch(jobID, str(pending["id"]))) {
		return Public("Staged credential recovery state is unavailable; inspect transaction storage")
	}
	jobs := filepath.Join(state, "jobs")
	fd, err := stagedDirectory(jobs)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) && errors.Is(pe.Err, syscall.ENOENT) {
			return nil
		}
		return Public("Staged credential cleanup failed; inspect protected transaction storage")
	}
	names, _ := listFD(fd)
	syscall.Close(fd)
	problems := false
	for _, name := range names {
		if !fullmatch(jobID, name) {
			continue
		}
		directory := filepath.Join(jobs, name)
		if !func() bool {
			dfd, err := stagedDirectory(directory)
			if err != nil {
				return false
			}
			defer syscall.Close(dfd)
			for _, t := range stagedTemporaryNames(dfd) {
				if unlinkStaged(dfd, t) != nil {
					return false
				}
			}
			syscall.Fsync(dfd)
			present := false
			entries, _ := listFD(dfd)
			for _, e := range entries {
				if e == "secrets.json" {
					present = true
				}
			}
			if present {
				var st unix.Stat_t
				if unix.Fstatat(dfd, "secrets.json", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG ||
					int(st.Uid) != os.Geteuid() || st.Nlink != 1 || st.Mode&0o077 != 0 {
					return false
				}
			}
			if !present || str(pending["id"]) == name {
				return true
			}
			record := filepath.Join(directory, "job.json")
			job, err := readJobRecord(record, nil)
			if err != nil {
				return false
			}
			switch status := str(job["status"]); status {
			case "confirmed", "rolled-back", "cancelled", "superseded", "expired":
				return removeStagedSecrets(directory) == nil
			case "reviewed", "ready", "failed", "building":
				expired, err := stagedSecretsExpired(job, 0)
				if err != nil {
					return false
				}
				if !expired {
					return true
				}
				phases := []string{}
				if status == "failed" {
					phases = []string{"build", "apply", "rollback"}
				} else if status == "building" {
					phases = []string{"build"}
				}
				for _, phase := range phases {
					active, err := workerActive("nixus-" + phase + "-" + name)
					if err != nil {
						return false
					}
					if active {
						return true
					}
				}
				again, err := readJobRecord(record, nil)
				if err != nil || !equalJSON(again, job) {
					return true
				}
				job["status"] = "cancelled"
				job["error"] = "Staged credentials expired; review the change again"
				if writeJSON(record, job) != nil {
					return false
				}
				return removeStagedSecrets(directory) == nil
			case "applying", "awaiting-confirmation", "rolling-back":
				expired, err := stagedSecretsExpired(job, 0)
				return err == nil && !expired
			}
			return false
		}() {
			problems = true
		}
	}
	if problems {
		return Public("Staged credential cleanup failed; inspect transaction storage, worker state and host clock; protected recovery was retained")
	}
	return nil
}

func groupID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(g.Gid)
}

// prepareStateAccess is kept for callers; the console stores no accounts the
// UI process must read.
func prepareStateAccess(locked bool) error { return nil }

// BusyError reports that another mutation holds the lock.
type BusyError struct{}

func (BusyError) Error() string {
	return "Another configuration or guest operation is active; retry after it finishes"
}

// openLock opens a lock file without following links or truncating.
func openLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		syscall.Close(fd)
		return nil, Hidden("Operation lock must be a singly linked regular file owned by the current privileged user")
	}
	syscall.Fchmod(fd, 0o600)
	return os.NewFile(uintptr(fd), path), nil
}

// lockFile takes an exclusive flock; non-blocking returns BusyError.
func lockFile(path string, blocking bool) (func(), error) {
	f, err := openLock(path)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_EX
	if !blocking {
		how |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, Public(BusyError{}.Error())
		}
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// locked holds the state mutation lock for the duration of fn.
func locked(blocking bool, fn func() error) error {
	if err := os.MkdirAll(STATE, 0o755); err != nil {
		return err
	}
	release, err := lockFile(filepath.Join(STATE, "mutation.lock"), blocking)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

func lockedValue[T any](blocking bool, fn func() (T, error)) (T, error) {
	var out T
	err := locked(blocking, func() error {
		var err error
		out, err = fn()
		return err
	})
	return out, err
}

func audit(action string, fields M) {
	record := M{"time": now(), "action": action}
	for k, v := range fields {
		record[k] = v
	}
	f, err := os.OpenFile(filepath.Join(STATE, "audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(canonicalSpaced(record) + "\n")
}

// --- machine source layout ---------------------------------------------

func modernLayout(root string) (bool, error) {
	marker := filepath.Join(root, "machine/format.json")
	if !exists(marker) {
		return false, nil
	}
	m, err := mustReadObj(marker)
	if err != nil {
		return false, err
	}
	if v, _ := num(m["version"]); v != 1 {
		return false, Public("Unsupported machine directory version")
	}
	return true, nil
}

// machinePath locates per-host files under machine/.
func machinePath(root, name string) string {
	return filepath.Join(root, "machine", map[string]string{"settings": "settings.json", "installation": "installation.json",
		"modules": "modules", "installed": "installed-system"}[name])
}

var moduleName = re(`[a-zA-Z0-9][a-zA-Z0-9_/-]*\.nix`)

func validateModules(changes M) (M, error) {
	if changes == nil || len(changes) > 16 {
		return nil, Public("Upload at most 16 named Nix module files")
	}
	total := 0
	for name, content := range changes {
		if !fullmatch(moduleName, name) {
			return nil, Public("Use a relative .nix module path without traversal")
		}
		for _, part := range strings.Split(name, "/") {
			if part == "" || part == "." || part == ".." {
				return nil, Public("Use a relative .nix module path without traversal")
			}
		}
		text, ok := content.(string)
		if !ok || strings.Contains(text, "\x00") {
			return nil, Public("Nix module content must be text")
		}
		if len(text) > 65536 {
			return nil, Public("A module exceeds the 64 KiB limit")
		}
		total += len(text)
	}
	if total > 131072 {
		return nil, Public("Module upload exceeds the 128 KiB limit")
	}
	return changes, nil
}

func installModules(source, root string) error {
	files, err := moduleFiles(source)
	if err != nil {
		return err
	}
	if _, err := moduleFiles(root); err != nil {
		return err
	}
	for _, path := range files {
		relative, _ := filepath.Rel(source, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := atomic(filepath.Join(root, relative), data, 0o644, ""); err != nil {
			return err
		}
	}
	return nil
}

func moduleFiles(root string) ([]string, error) {
	directory := machinePath(root, "modules")
	if isSymlink(directory) {
		return nil, Public("Module directory cannot be a symlink")
	}
	if !lexists(directory) {
		return nil, nil
	}
	var result []string
	err := filepath.WalkDir(directory, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == directory {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return Public("Module paths cannot be symlinks")
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(p)
		if !d.Type().IsRegular() || (ext != ".nix" && ext != ".md") {
			return Public("Only Nix modules and documentation belong in site-modules")
		}
		result = append(result, p)
		return nil
	})
	sort.Strings(result)
	return result, err
}

type sourceFile struct{ name, path string }

func sourceFiles(root string) ([]sourceFile, error) {
	names := map[string]bool{}
	manifest := filepath.Join(root, ".nixus-files.json")
	if exists(manifest) {
		v, err := readJSON(manifest, nil)
		if err != nil {
			return nil, err
		}
		list, _ := anyStrings(v)
		for _, n := range list {
			names[n] = true
		}
		names[".nixus-files.json"] = true
	} else {
		out, err := check([]string{"git", "-C", root, "ls-files", "-z"}, nil, time.Minute)
		if err != nil {
			return nil, err
		}
		for _, n := range strings.Split(string(out), "\x00") {
			if n != "" {
				names[n] = true
			}
		}
	}
	if _, err := modernLayout(root); err != nil {
		return nil, err
	}
	names["hardware-configuration.nix"] = true
	modules, err := moduleFiles(root)
	if err != nil {
		return nil, err
	}
	for _, f := range modules {
		rel, _ := filepath.Rel(root, f)
		names[rel] = true
	}
	if directory := filepath.Join(root, "machine"); exists(directory) {
		filepath.WalkDir(directory, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				rel, _ := filepath.Rel(root, p)
				names[rel] = true
			}
			return nil
		})
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	var out []sourceFile
	for _, name := range sorted {
		if filepath.IsAbs(name) || strings.Contains("/"+name+"/", "/../") {
			return nil, Public("Invalid source manifest path")
		}
		p := filepath.Join(root, name)
		if !lexists(p) {
			continue
		}
		for cur := p; cur != root && cur != filepath.Dir(cur); cur = filepath.Dir(cur) {
			if isSymlink(cur) {
				return nil, Public("Managed source cannot traverse symlinks: " + name)
			}
		}
		if !isFile(p) {
			return nil, Public("Managed source cannot contain symlinks: " + name)
		}
		ext := filepath.Ext(name)
		switch {
		case strings.HasPrefix(name, "machine/") && !(name == "machine/format.json" || name == "machine/settings.json" ||
			name == "machine/installation.json" || name == hostSecretsRelative || (strings.HasPrefix(name, "machine/modules/") && (ext == ".nix" || ext == ".md")) ||
			(strings.HasPrefix(name, "machine/installed-system/") && ext == ".nix")):
			return nil, Public("Unexpected file in machine configuration: " + name)
		case strings.HasPrefix(name, "local/") || strings.HasPrefix(name, "site-modules/") || strings.HasPrefix(name, "installed-system/"):
			continue // pre-machine/ layout files are not part of the source
		}
		out = append(out, sourceFile{name, p})
	}
	return out, nil
}

func digestSource(root string) (string, error) {
	files, err := sourceFiles(root)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			return "", err
		}
		h.Write([]byte(f.name))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func snapshot(destination, root string) error {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return err
	}
	files, err := sourceFiles(root)
	if err != nil {
		return err
	}
	var names []any
	for _, f := range files {
		target := filepath.Join(destination, f.name)
		os.MkdirAll(filepath.Dir(target), 0o755)
		data, err := os.ReadFile(f.path)
		if err != nil {
			return err
		}
		info, _ := os.Stat(f.path)
		if err := os.WriteFile(target, data, info.Mode().Perm()); err != nil {
			return err
		}
		os.Chmod(target, info.Mode().Perm())
		names = append(names, f.name)
	}
	if names == nil {
		names = []any{}
	}
	return writeJSON(filepath.Join(destination, ".nixus-files.json"), names)
}

// shellQuote matches Python shlex.quote.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("@%+=:,./-_", c)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func encodeSecrets(values M, settings M) (M, error) {
	result := M{}
	for field := range values {
		if _, ok := SECRET_PATHS[field]; !ok {
			return nil, Public("Unknown secret field")
		}
	}
	for _, field := range keys(values) {
		raw := values[field]
		if raw == nil || raw == "" {
			continue
		}
		value, ok := raw.(string)
		if !ok || len(value) > 16384 || strings.Contains(value, "\x00") {
			return nil, Public("Invalid secret value")
		}
		n := len([]rune(value))
		switch field {
		case "wifiPassword":
			if strings.ContainsAny(value, "\n\r") || !((n >= 8 && n <= 63) || (n == 64 && isHex(value))) {
				return nil, Public("Wi-Fi WPA password must contain 8–63 characters, or 64 hex digits")
			}
			value = "NIXUS_WIFI_PSK=" + shellQuote(strings.ReplaceAll(value, `\`, `\\`)) + "\n"
		case "cockpitPassword":
			if !isTrue(jget(settings, "cockpit", "managePassword")) {
				return nil, Public("Cockpit password enrollment must manage the operator password")
			}
			if n < 16 || n > 256 || strings.ContainsAny(value, "\n\r") {
				return nil, Public("Cockpit passwords must contain 16–256 characters and no newline")
			}
			out, err := check([]string{"openssl", "passwd", "-6", "-stdin"}, []byte(value+"\n"), 30*time.Second)
			if err != nil {
				return nil, err
			}
			value = strings.TrimSpace(string(out)) + "\n"
			if !strings.HasPrefix(value, "$6$") {
				return nil, Public("Failed to encode the local account password")
			}
		default:
			if n < 16 || strings.ContainsAny(value, "\n\r") {
				return nil, Public("Service passwords must contain at least 16 characters and no newline")
			}
		}
		result[field] = value
	}
	return result, nil
}

func canonicalSpacedRaw(raw []byte) string {
	v, _ := parseJSON(raw)
	return canonicalSpaced(v)
}

// issueTLS creates the local CA once, then a fresh management leaf.
func issueTLS(address, hostname string) error {
	if err := os.MkdirAll(STATE, 0o755); err != nil {
		return err
	}
	caKey, caCrt := filepath.Join(STATE, "ca.key"), filepath.Join(STATE, "ca.crt")
	if !exists(caKey) {
		if _, err := check([]string{"openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "3650",
			"-subj", "/CN=Nixus local management CA", "-keyout", caKey, "-out", caCrt,
			"-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"}, nil, 2*time.Minute); err != nil {
			return err
		}
		os.Chmod(caKey, 0o600)
		os.Chmod(caCrt, 0o644)
	}
	temp, err := os.MkdirTemp(STATE, "tls-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	if _, err := check([]string{"openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-subj", "/CN=" + hostname,
		"-keyout", filepath.Join(temp, "key"), "-out", filepath.Join(temp, "csr")}, nil, 2*time.Minute); err != nil {
		return err
	}
	alt := fmt.Sprintf("IP:%s,IP:127.0.0.1,DNS:localhost,DNS:%s", address, hostname)
	os.WriteFile(filepath.Join(temp, "extensions"), []byte("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName="+alt+"\n"), 0o600)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if _, err := check([]string{"openssl", "x509", "-req", "-in", filepath.Join(temp, "csr"), "-CA", caCrt, "-CAkey", caKey,
		"-set_serial", serial.String(), "-days", "825", "-sha256", "-extfile", filepath.Join(temp, "extensions"),
		"-out", filepath.Join(temp, "crt")}, nil, 2*time.Minute); err != nil {
		return err
	}
	key, _ := os.ReadFile(filepath.Join(temp, "key"))
	crt, _ := os.ReadFile(filepath.Join(temp, "crt"))
	ca, _ := os.ReadFile(caCrt)
	if err := atomic(filepath.Join(STATE, "tls.key"), key, 0o600, ""); err != nil {
		return err
	}
	return atomic(filepath.Join(STATE, "tls.crt"), append(crt, ca...), 0o644, "")
}

func pendingAccess(id string, record M) {
	fmt.Println("Activation is awaiting access confirmation; automatic rollback remains armed.")
	fmt.Println("Open a NEW SSH/Cockpit login after activation (or use the physical console), verify access, then run:")
	fmt.Println("sudo nixus-admin config confirm " + id)
	fmt.Println("You can also confirm this transaction in the Nixus portal.")
	if d, ok := num(record["deadline"]); ok && d > 0 {
		fmt.Println("Confirmation deadline: " + time.Unix(int64(d), 0).UTC().Format("2006-01-02 15:04:05 UTC"))
	}
}

// incusRun is the shared local Incus CLI transport.
func incusRun(args []string, timeout time.Duration, limit int) (string, error) {
	res, err := run(append([]string{"incus", "--force-local"}, args...), nil, timeout, nil, "")
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		message := strings.TrimSpace(string(res.Stderr))
		if limit > 0 && len(message) > limit {
			message = message[len(message)-limit:]
		}
		if message == "" {
			message = fmt.Sprintf("Incus operation failed with status %d", res.Code)
		}
		return "", Hidden(message)
	}
	return string(res.Stdout), nil
}

// adminLauncher is the packaged nixus-admin wrapper when available, so that
// transient workers inherit its pinned tools and environment.
func adminLauncher() string {
	if launcher := os.Getenv("NIXUS_ADMIN_LAUNCHER"); strings.HasPrefix(launcher, "/nix/store/") {
		return launcher
	}
	exe, _ := os.Executable()
	return exe
}

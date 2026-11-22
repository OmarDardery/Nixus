package main

// Root broker for separately approved offline OCI builds, verified import into
// Incus, and the Compose deploy adapter (#45). Every parser/build command runs
// in bubblewrap under the dedicated unprivileged builder account with an empty
// network namespace and no Incus socket.

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var ociRoot = envPath("NIXUS_OCI_ROOT", "/var/lib/nixus-oci")

const ociReviewLifetime = 15 * 60
const ociBuilderUser = "nixus-oci"
const ociMaxArtifacts = 16
const ociMaxWorkerRecord = 1024 * 1024

var ociAccountOverride func() (int, int, error)

func ociAccount() (int, int, error) {
	if ociAccountOverride != nil {
		return ociAccountOverride()
	}
	u, err := user.Lookup(ociBuilderUser)
	if err != nil {
		return 0, 0, Public("OCI builder account is missing")
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid, nil
}

func workerJSON(p string) (M, error) {
	uid, _, err := ociAccount()
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, Public("Untrusted OCI worker record metadata")
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	var st syscall.Stat_t
	syscall.Fstat(fd, &st)
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != uid || st.Nlink != 1 || st.Size > ociMaxWorkerRecord {
		return nil, Public("Untrusted OCI worker record metadata")
	}
	raw, _ := io.ReadAll(io.LimitReader(f, ociMaxWorkerRecord+1))
	if int64(len(raw)) != st.Size {
		return nil, Public("Untrusted OCI worker output changed")
	}
	m, err := parseObject(raw)
	if err != nil {
		return nil, Public("Untrusted OCI worker record is not an object")
	}
	return m, nil
}

func ociOwned(p string, mode os.FileMode, create bool) error {
	if create {
		os.MkdirAll(p, mode)
	}
	info, err := os.Lstat(p)
	if err != nil || !info.IsDir() || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		return Public("Untrusted OCI broker directory")
	}
	return nil
}

var chownTree = func(root string, uid, gid int) error {
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == root {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if !info.IsDir() {
				return Public("OCI work contains unsafe directory metadata")
			}
			os.Lchown(p, uid, gid)
			return os.Chmod(p, 0o700)
		}
		if !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Nlink != 1 {
			return Public("OCI work contains nonregular source")
		}
		os.Lchown(p, uid, gid)
		mode := os.FileMode(0o600)
		if strings.Contains("/"+p+"/", "/context/") {
			mode = 0o400
		}
		return os.Chmod(p, mode)
	})
	if err != nil {
		return err
	}
	os.Lchown(root, uid, gid)
	return os.Chmod(root, 0o700)
}

func ociStoreReady() (string, error) {
	if err := ociOwned(ociRoot, 0o711, true); err != nil {
		return "", err
	}
	work := filepath.Join(ociRoot, "jobs")
	if err := ociOwned(work, 0o711, true); err != nil {
		return "", err
	}
	for _, p := range []string{ociRoot, work} {
		info, _ := os.Stat(p)
		if m := info.Mode().Perm() & 0o077; m != 0o011 && m != 0 {
			return "", Public("OCI state parent must not be group-writable or enumerable")
		}
	}
	return work, nil
}

func ociSnapshot(project, revision, identity string, publisher *PublishedSources) (string, M, error) {
	plan, err := sourcePlan(project, revision, publisher)
	if err != nil {
		return "", nil, err
	}
	mode := str(plan["mode"])
	blocked := false
	for _, b := range list(plan["blocking"]) {
		if str(b) == "unsupported-buildkit-feature-requires-explicit-policy" || str(b) == "dockerfile-base-image-must-be-pinned-by-digest" {
			blocked = true
		}
	}
	if (mode != "compose" && mode != "dockerfile") || blocked {
		return "", nil, Public("OCI project source is ambiguous or uses unsupported build syntax")
	}
	files, err := checkFiles(plan["sourceFiles"])
	if err != nil {
		return "", nil, err
	}
	uid, gid, err := ociAccount()
	if err != nil {
		return "", nil, err
	}
	workspace, err := ociStoreReady()
	if err != nil {
		return "", nil, err
	}
	scratch, err := os.MkdirTemp(workspace, ".")
	if err != nil {
		return "", nil, err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(scratch)
		}
	}()
	os.Chmod(scratch, 0o700)
	context := filepath.Join(scratch, "context")
	os.Mkdir(context, 0o700)
	if err := verifiedSource(filepath.Join(publisher.root, project, "revisions", revision, "source"), files, context); err != nil {
		return "", nil, err
	}
	for _, n := range []string{"work", "out"} {
		os.Mkdir(filepath.Join(scratch, n), 0o700)
	}
	work := filepath.Join(scratch, "work")
	for _, n := range []string{"home", "tmp", "run", "config"} {
		os.Mkdir(filepath.Join(work, n), 0o700)
	}
	os.WriteFile(filepath.Join(work, "storage.conf"), []byte("[storage]\ndriver = \"vfs\"\nrunroot = \"/work/runroot\"\ngraphroot = \"/work/graphroot\"\n"), 0o600)
	etc := filepath.Join(scratch, "etc")
	os.Mkdir(etc, 0o700)
	os.WriteFile(filepath.Join(etc, "passwd"), []byte("root:x:0:0:OCI builder:/work/home:/bin/sh\n"), 0o600)
	os.WriteFile(filepath.Join(etc, "group"), []byte("root:x:0:\n"), 0o600)
	bases := baseImages(plan)
	if err := fetchBaseImages(scratch, bases); err != nil {
		return "", nil, err
	}
	plan["bases"] = bases
	if err := atomicString(filepath.Join(work, "intent.json"), canonicalSpaced(plan), 0o600); err != nil {
		return "", nil, err
	}
	if err := chownTree(scratch, uid, gid); err != nil {
		return "", nil, err
	}
	target := filepath.Join(workspace, identity)
	if lexists(target) {
		return "", nil, Public("OCI work already exists; inspect prior journal")
	}
	if err := os.Rename(scratch, target); err != nil {
		return "", nil, err
	}
	ok = true
	return target, plan, nil
}

func ociSandboxCommand(workspace, mode string) ([]string, error) {
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	pins := map[string]string{"bwrap": os.Getenv("NIXUS_OCI_BWRAP_BIN"), "compose": os.Getenv("NIXUS_OCI_COMPOSE_BIN"),
		"buildah": os.Getenv("NIXUS_OCI_BUILDAH_BIN"), "worker": exe}
	for _, label := range []string{"bwrap", "compose", "buildah", "worker"} {
		if !strings.HasPrefix(pins[label], "/nix/store/") {
			return nil, Public("Pinned OCI build runtime is unavailable: " + label)
		}
	}
	work := filepath.Join(workspace, "work")
	cmd := []string{pins["bwrap"], "--unshare-all", "--die-with-parent", "--new-session", "--uid", "0", "--gid", "0",
		"--cap-add", "ALL", "--ro-bind", "/nix/store", "/nix/store", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
		"--dir", "/etc", "--ro-bind", filepath.Join(workspace, "etc", "passwd"), "/etc/passwd",
		"--ro-bind", filepath.Join(workspace, "etc", "group"), "/etc/group",
		"--dir", "/context", "--ro-bind", filepath.Join(workspace, "context"), "/context",
		"--dir", "/work", "--bind", work, "/work", "--dir", "/out", "--bind", filepath.Join(workspace, "out"), "/out",
		"--chdir", "/work", "--clearenv", "--setenv", "PATH", os.Getenv("NIXUS_OCI_PATH"),
		"--setenv", "NIXUS_OCI_PATH", os.Getenv("NIXUS_OCI_PATH"), "--setenv", "NIXUS_OCI_COMPOSE_BIN", pins["compose"],
		"--setenv", "NIXUS_OCI_BUILDAH_BIN", pins["buildah"]}
	if os.Getenv("NIXUS_OCI_VM_TEST") == "1" {
		cmd = append(cmd, "--setenv", "NIXUS_OCI_VM_TEST", "1")
	}
	return append(cmd, pins["worker"], "oci-child", mode, "/work/intent.json"), nil
}

var ociRunSandbox = func(workspace, mode, identity string) error {
	if _, _, err := ociAccount(); err != nil {
		return err
	}
	cmd, err := ociSandboxCommand(workspace, mode)
	if err != nil {
		return err
	}
	runtimeMax, timeout := "1800", 1830*time.Second
	if mode == "inspect" {
		runtimeMax, timeout = "120", 130*time.Second
	}
	sandbox := append([]string{"systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=nixus-oci-sandbox-" + identity,
		"--property=User=" + ociBuilderUser, "--property=NoNewPrivileges=yes", "--property=PrivateNetwork=yes",
		"--property=IPAddressDeny=any", "--property=PrivateDevices=yes", "--property=ProtectHome=yes",
		"--property=ProtectSystem=strict", "--property=ProtectControlGroups=yes", "--property=RestrictSUIDSGID=yes",
		"--property=LockPersonality=yes", "--property=RestrictRealtime=yes", "--property=CPUQuota=200%",
		"--property=MemoryMax=2G", "--property=TasksMax=256", "--property=RuntimeMaxSec=" + runtimeMax,
		"--property=ReadWritePaths=" + workspace,
		"--property=InaccessiblePaths=-/var/lib/incus -/etc/nixos -/etc/ssh -/run/nixus-secrets -/srv/nixus -/var/lib/nixus-admin -/var/lib/nixus-secrets",
		"--property=WorkingDirectory=" + workspace, "--property=Environment=NIXUS_OCI_JOB=" + identity}, cmd...)
	res, err := run(sandbox, nil, timeout, nil, "")
	if err != nil || res.Code != 0 {
		// The journal is root-only; keep the builder tail for diagnosis.
		tail := string(res.Stderr)
		if len(tail) > 4000 {
			tail = tail[len(tail)-4000:]
		}
		os.Stderr.WriteString("nixus: OCI sandbox " + mode + " failed: " + tail + "\n")
		return Public("Isolated OCI validation/build failed; source was not deployed")
	}
	return nil
}

type OCIBuilds struct {
	state, jobs string
	publisher   *PublishedSources
	incus       incusFunc
}

func NewOCIBuilds(state string, publisher *PublishedSources) *OCIBuilds {
	if state == "" {
		state = STATE
	}
	if publisher == nil {
		publisher = NewPublishedSources("")
	}
	b := &OCIBuilds{state, filepath.Join(state, "oci-builds"), publisher, defaultIncus}
	os.MkdirAll(b.jobs, 0o700)
	return b
}

func (b *OCIBuilds) job(id any) (string, error) {
	s, ok := id.(string)
	if !ok || !fullmatch(jobID, s) {
		return "", Public("Invalid OCI review ID")
	}
	p := filepath.Join(b.jobs, s)
	if isSymlink(p) || !isDir(p) {
		return "", Public("Unknown OCI review ID")
	}
	return p, nil
}

func (b *OCIBuilds) record(id any) (M, error) {
	p, err := b.job(id)
	if err != nil {
		return nil, err
	}
	return readJobRecord(filepath.Join(p, "job.json"), nil)
}

func (b *OCIBuilds) active(identity string) error {
	current := readObj(filepath.Join(b.state, "oci-build-active.json"))
	if id := str(current["id"]); id != "" && id != identity {
		record, err := b.record(id)
		if err != nil {
			return err
		}
		switch str(record["status"]) {
		case "verified-artifact", "imported", "failed", "cancelled":
		default:
			return Public("Finish or recover the current OCI build")
		}
	}
	return nil
}

func (b *OCIBuilds) status(identity string) (M, error) {
	if identity == "" {
		identity = str(readObj(filepath.Join(b.state, "oci-build-last.json"))["id"])
	}
	if identity == "" {
		return M{"id": nil, "status": "not-started"}, nil
	}
	record, err := b.record(identity)
	if err != nil {
		return nil, err
	}
	updated, ok := num(record["updatedAt"])
	if !ok {
		updated, _ = num(record["createdAt"])
	}
	if s := str(record["status"]); (s == "queued" || s == "building") && now()-updated > 45 {
		if active, err := workerActive("nixus-oci-build-" + identity); err == nil && !active {
			record["status"], record["errorCode"], record["updatedAt"] = "interrupted", "worker-interrupted", now()
			dir, _ := b.job(identity)
			writeJSON(filepath.Join(dir, "job.json"), record)
		}
	}
	out := M{}
	for _, k := range []string{"id", "project", "revision", "status", "planHash", "createdAt", "expires", "intentHash",
		"services", "artifacts", "errorCode", "errorDetail", "importedAt"} {
		out[k] = record[k]
	}
	return out, nil
}

// imported returns the newest imported build of exactly this revision.
func (b *OCIBuilds) imported(project, revision string) M {
	entries, _ := os.ReadDir(b.jobs)
	var best M
	var bestDir string
	for _, e := range entries {
		dir := filepath.Join(b.jobs, e.Name())
		if isSymlink(dir) || !isDir(dir) || !fullmatch(jobID, e.Name()) {
			continue
		}
		record, err := readJobRecord(filepath.Join(dir, "job.json"), nil)
		if err != nil {
			continue
		}
		at, _ := num(record["importedAt"])
		bestAt, _ := num(best["importedAt"])
		if str(record["project"]) == project && str(record["revision"]) == revision && str(record["status"]) == "imported" &&
			(best == nil || at > bestAt) {
			best, bestDir = record, dir
		}
	}
	if best == nil {
		return nil
	}
	return M{"id": best["id"], "intentHash": best["intentHash"], "artifacts": best["artifacts"], "services": best["services"],
		"intent": readObj(filepath.Join(bestDir, "intent.json"))}
}

func (b *OCIBuilds) review(project, revision any, principal string) (M, error) {
	return lockedValue(false, func() (M, error) {
		if err := b.active(""); err != nil {
			return nil, err
		}
		p, ok1 := project.(string)
		rev, ok2 := revision.(string)
		if !ok1 || !ok2 {
			return nil, Public("Invalid published source identity")
		}
		identity := tokenHex(16)
		scratch, _, err := ociSnapshot(p, rev, identity, b.publisher)
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(scratch)
		if err := ociRunSandbox(scratch, "inspect", identity); err != nil {
			return nil, err
		}
		parsed, err := workerJSON(filepath.Join(scratch, "out", "intent.json"))
		if err != nil {
			return nil, err
		}
		if v, _ := num(parsed["format"]); str(parsed["sourceHash"]) != rev || str(parsed["project"]) != p || v != 1 {
			return nil, Public("Isolated Compose parser did not attest the reviewed source")
		}
		if _, err := b.publisher.attest(p, rev); err != nil {
			return nil, err
		}
		record := M{"id": identity, "format": 1, "project": p, "revision": rev, "status": "ready", "createdAt": now(),
			"expires": now() + ociReviewLifetime, "principal": principal, "intentHash": parsed["intentHash"],
			"services": parsed["services"], "sourceHash": rev}
		record["planHash"] = digestJSON(M{"project": p, "revision": rev, "intentHash": parsed["intentHash"], "services": parsed["services"]})
		dir := filepath.Join(b.jobs, identity)
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
		writeJSON(filepath.Join(dir, "intent.json"), parsed)
		writeJSON(filepath.Join(dir, "job.json"), record)
		audit("oci-build-reviewed", M{"project": p, "identity": identity, "principal": principal, "revision": rev})
		writeJSON(filepath.Join(b.state, "oci-build-last.json"), M{"id": identity})
		return b.status(identity)
	})
}

func (b *OCIBuilds) queue(identity, planHash any, resume bool) (M, error) {
	return lockedValue(false, func() (M, error) {
		id, _ := identity.(string)
		if err := b.active(id); err != nil {
			return nil, err
		}
		record, err := b.record(identity)
		if err != nil {
			return nil, err
		}
		allowed := str(record["status"]) == "ready"
		if resume {
			allowed = str(record["status"]) == "failed" || str(record["status"]) == "interrupted"
		}
		hash, ok := planHash.(string)
		if !allowed || !ok || !compareDigest(hash, str(record["planHash"])) {
			return nil, Public("OCI build requires an exact, fresh reviewed revision")
		}
		if expires, _ := num(record["expires"]); !resume && now() >= expires {
			return nil, Public("OCI build review expired; review the source again")
		}
		if _, err := b.publisher.attest(record["project"], record["revision"]); err != nil {
			return nil, err
		}
		dir, _ := b.job(id)
		record["status"], record["updatedAt"] = "queued", now()
		writeJSON(filepath.Join(dir, "job.json"), record)
		writeJSON(filepath.Join(b.state, "oci-build-active.json"), M{"id": id})
		pinErr := pinWorkerRuntime(dir)
		var runErr error
		if pinErr == nil {
			_, runErr = check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-oci-build-" + id,
				"--property=RuntimeMaxSec=2400", "--setenv=NIXUS_STATE=" + b.state, "--setenv=NIXUS_OCI_ROOT=" + ociRoot,
				"--setenv=NIXUS_OCI_BWRAP_BIN=" + os.Getenv("NIXUS_OCI_BWRAP_BIN"), "--setenv=NIXUS_OCI_COMPOSE_BIN=" + os.Getenv("NIXUS_OCI_COMPOSE_BIN"),
				"--setenv=NIXUS_OCI_BUILDAH_BIN=" + os.Getenv("NIXUS_OCI_BUILDAH_BIN"), "--setenv=NIXUS_OCI_PATH=" + os.Getenv("NIXUS_OCI_PATH"),
				"--setenv=PATH=" + os.Getenv("PATH"), "--setenv=NIXUS_OCI_VM_TEST=" + os.Getenv("NIXUS_OCI_VM_TEST"),
				adminLauncher(), "admin", "oci-build-job", id}, nil, 20*time.Second)
		}
		if pinErr != nil || runErr != nil {
			record["status"], record["errorCode"] = "interrupted", "builder-launch-failed"
			writeJSON(filepath.Join(dir, "job.json"), record)
			return nil, Public("OCI build worker failed to start; use explicit retry")
		}
		audit("oci-build-queued", M{"identity": id, "project": record["project"]})
		return b.status(id)
	})
}

func (b *OCIBuilds) run(identity string) (M, error) {
	return lockedValue(true, func() (M, error) {
		dir, err := b.job(identity)
		if err != nil {
			return nil, err
		}
		record, err := b.record(identity)
		if err != nil {
			return nil, err
		}
		if str(record["status"]) != "queued" {
			return nil, Public("Unapproved OCI build job")
		}
		record["status"], record["updatedAt"] = "building", now()
		writeJSON(filepath.Join(dir, "job.json"), record)
		var scratch string
		err = func() error {
			var spec M
			var err error
			scratch, spec, err = ociSnapshot(str(record["project"]), str(record["revision"]), identity, b.publisher)
			if err != nil {
				return err
			}
			spec["intentHash"] = record["intentHash"]
			intent := filepath.Join(scratch, "work", "intent.json")
			if err := atomicString(intent, canonicalSpaced(spec), 0o400); err != nil {
				return err
			}
			uid, gid, _ := ociAccount()
			os.Chown(intent, uid, gid)
			if err := ociRunSandbox(scratch, "build", identity); err != nil {
				return err
			}
			response, err := workerJSON(filepath.Join(scratch, "out", "build-result.json"))
			if err != nil {
				return err
			}
			artifacts := list(response["artifacts"])
			if v, _ := num(response["format"]); v != 1 || str(response["project"]) != str(record["project"]) ||
				str(response["revision"]) != str(record["revision"]) || str(response["intentHash"]) != str(record["intentHash"]) ||
				len(artifacts) < 1 || len(artifacts) > ociMaxArtifacts {
				return Public("Builder returned an unapproved or invalid OCI artifact set")
			}
			expected := map[string]string{}
			for _, s := range list(record["services"]) {
				if isTrue(obj(s)["built"]) {
					expected[str(obj(s)["service"])] = str(obj(s)["image"])
				}
			}
			got := map[string]bool{}
			for _, a := range artifacts {
				got[str(obj(a)["service"])] = true
			}
			if len(got) != len(expected) {
				return Public("OCI build artifact set differs from approved services")
			}
			for s := range expected {
				if !got[s] {
					return Public("OCI build artifact set differs from approved services")
				}
			}
			destination := filepath.Join(dir, "artifacts")
			if err := os.Mkdir(destination, 0o700); err != nil {
				return err
			}
			completed := []any{}
			for _, raw := range artifacts {
				entry := obj(raw)
				name := str(entry["service"])
				if str(entry["image"]) != expected[name] || str(entry["artifact"]) != name+".oci.tar" || str(entry["rootfs"]) != name+".rootfs.tar" {
					return Public("OCI artifact identity changed after review")
				}
				source := filepath.Join(scratch, "out", str(entry["artifact"]))
				metadata, err := verifyArchive(source, entry["sha256"], entry["bytes"])
				if err != nil {
					return err
				}
				rootfsSource := filepath.Join(scratch, "out", str(entry["rootfs"]))
				rootfs, err := verifyRootfs(rootfsSource, entry["rootfsSha256"], entry["rootfsBytes"])
				if err != nil {
					return err
				}
				specJSON, err := runtimeSpec(obj(metadata["config"]), str(rootfs["passwd"]), str(rootfs["group"]))
				if err != nil {
					return err
				}
				metaBytes, err := metadataTar(str(entry["image"]), str(metadata["architecture"]), time.Now().Unix(), specJSON)
				if err != nil {
					return err
				}
				meta := filepath.Join(destination, name+".meta.tar")
				if err := atomic(meta, metaBytes, 0o400, ""); err != nil {
					return err
				}
				target, rootfsTarget := filepath.Join(destination, str(entry["artifact"])), filepath.Join(destination, str(entry["rootfs"]))
				for _, pair := range [][2]string{{source, target}, {rootfsSource, rootfsTarget}} {
					if err := os.Rename(pair[0], pair[1]); err != nil {
						return err
					}
					os.Lchown(pair[1], os.Geteuid(), os.Getegid())
					os.Chmod(pair[1], 0o400)
				}
				alias, err := aliasFor(str(entry["image"]))
				if err != nil {
					return err
				}
				fingerprint, err := imageFingerprint(meta, rootfsTarget)
				if err != nil {
					return err
				}
				completed = append(completed, M{"service": name, "image": entry["image"], "sha256": metadata["sha256"],
					"bytes": metadata["bytes"], "ociManifestDigest": metadata["ociManifestDigest"], "rootfsSha256": rootfs["sha256"],
					"incusAlias": alias, "incusFingerprint": fingerprint})
			}
			if _, err := b.publisher.attest(record["project"], record["revision"]); err != nil {
				return err
			}
			record["status"], record["completedAt"], record["artifacts"] = "verified-artifact", now(), completed
			audit("oci-build-artifacts-verified", M{"identity": identity, "project": record["project"], "imageCount": len(completed)})
			importErr := func() error {
				project, err := incusProjectName(str(record["project"]))
				if err != nil {
					return err
				}
				if err := ensureComposeProject(project, b.incus); err != nil {
					return err
				}
				for _, raw := range completed {
					item := obj(raw)
					svc := str(item["service"])
					if _, err := importImage(project, str(item["incusAlias"]), str(item["incusFingerprint"]),
						filepath.Join(destination, svc+".meta.tar"), filepath.Join(destination, svc+".rootfs.tar"), b.incus); err != nil {
						return err
					}
					item["incusProject"] = project
				}
				return nil
			}()
			if importErr != nil {
				record["status"], record["errorCode"] = "failed", "incus-import-failed"
				record["errorDetail"] = publicError(importErr)
				fmt.Fprintln(os.Stderr, "nixus: OCI import failed:", importErr)
				audit("oci-build-import-failed", M{"identity": identity, "project": record["project"]})
			} else {
				record["status"], record["importedAt"] = "imported", now()
				audit("oci-build-imported", M{"identity": identity, "project": record["project"], "imageCount": len(completed)})
			}
			return nil
		}()
		if err != nil {
			record["status"], record["errorCode"] = "failed", "build-or-artifact-verification-failed"
			record["errorDetail"] = publicError(err)
			fmt.Fprintln(os.Stderr, "nixus: OCI build failed:", err)
			audit("oci-build-failed", M{"identity": identity, "project": record["project"]})
		}
		if scratch != "" {
			os.RemoveAll(scratch)
		}
		writeJSON(filepath.Join(dir, "job.json"), record)
		durableUnlink(filepath.Join(b.state, "oci-build-active.json"))
		return b.status(identity)
	})
}

// --- Compose deploy adapter (#45) ------------------------------------------

const composeServiceLabel = "user.label.incus-compose.service"
const composeIntentKey = "user.nixus.compose-intent"

var composeStable = []string{"kind", "project", "name", "sourceProject", "revision", "buildId", "intentHash", "images", "services"}

type composeAdapter struct {
	builds *OCIBuilds
	incus  incusFunc
	up     func(sourceProject, incusProject, revision string) error
}

func newComposeAdapter() *composeAdapter {
	a := &composeAdapter{builds: NewOCIBuilds("", nil), incus: defaultIncus}
	a.up = a.composeUp
	return a
}

func (a *composeAdapter) observe(sourceProject, incusProject, revision string) (M, error) {
	derived, err := incusProjectName(sourceProject)
	if err != nil || incusProject != derived {
		return nil, Public("A Compose project's Incus project must be the name incus-compose derives")
	}
	build := a.builds.imported(sourceProject, revision)
	if build == nil {
		return nil, Public("Build and import the bound source revision before deploying it")
	}
	project := incusQueryObj(a.incus, "/1.0/projects/"+incusProject)
	config := obj(project["config"])
	if project == nil || str(config[imageOwnerKey]) != "true" || str(config[imageBackendKey]) != composeBackend {
		return nil, Public("The Incus project is not owned by Nixus for Compose")
	}
	images := []any{}
	expected := map[string]string{}
	for _, raw := range list(build["artifacts"]) {
		item := obj(raw)
		alias := incusQueryObj(a.incus, "/1.0/images/aliases/"+str(item["incusAlias"])+"?project="+incusProject)
		if str(alias["target"]) != str(item["incusFingerprint"]) {
			return nil, Public("A built image alias no longer points at its verified fingerprint")
		}
		images = append(images, M{"service": item["service"], "alias": item["incusAlias"], "fingerprint": item["incusFingerprint"]})
		expected[str(item["service"])] = str(item["incusFingerprint"])
	}
	var services []string
	for _, s := range list(build["services"]) {
		services = append(services, str(obj(s)["service"]))
	}
	sortStrings(services)
	out, err := a.incus(0, "query", "/1.0/instances?recursion=1&project="+incusProject)
	instances := []any{}
	if err == nil {
		instances = list(must(parseJSON([]byte(out))))
	}
	observed := M{}
	for _, raw := range instances {
		instance := obj(raw)
		settings := obj(instance["config"])
		if str(settings[OWNER]) == "true" {
			return nil, Public("A native Nixus-owned instance is inside the Compose project")
		}
		service := str(settings[composeServiceLabel])
		if service == "" {
			return nil, Public("An instance not managed by incus-compose is inside the Compose project")
		}
		observed[str(instance["name"])] = M{"service": service, "status": truncate(str(instance["status"]), 32),
			"image": str(settings["volatile.base_image"])}
	}
	current := str(config[composeIntentKey]) == str(build["intentHash"])
	var recreates []string
	for _, s := range services {
		count := 0
		for _, o := range observed {
			om := obj(o)
			if str(om["service"]) != s {
				continue
			}
			count++
			want, built := expected[s]
			if str(om["status"]) != "Running" || (built && str(om["image"]) != want) {
				current = false
			}
			if built && str(om["image"]) != want {
				recreates = append(recreates, s)
			}
		}
		if count == 0 {
			current = false
		}
	}
	recreates = uniqueSorted(recreates)
	before := map[string]bool{}
	for _, o := range observed {
		before[str(obj(o)["service"])] = true
	}
	action, status := "compose-up", "Pending"
	if current {
		action, status = "noop", "Running"
	}
	resource := M{"kind": "compose", "project": incusProject, "name": "compose", "sourceProject": sourceProject,
		"revision": revision, "buildId": build["id"], "intentHash": build["intentHash"], "images": images,
		"services": strings2any(nonNil(services)), "instances": observed, "action": action, "observedStatus": status,
		"before": M{"services": strings2any(sortedKeys(before))}, "after": M{"services": strings2any(nonNil(services)), "revision": revision},
		"recreates": strings2any(nonNil(recreates))}
	etag := M{}
	for _, k := range append(append([]string{}, composeStable...), "instances") {
		etag[k] = resource[k]
	}
	resource["etag"] = digestJSON(etag)
	return normalize(resource).(M), nil
}

func sortStrings(s []string) { sortSlice(s) }

func uniqueSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		set[s] = true
	}
	return sortedKeys(set)
}

func composeStableOf(r M) M {
	out := M{}
	for _, k := range composeStable {
		out[k] = r[k]
	}
	return out
}

func (a *composeAdapter) composeUp(sourceProject, incusProject, revision string) error {
	build := a.builds.imported(sourceProject, revision)
	if build == nil {
		return Public("Build and import the bound source revision before deploying it")
	}
	scratch, err := os.MkdirTemp(STATE, "compose-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	os.Chmod(scratch, 0o700)
	plan, err := sourcePlan(sourceProject, revision, a.builds.publisher)
	if err != nil {
		return err
	}
	files, err := checkFiles(plan["sourceFiles"])
	if err != nil {
		return err
	}
	source := filepath.Join(scratch, "source")
	os.Mkdir(source, 0o700)
	if err := verifiedSource(filepath.Join(a.builds.publisher.root, sourceProject, "revisions", revision, "source"), files, source); err != nil {
		return err
	}
	var compose string
	if g := str(plan["generatedCompose"]); g != "" {
		compose = filepath.Join(source, ".nixus-generated-compose.yaml")
		if err := atomicString(compose, g, 0o600); err != nil {
			return err
		}
	} else if e := str(plan["entrypoint"]); e != "" {
		compose = filepath.Join(source, e)
	} else {
		return Public("The reviewed source has no Compose entry point")
	}
	flags := []string{"-p", sourceProject, "-P", source, "-f", compose}
	if override := str(obj(build["intent"])["separateOverride"]); override != "" {
		p := filepath.Join(scratch, "nixus-override.yaml")
		if err := atomicString(p, override, 0o600); err != nil {
			return err
		}
		flags = append(flags, "-f", p)
	}
	binary := os.Getenv("NIXUS_OCI_COMPOSE_BIN")
	if binary == "" {
		binary = "incus-compose"
	}
	args := append(append([]string{binary, "--ansi", "never"}, flags...), "--image-cache", "", "up", "--detach", "--no-build",
		"--pull", "missing", "--no-healthd", "--no-dns")
	res, err := run(args, nil, 1800*time.Second, []string{"PATH=" + os.Getenv("PATH"), "HOME=" + scratch}, source)
	if err != nil || res.Code != 0 {
		if os.Getenv("NIXUS_OCI_VM_TEST") == "1" {
			tail := string(res.Stderr)
			if len(tail) > 3000 {
				tail = tail[len(tail)-3000:]
			}
			os.Stdout.WriteString("COMPOSE-VM-STDERR: " + tail + "\n")
		}
		return Public("incus-compose could not bring the reviewed project up")
	}
	_, err = a.incus(0, "project", "set", incusProject, composeIntentKey+"="+str(build["intentHash"]))
	return err
}

func (a *composeAdapter) recheckAndApply(approved M, verifyOnly bool) (M, error) {
	actual, err := a.observe(str(approved["sourceProject"]), str(approved["project"]), str(approved["revision"]))
	if err != nil {
		return nil, err
	}
	if !equalJSON(composeStableOf(actual), composeStableOf(approved)) {
		return nil, Public("The Compose project changed since review; re-review before deployment")
	}
	if str(actual["action"]) == "noop" {
		return M{"status": "verified", "newEtag": actual["etag"], "health": "Running"}, nil
	}
	if !verifyOnly && str(actual["etag"]) != str(approved["etag"]) {
		return nil, Public("Compose instances changed since review; re-review before deployment")
	}
	if err := a.up(str(approved["sourceProject"]), str(approved["project"]), str(approved["revision"])); err != nil {
		return nil, err
	}
	verified, err := a.observe(str(approved["sourceProject"]), str(approved["project"]), str(approved["revision"]))
	if err != nil {
		return nil, err
	}
	if str(verified["action"]) != "noop" {
		return nil, Public("Compose services are not all running the reviewed images")
	}
	return M{"status": "verified", "newEtag": verified["etag"], "health": "Running"}, nil
}

var _ = path.Base

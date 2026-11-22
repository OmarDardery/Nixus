package main

// Apps repository: a git repository (any SSH host) holding one folder per app:
//
//	<app>/compose.yaml, Dockerfile, ...   source files (Compose apps)
//	<app>/default.nix, <app>/modules/     Nix declaration (optional for Compose)
//	<app>/secrets.enc.yaml                SOPS ciphertext, decryptable only with
//	                                      the host's projects age key
//	backups.nix                           backup policy (no credentials)
//
// Console changes are committed and pushed. Remote commits are fetched on a
// timer and shown for review; they deploy only when someone confirms. The age
// key and the deploy key never enter the repository: they are in the
// encrypted backups and the recovery kit.

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	appsRepoKeyPath    = "/var/lib/nixus-secrets/apps-repo-key"
	appsRepoKnownHosts = "/var/lib/nixus-secrets/apps-repo-known-hosts"
)

var appsRepoConfigPath = "/var/lib/nixus-secrets/apps-repo.json"
var appsRepoRoot = func() string { return filepath.Join(STATE, "apps-repo") }

var repoURL = re(`(?:ssh://([A-Za-z0-9._-]{1,64})@([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?/([A-Za-z0-9._~/-]{1,200})|([A-Za-z0-9._-]{1,64})@([A-Za-z0-9.-]{1,253}):([A-Za-z0-9._~][A-Za-z0-9._~/-]{0,199}))`)
var repoBranch = re(`[A-Za-z0-9][A-Za-z0-9._/-]{0,99}`)

// parseRepoURL returns the SSH host and port of an accepted repository URL.
func parseRepoURL(u string) (string, string, error) {
	m := repoURL.FindStringSubmatch(u)
	if m == nil || m[0] != u || strings.Contains(u, "..") {
		return "", "", Public("Use an SSH URL: git@host:owner/repo.git or ssh://git@host:port/owner/repo.git")
	}
	if m[2] != "" {
		port := m[3]
		if port == "" {
			port = "22"
		}
		return m[2], port, nil
	}
	return m[6], "22", nil
}

// appsRepoConfig is nil until a repository is connected.
func appsRepoConfig() M {
	cfg := readObj(appsRepoConfigPath)
	if str(cfg["url"]) == "" {
		return nil
	}
	return cfg
}

func appsRepoStatusPath() string { return filepath.Join(appsRepoRoot(), "status.json") }
func appsRepoClone() string      { return filepath.Join(appsRepoRoot(), "clone") }
func appsRepoStatus() M {
	s := readObj(appsRepoStatusPath())
	if s == nil {
		s = M{}
	}
	return s
}
func saveAppsRepoStatus(s M) {
	os.MkdirAll(appsRepoRoot(), 0o700)
	writeJSONMode(appsRepoStatusPath(), s, 0o600, "")
}

func gitEnv() []string {
	return []string{"PATH=" + os.Getenv("PATH"), "HOME=/var/empty", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C",
		"GIT_SSH_COMMAND=ssh -i " + appsRepoKeyPath + " -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + appsRepoKnownHosts,
		"GIT_AUTHOR_NAME=Nixus", "GIT_AUTHOR_EMAIL=nixus@localhost", "GIT_COMMITTER_NAME=Nixus", "GIT_COMMITTER_EMAIL=nixus@localhost"}
}

// git runs one git command in the clone; stderr is logged, never returned.
var git = func(args ...string) (string, error) {
	res, err := run(append([]string{"git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-C", appsRepoClone()}, args...),
		nil, 10*time.Minute, gitEnv(), "")
	if err != nil || res.Code != 0 {
		fmt.Fprintln(os.Stderr, "nixus: git", args[0], "failed:", strings.TrimSpace(string(res.Stderr)))
		return "", Public("git " + args[0] + " failed; check the repository URL and that the deploy key has write access")
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// --- console API -----------------------------------------------------------------------

func appsRepoView() M {
	cfg := appsRepoConfig()
	out := M{"configured": cfg != nil, "status": appsRepoStatus()}
	if cfg != nil {
		out["url"], out["branch"], out["fingerprints"] = cfg["url"], cfg["branch"], cfg["fingerprints"]
	}
	if pub, err := os.ReadFile(appsRepoKeyPath + ".pub"); err == nil {
		out["publicKey"] = strings.TrimSpace(string(pub))
	}
	return out
}

func ensureAppsRepoKey() (M, error) {
	if !isFile(appsRepoKeyPath) {
		os.MkdirAll(filepath.Dir(appsRepoKeyPath), 0o700)
		if _, err := check([]string{"ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "nixus-apps-repo", "-f", appsRepoKeyPath}, nil, 30*time.Second); err != nil {
			return nil, Public("Could not create the deploy key")
		}
		os.Chmod(appsRepoKeyPath, 0o600)
	}
	return appsRepoView(), nil
}

// scanAppsRepo fetches the host's SSH keys so their fingerprints can be
// confirmed before anything trusts them.
func scanAppsRepo(body M) (M, error) {
	url := strings.TrimSpace(str(body["url"]))
	host, port, err := parseRepoURL(url)
	if err != nil {
		return nil, err
	}
	// ssh-keyscan tries only the first address of a host; when IPv6 is
	// listed but unreachable it returns nothing, so retry over IPv4.
	var lines []string
	for _, family := range [][]string{nil, {"-4"}} {
		args := append(append([]string{"ssh-keyscan"}, family...), "-T", "10", "-p", port, "-t", "ed25519,ecdsa,rsa", host)
		res, err := run(args, nil, 30*time.Second, nil, "")
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(res.Stdout), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				lines = append(lines, l)
			}
		}
		if len(lines) > 0 {
			break
		}
		fmt.Fprintln(os.Stderr, "nixus: ssh-keyscan", strings.Join(family, ""), host, port+":", strings.TrimSpace(string(res.Stderr)))
	}
	if len(lines) == 0 {
		return nil, Public("Could not reach " + host + " on port " + port)
	}
	known := strings.Join(lines, "\n") + "\n"
	fp, err := run([]string{"ssh-keygen", "-l", "-f", "-"}, []byte(known), 10*time.Second, nil, "")
	if err != nil || fp.Code != 0 {
		return nil, Public("The host returned unreadable SSH keys")
	}
	fingerprints := []any{}
	for _, l := range strings.Split(strings.TrimSpace(string(fp.Stdout)), "\n") {
		fingerprints = append(fingerprints, l)
	}
	os.MkdirAll(appsRepoRoot(), 0o700)
	writeJSONMode(filepath.Join(appsRepoRoot(), "scan.json"), M{"url": url, "knownHosts": known, "fingerprints": fingerprints}, 0o600, "")
	return M{"fingerprints": fingerprints}, nil
}

// connectAppsRepo trusts the scanned host keys, saves the repository and
// checks the deploy key can reach it.
func connectAppsRepo(actor string, body M) (M, error) {
	url, branch := strings.TrimSpace(str(body["url"])), strings.TrimSpace(str(body["branch"]))
	if branch == "" {
		branch = "main"
	}
	if _, _, err := parseRepoURL(url); err != nil {
		return nil, err
	}
	if !fullmatch(repoBranch, branch) || strings.Contains(branch, "..") {
		return nil, Public("Invalid branch name")
	}
	scan := readObj(filepath.Join(appsRepoRoot(), "scan.json"))
	if str(scan["url"]) != url {
		return nil, Public("Check the host key first")
	}
	if !isFile(appsRepoKeyPath) {
		return nil, Public("Create the deploy key first")
	}
	if err := atomicString(appsRepoKnownHosts, str(scan["knownHosts"]), 0o600); err != nil {
		return nil, err
	}
	os.RemoveAll(appsRepoClone())
	if err := initClone(url, branch); err != nil {
		return nil, err
	}
	if _, err := git("ls-remote", "origin"); err != nil {
		return nil, Public("Nixus cannot reach the repository; add the deploy key with write access")
	}
	if err := writeJSONMode(appsRepoConfigPath, M{"url": url, "branch": branch, "fingerprints": scan["fingerprints"], "connectedAt": now()}, 0o600, ""); err != nil {
		return nil, err
	}
	saveAppsRepoStatus(M{})
	audit("apps-repo-connected", M{"principal": actor})
	return checkAppsRepo()
}

func disconnectAppsRepo(actor string) (M, error) {
	os.Remove(appsRepoConfigPath)
	os.RemoveAll(appsRepoRoot())
	audit("apps-repo-disconnected", M{"principal": actor})
	return appsRepoView(), nil
}

func initClone(url, branch string) error {
	if isDir(filepath.Join(appsRepoClone(), ".git")) {
		_, err := git("remote", "set-url", "origin", url)
		return err
	}
	if err := os.MkdirAll(appsRepoClone(), 0o700); err != nil {
		return err
	}
	if _, err := git("init", "-q", "-b", branch); err != nil {
		return err
	}
	_, err := git("remote", "add", "origin", url)
	return err
}

// fetchAppsRepo updates origin/<branch>; an empty repository has no head.
func fetchAppsRepo() (M, string, error) {
	cfg := appsRepoConfig()
	if cfg == nil {
		return nil, "", Public("Connect an apps repository first")
	}
	branch := str(cfg["branch"])
	if err := initClone(str(cfg["url"]), branch); err != nil {
		return nil, "", err
	}
	heads, err := git("ls-remote", "--heads", "origin", branch)
	if err != nil {
		return nil, "", err
	}
	if heads == "" {
		return cfg, "", nil
	}
	if _, err := git("fetch", "-q", "--prune", "origin", "+refs/heads/"+branch+":refs/remotes/origin/"+branch); err != nil {
		return nil, "", err
	}
	head, err := git("rev-parse", "refs/remotes/origin/"+branch)
	return cfg, head, err
}

// checkAppsRepo fetches and summarizes remote changes not yet deployed. With
// none pending it pushes console changes.
func checkAppsRepo() (M, error) {
	_, head, err := fetchAppsRepo()
	status := appsRepoStatus()
	status["checkedAt"] = now()
	if err != nil {
		status["error"] = publicError(err)
		saveAppsRepoStatus(status)
		return nil, err
	}
	delete(status, "error")
	status["remoteHead"] = head
	deployed := str(status["deployedHead"])
	if head != "" && head != deployed && !appsRepoContains(deployed, head) {
		pending, err := pendingChanges(deployed, head)
		if err != nil {
			return nil, err
		}
		status["pending"] = pending
		saveAppsRepoStatus(status)
		return appsRepoView(), nil
	}
	delete(status, "pending")
	saveAppsRepoStatus(status)
	if _, err := exportAppsRepo("console"); err != nil {
		return nil, err
	}
	return appsRepoView(), nil
}

// appsRepoContains: head is already part of what was deployed or pushed.
func appsRepoContains(deployed, head string) bool {
	if deployed == "" {
		return false
	}
	_, err := git("merge-base", "--is-ancestor", head, deployed)
	return err == nil
}

// pendingChanges lists commits and changed app folders from deployed to head.
func pendingChanges(deployed, head string) (M, error) {
	rangeSpec := head
	if _, err := git("cat-file", "-e", deployed+"^{commit}"); deployed != "" && err == nil {
		rangeSpec = deployed + ".." + head
	}
	log, err := git("log", "--format=%h %s", "-n", "30", rangeSpec)
	if err != nil {
		return nil, err
	}
	commits := []any{}
	for _, l := range strings.Split(log, "\n") {
		if l != "" {
			commits = append(commits, l)
		}
	}
	changed, removed, err := changedApps(deployed, head)
	if err != nil {
		return nil, err
	}
	return M{"head": head, "commits": commits, "apps": strings2any(changed), "removed": strings2any(removed)}, nil
}

// isAppFile marks a folder as an app: anything else (docs, CI) is ignored.
func isAppFile(name string) bool {
	switch name {
	case "default.nix", "compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml", "Dockerfile":
		return true
	}
	return false
}

// appDirs lists the app folders of a commit.
func appDirs(rev string) (map[string]bool, error) {
	files, err := git("ls-tree", "-r", "--name-only", rev)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, f := range strings.Split(files, "\n") {
		parts := strings.Split(f, "/")
		if len(parts) == 2 && fullmatch(projectName, parts[0]) && isAppFile(parts[1]) {
			out[parts[0]] = true
		}
	}
	return out, nil
}

// changedApps returns app folders (and backups.nix) changed between two
// commits; every app when there is no base.
func changedApps(base, head string) ([]string, []string, error) {
	if base != "" {
		if _, err := git("cat-file", "-e", base+"^{commit}"); err != nil {
			base = "" // history was rewritten: treat every app as changed
		}
	}
	inHead, err := appDirs(head)
	if err != nil {
		return nil, nil, err
	}
	inBase := map[string]bool{}
	if base != "" {
		inBase, _ = appDirs(base)
	}
	rootFiles, _ := git("ls-tree", "--name-only", head)
	touched := map[string]bool{}
	if base == "" {
		for d := range inHead {
			touched[d] = true
		}
		for _, f := range strings.Split(rootFiles, "\n") {
			if f == "backups.nix" {
				touched[f] = true
			}
		}
	} else {
		names, err := git("diff", "--name-only", base, head)
		if err != nil {
			return nil, nil, err
		}
		for _, n := range strings.Split(names, "\n") {
			top := strings.SplitN(n, "/", 2)[0]
			if n == "backups.nix" || (strings.Contains(n, "/") && fullmatch(projectName, top)) {
				touched[top] = true
			}
		}
	}
	var changed, removed []string
	for d := range touched {
		if d == "backups.nix" || inHead[d] {
			changed = append(changed, d)
		} else if inBase[d] {
			removed = append(removed, d)
		}
	}
	sort.Strings(changed)
	sort.Strings(removed)
	return changed, removed, nil
}

// startAppsRepoDeploy deploys the reviewed remote head in a worker.
func startAppsRepoDeploy(actor string, body M) (M, error) {
	head := str(body["head"])
	pending := obj(appsRepoStatus()["pending"])
	if !fullmatch(re(`[0-9a-f]{40}`), head) || str(pending["head"]) != head {
		return nil, Public("Check the repository again; the reviewed changes are out of date")
	}
	status := appsRepoStatus()
	status["deploy"] = M{"status": "queued", "head": head, "actor": actor, "startedAt": now()}
	saveAppsRepoStatus(status)
	if _, err := check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-apps-repo-deploy",
		"--property=RuntimeMaxSec=14400", "--setenv=NIXUS_STATE=" + STATE, "--setenv=PATH=" + os.Getenv("PATH"),
		adminLauncher(), "admin", "apps-repo", "deploy", head}, nil, 20*time.Second); err != nil {
		return nil, Public("A repository deployment is already running")
	}
	audit("apps-repo-deploy-requested", M{"principal": actor, "head": head})
	return M{"started": true}, nil
}

// --- import ----------------------------------------------------------------------------

type repoApp struct {
	nix     M // workspace-relative path → content
	source  map[string][]byte
	secrets []byte
}

// readRepoApp splits an app folder into Nix files, source files and secrets.
func readRepoApp(dir, name string) (repoApp, error) {
	app := repoApp{nix: M{}, source: map[string][]byte{}}
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return Public(name + "/" + rel + ": only regular files are allowed")
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		total += int64(len(data))
		if total > importMaxTotal || len(app.source) >= importMaxFiles {
			return Public(name + " is too large")
		}
		rel = filepath.ToSlash(rel)
		switch {
		case rel == "secrets.enc.yaml":
			app.secrets = data
		case rel == ".sops.yaml":
		case rel == "default.nix" || (strings.HasPrefix(rel, "modules/") && strings.HasSuffix(rel, ".nix")):
			app.nix[name+"/"+rel] = string(data)
		default:
			app.source[rel] = data
		}
		return nil
	})
	return app, err
}

var repoSource = currentSource

// currentSource returns the published current revision's files of an app.
func currentSource(project string) map[string][]byte {
	publisher := NewPublishedSources("")
	cur, err := publisher.current(project)
	if err != nil || cur == nil {
		return nil
	}
	folder := filepath.Join(publisher.root, project, "revisions", str(cur["revision"]))
	files, err := checkFiles(readObj(filepath.Join(folder, "manifest.json"))["files"])
	if err != nil {
		return nil
	}
	out := map[string][]byte{}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(folder, "source", f.Path))
		if err != nil {
			return nil
		}
		out[f.Path] = data
	}
	return out
}

func sameFiles(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

// publishSourceFiles stages, publishes and builds an app's source files.
func publishSourceFiles(actor, project string, source map[string][]byte) (string, error) {
	names := make([]string, 0, len(source))
	for k := range source {
		names = append(names, k)
	}
	sort.Strings(names)
	entries, files := []any{}, []sourceEntry{}
	for _, n := range names {
		e := sourceEntry{Path: n, Size: int64(len(source[n])), SHA256: sha256hex(source[n])}
		files = append(files, e)
		entries = append(entries, e.M())
	}
	staged, err := stageFiles(actor, project, entries, files, source)
	if err != nil {
		return "", err
	}
	revision, err := publishStaged(actor, staged)
	if err != nil {
		return "", err
	}
	if _, err := buildRevision(actor, project, revision); err != nil {
		return "", err
	}
	return revision, nil
}

// applyRepoApp deploys one app folder: new source, changed Nix, then secrets.
func applyRepoApp(actor, name string, app repoApp) error {
	workspace := NewProjectTransactions("", "").workspace
	changes, refs := M{}, M{}
	if len(app.source) > 0 && !sameFiles(app.source, currentSource(name)) {
		revision, err := publishSourceFiles(actor, name, app.source)
		if err != nil {
			return err
		}
		refs[name] = revision
	}
	for path, content := range app.nix {
		current, _ := os.ReadFile(filepath.Join(workspace, path))
		if string(current) != str(content) {
			changes[path] = content
		}
	}
	if _, ok := app.nix[name+"/default.nix"]; !ok && !isFile(filepath.Join(workspace, name, "default.nix")) {
		if len(app.source) == 0 {
			return Public(name + " has neither a default.nix nor source files")
		}
		changes[name+"/default.nix"] = defaultComposeDeclaration
	}
	if len(changes) > 0 || len(refs) > 0 {
		if _, err := deployChange(actor, changes, refs); err != nil {
			return Public(name + ": " + publicError(err))
		}
	}
	if app.secrets != nil {
		s := NewSecrets("", "", "")
		values, err := s.decode(app.secrets, "")
		if err != nil {
			return Public(name + "/secrets.enc.yaml cannot be decrypted with this server's key; restore the key from a backup or recovery kit")
		}
		current, _ := readEnv(name)
		if !equalJSON(obj(current["vars"]), values) {
			if _, err := saveEnv(actor, name, values, current["revision"]); err != nil {
				return Public(name + " secrets: " + publicError(err))
			}
		}
	}
	return nil
}

// runAppsRepoDeploy is the worker: check out the reviewed head and apply
// every changed app, then record it as deployed and push any console state.
func runAppsRepoDeploy(head string) error {
	status := appsRepoStatus()
	job := obj(status["deploy"])
	actor := str(job["actor"])
	save := func(state string, extra M) {
		job["status"], job["updatedAt"] = state, now()
		for k, v := range extra {
			job[k] = v
		}
		status["deploy"] = job
		saveAppsRepoStatus(status)
	}
	fail := func(err error) error {
		fmt.Fprintln(os.Stderr, "nixus: apps repository deploy failed:", err)
		save("failed", M{"error": publicError(err), "completedAt": now()})
		return err
	}
	save("fetching", nil)
	_, remote, err := fetchAppsRepo()
	if err != nil {
		return fail(err)
	}
	if remote != head {
		return fail(Public("The repository changed after review; check it again"))
	}
	if _, err := git("checkout", "-q", "-f", "-B", str(appsRepoConfig()["branch"]), head); err != nil {
		return fail(err)
	}
	git("clean", "-fdq")
	changed, removed, err := changedApps(str(status["deployedHead"]), head)
	if err != nil {
		return fail(err)
	}
	if err := ensureWorkspace(actor); err != nil {
		return fail(err)
	}
	for _, name := range changed {
		save("deploying", M{"app": name})
		if name == "backups.nix" {
			data, err := os.ReadFile(filepath.Join(appsRepoClone(), "backups.nix"))
			if err != nil {
				return fail(err)
			}
			current, _ := os.ReadFile(filepath.Join(NewProjectTransactions("", "").workspace, "backups.nix"))
			if !bytes.Equal(current, data) {
				if _, err := saveBackupPolicy(actor, string(data)); err != nil {
					return fail(err)
				}
			}
			continue
		}
		app, err := readRepoApp(filepath.Join(appsRepoClone(), name), name)
		if err != nil {
			return fail(err)
		}
		if err := applyRepoApp(actor, name, app); err != nil {
			return fail(err)
		}
	}
	status["deployedHead"] = head
	delete(status, "pending")
	save("deployed", M{"completedAt": now(), "removed": strings2any(removed), "app": nil})
	audit("apps-repo-deployed", M{"principal": actor, "head": head, "apps": len(changed)})
	if _, err := exportAppsRepo("console"); err != nil {
		fmt.Fprintln(os.Stderr, "nixus: apps repository push after deploy failed:", err)
	}
	return nil
}

// --- export ----------------------------------------------------------------------------

// workspaceApps lists apps declared in the project workspace.
func workspaceApps(workspace string) []string {
	entries, _ := os.ReadDir(workspace)
	var out []string
	for _, e := range entries {
		if e.IsDir() && fullmatch(projectName, e.Name()) && isFile(filepath.Join(workspace, e.Name(), "default.nix")) {
			out = append(out, e.Name())
		}
	}
	return out
}

// writeRepoTree makes the clone's app folders mirror the server. Repository
// files outside app folders (README, CI, docs) are left alone. Secrets keep
// the repository's ciphertext when it already holds the same values, so a
// re-encryption never shows up as a change.
func writeRepoTree(clone, workspace string, source func(string) map[string][]byte, sameSecrets func(a, b []byte) bool) error {
	apps := workspaceApps(workspace)
	keep := map[string]bool{}
	for _, a := range apps {
		keep[a] = true
	}
	entries, _ := os.ReadDir(clone)
	for _, e := range entries {
		if e.IsDir() && fullmatch(projectName, e.Name()) && !keep[e.Name()] {
			dir := filepath.Join(clone, e.Name())
			names, _ := os.ReadDir(dir)
			for _, n := range names {
				if isAppFile(n.Name()) {
					os.RemoveAll(dir)
					break
				}
			}
		}
	}
	for _, name := range apps {
		dir := filepath.Join(clone, name)
		oldSecrets, _ := os.ReadFile(filepath.Join(dir, "secrets.enc.yaml"))
		os.RemoveAll(dir)
		files := map[string][]byte{}
		for rel, data := range source(name) {
			files[rel] = data
		}
		filepath.WalkDir(filepath.Join(workspace, name), func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			rel, _ := filepath.Rel(filepath.Join(workspace, name), p)
			rel = filepath.ToSlash(rel)
			if rel == "default.nix" || rel == ".sops.yaml" || rel == "secrets.enc.yaml" || (strings.HasPrefix(rel, "modules/") && strings.HasSuffix(rel, ".nix")) {
				if data, err := os.ReadFile(p); err == nil {
					files[rel] = data
				}
			}
			return nil
		})
		if s, ok := files["secrets.enc.yaml"]; ok && oldSecrets != nil && sameSecrets(oldSecrets, s) {
			files["secrets.enc.yaml"] = oldSecrets
		}
		for rel, data := range files {
			p := filepath.Join(dir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				return err
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(workspace, "backups.nix")); err == nil {
		if err := os.WriteFile(filepath.Join(clone, "backups.nix"), data, 0o644); err != nil {
			return err
		}
	}
	if !isFile(filepath.Join(clone, "README.md")) {
		os.WriteFile(filepath.Join(clone, "README.md"), []byte(repoReadme), 0o644)
	}
	return nil
}

const repoReadme = `# Apps

Managed by Nixus. One folder per app:

- ` + "`compose.yaml`" + ` and build files: the app (images pinned by digest).
- ` + "`default.nix`" + `: optional Nix declaration (VMs, containers, options).
- ` + "`secrets.enc.yaml`" + `: environment variables, encrypted with SOPS to the
  server's age key. Edit them in the console's Env tab.

Push changes here and review them in the console under Backups → Apps repository.
Never commit plaintext secrets or private keys.
`

// exportAppsRepo commits the server's app state and pushes it. It refuses
// while the remote has changes nobody reviewed, so it never overwrites them.
func exportAppsRepo(reason string) (M, error) {
	cfg, head, err := fetchAppsRepo()
	if err != nil {
		return nil, err
	}
	status := appsRepoStatus()
	deployed := str(status["deployedHead"])
	if head != "" && head != deployed && !appsRepoContains(deployed, head) {
		return M{"pushed": false, "reason": "remote changes are waiting for review"}, nil
	}
	branch := str(cfg["branch"])
	if head != "" {
		if _, err := git("checkout", "-q", "-f", "-B", branch, head); err != nil {
			return nil, err
		}
	} else if _, err := git("rev-parse", "--verify", "-q", "HEAD"); err == nil {
		git("checkout", "-q", "-f", branch)
	}
	git("clean", "-fdq")
	s := NewSecrets("", "", "")
	same := func(a, b []byte) bool {
		va, err1 := s.decode(a, "")
		vb, err2 := s.decode(b, "")
		return err1 == nil && err2 == nil && equalJSON(va, vb)
	}
	if err := writeRepoTree(appsRepoClone(), NewProjectTransactions("", "").workspace, repoSource, same); err != nil {
		return nil, err
	}
	if _, err := git("add", "-A"); err != nil {
		return nil, err
	}
	if changes, _ := git("status", "--porcelain"); changes == "" {
		status["deployedHead"] = head
		saveAppsRepoStatus(status)
		return M{"pushed": false}, nil
	}
	if _, err := git("commit", "-q", "-m", "nixus: update from "+reason); err != nil {
		return nil, err
	}
	if _, err := git("push", "-q", "origin", "HEAD:refs/heads/"+branch); err != nil {
		status["pushError"] = publicError(err)
		saveAppsRepoStatus(status)
		return nil, err
	}
	pushed, _ := git("rev-parse", "HEAD")
	delete(status, "pushError")
	status["deployedHead"], status["remoteHead"], status["pushedAt"] = pushed, pushed, now()
	saveAppsRepoStatus(status)
	audit("apps-repo-pushed", M{"head": pushed})
	return M{"pushed": true, "head": pushed}, nil
}

// notifyAppsRepo queues a push after a console change. If a push is already
// running, the dirty marker makes that run go round again.
var notifyAppsRepo = func() {
	if appsRepoConfig() == nil {
		return
	}
	os.MkdirAll(appsRepoRoot(), 0o700)
	os.WriteFile(filepath.Join(appsRepoRoot(), "dirty"), nil, 0o600)
	run([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-apps-repo-push",
		"--setenv=NIXUS_STATE=" + STATE, "--setenv=PATH=" + os.Getenv("PATH"),
		adminLauncher(), "admin", "apps-repo", "check"}, nil, 20*time.Second, nil, "")
}

// withRepoLock serializes repository work. It is separate from the mutation
// lock, which the project and secret transactions take themselves.
func withRepoLock[T any](fn func() (T, error)) (T, error) {
	var zero T
	if err := os.MkdirAll(appsRepoRoot(), 0o700); err != nil {
		return zero, err
	}
	release, err := lockFile(filepath.Join(appsRepoRoot(), "lock"), true)
	if err != nil {
		return zero, err
	}
	defer release()
	return fn()
}

func appsRepoCLI(args []string) error {
	switch {
	case len(args) == 1 && args[0] == "check":
		if appsRepoConfig() == nil {
			return nil
		}
		// Repeat while console changes arrive during a run, so none is lost.
		dirty := filepath.Join(appsRepoRoot(), "dirty")
		var out M
		var err error
		for i := 0; i < 5; i++ {
			os.Remove(dirty)
			if out, err = withRepoLock(checkAppsRepo); err != nil || !lexists(dirty) {
				break
			}
		}
		if out != nil {
			printJSON(out)
		}
		return err
	case len(args) == 2 && args[0] == "deploy":
		_, err := withRepoLock(func() (M, error) { return nil, runAppsRepoDeploy(args[1]) })
		return err
	case len(args) == 1 && args[0] == "status":
		printJSON(appsRepoView())
		return nil
	}
	return Public("usage: nixus-admin apps-repo {check|deploy HEAD|status}")
}

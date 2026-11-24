package main

// Runtime secret delivery via read-only Incus disk mounts backed by host tmpfs
// (/run/nixus-secrets/<project>).
//
// The parent directory /run/nixus-secrets is 0700 root:root so unprivileged
// host users cannot traverse it; each per-project bind-mount root is 0755 with
// 0444 secret files, mounted read-only at /run/secrets inside containers.
// Because the mount is a persistent Incus device, secrets survive container
// stop/start/restart automatically with no polling timer or `incus file push`.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var secretMountRoot = "/run/nixus-secrets"

type secretTarget struct{ Instance, Destination, Key string }

// secretTargets decides where each key goes. Without bindings every key is
// delivered to every instance of the app at /run/secrets/<KEY>.
func secretTargets(project M, values M, instances []M) ([]secretTarget, error) {
	bindings := obj(jget(project, "secrets", "bindings"))
	var out []secretTarget
	if len(bindings) == 0 {
		for _, inst := range instances {
			if str(inst["status"]) != "Running" {
				continue
			}
			for _, key := range keys(values) {
				out = append(out, secretTarget{str(inst["name"]), "/run/secrets/" + key, key})
			}
		}
	} else {
		for _, name := range keys(bindings) {
			b := obj(bindings[name])
			key := str(b["key"])
			if _, ok := values[key]; !ok {
				return nil, Public("Secret " + key + " is bound but has no value; add it on the Apps page")
			}
			matched := false
			for _, inst := range instances {
				if str(inst["name"]) == str(b["instance"]) || str(inst["service"]) == str(b["instance"]) {
					matched = true
					if str(inst["status"]) == "Running" {
						out = append(out, secretTarget{str(inst["name"]), str(b["destination"]), key})
					}
				}
			}
			if !matched {
				return nil, Public("Secret " + key + " is bound to " + str(b["instance"]) + ", which does not exist")
			}
		}
	}
	for _, t := range out {
		if !strings.HasPrefix(t.Destination, "/run/secrets/") || strings.Contains(t.Destination+"/", "/../") {
			return nil, Public("Secret destinations must be under /run/secrets/")
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance+out[i].Destination < out[j].Instance+out[j].Destination })
	return out, nil
}

// envValuesFor returns the variables one instance may receive. Without
// bindings every instance gets every key; with bindings an instance only gets
// the keys bound to it (by instance or service name), so a database credential
// never reaches the web container (#105).
func envValuesFor(project M, values M, inst M) M {
	bindings := obj(jget(project, "secrets", "bindings"))
	if len(bindings) == 0 {
		return values
	}
	out := M{}
	for _, name := range keys(bindings) {
		b := obj(bindings[name])
		key := str(b["key"])
		if v, ok := values[key]; ok && (str(inst["name"]) == str(b["instance"]) || str(inst["service"]) == str(b["instance"])) {
			out[key] = v
		}
	}
	return out
}

// appInstances lists an app's instances with their Compose service name.
func appInstances(incus incusFunc, incusProject string) []M {
	out, err := incus(0, "query", "/1.0/instances?recursion=1&project="+incusProject)
	if err != nil {
		return nil
	}
	var result []M
	for _, raw := range list(must(parseJSON([]byte(out)))) {
		inst := obj(raw)
		if isComposeSidecar(incusProject, str(inst["name"])) {
			continue
		}
		result = append(result, M{"name": inst["name"], "service": obj(inst["config"])[composeServiceLabel], "status": inst["status"]})
	}
	return result
}

func projectSecretsDir(project string) string {
	return filepath.Join(secretMountRoot, project)
}

// materializeProjectSecrets atomically syncs decrypted secret files into the
// host tmpfs directory mounted read-only at /run/secrets inside the app's
// containers. Returns the directory path.
func materializeProjectSecrets(project string, values M) (string, error) {
	if !fullmatch(projectName, project) {
		return "", Public("Invalid project name for secrets")
	}
	if err := os.MkdirAll(secretMountRoot, 0o700); err != nil {
		return "", err
	}
	os.Chmod(secretMountRoot, 0o700)
	dir := projectSecretsDir(project)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	os.Chmod(dir, 0o755)
	want := map[string]bool{}
	for _, key := range keys(values) {
		if !fullmatch(secretKey, key) {
			continue
		}
		want[key] = true
		if err := atomic(filepath.Join(dir, key), []byte(str(values[key])), 0o444, ""); err != nil {
			return "", err
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !want[e.Name()] {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return dir, nil
}

func removeProjectSecretsDir(project string) {
	if fullmatch(projectName, project) {
		os.RemoveAll(projectSecretsDir(project))
	}
}

// ensureSecretsDiskMount ensures an existing instance has the read-only
// /run/secrets disk device attached (for native instances or apps created
// before disk-mounted secrets).
var ensureSecretsDiskMount = func(incusProject, instance, sourceDir string) error {
	path := instancePath(incusProject, instance)
	current, etag, err := envAPI("GET", path, nil, "")
	if err != nil {
		return err
	}
	devices := cloneM(obj(current["devices"]))
	if devices == nil {
		devices = M{}
	}
	want := M{"type": "disk", "source": sourceDir, "path": "/run/secrets", "readonly": "true"}
	if equalJSON(devices["nixus-secrets"], want) {
		return nil
	}
	devices["nixus-secrets"] = want
	current["devices"] = devices
	put := M{}
	for _, k := range []string{"architecture", "config", "devices", "ephemeral", "profiles", "stateful", "description"} {
		if v, ok := current[k]; ok {
			put[k] = v
		}
	}
	_, _, err = envAPI("PUT", path, put, etag)
	return err
}

// deliverProjectSecrets materializes one app's secrets onto host tmpfs and
// syncs environment variables to its instances; apps without ciphertext have
// their tmpfs directory cleared. Returns how many secret files are present.
func deliverProjectSecrets(name string, project M) (int, error) {
	if !isTrue(project["enable"]) {
		return 0, nil
	}
	s := NewSecrets("", "", "")
	dir := filepath.Join(s.projects, name)
	ciphertext, err := s.cipher(dir)
	if err != nil {
		return 0, err
	}
	values := M{}
	if ciphertext != nil {
		values, err = s.decode(ciphertext, "")
		if err != nil {
			return 0, err
		}
	}
	if len(values) == 0 {
		if isDir(projectSecretsDir(name)) {
			materializeProjectSecrets(name, M{})
		}
		return 0, nil
	}
	secretDir, err := materializeProjectSecrets(name, values)
	if err != nil {
		return 0, err
	}
	incusProject := str(project["incusProject"])
	instances := appInstances(updateIncus, incusProject)
	targets, err := secretTargets(project, values, instances)
	if err != nil {
		return 0, err
	}
	for _, inst := range instances {
		instName := str(inst["name"])
		if err := ensureSecretsDiskMount(incusProject, instName, secretDir); err != nil {
			return 0, err
		}
		if _, err := injectEnv(incusProject, instName, envValuesFor(project, values, inst)); err != nil {
			return 0, err
		}
	}
	if len(targets) > 0 {
		audit("project-secrets-delivered", M{"project": name, "files": len(targets)})
	}
	return len(values), nil
}

// deliverAllSecrets materializes every published app's secrets onto host tmpfs
// (invoked once at boot before incus-startup.service, and on demand).
func deliverAllSecrets() (M, error) {
	s := NewSecrets("", "", "")
	entries, err := os.ReadDir(s.projects)
	if err != nil {
		if os.IsNotExist(err) {
			return M{"projects": M{}}, nil
		}
		return M{"projects": M{}}, err
	}
	results := M{}
	var failed []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !fullmatch(projectName, name) {
			continue
		}
		ciphertext, err := s.cipher(filepath.Join(s.projects, name))
		if err != nil {
			failed = append(failed, name)
			results[name] = M{"error": publicError(err)}
			continue
		}
		if ciphertext == nil {
			// Ensure an empty mount directory exists so restored/autostarted
			// containers with the read-only /run/secrets disk mount start cleanly.
			if _, err := materializeProjectSecrets(name, M{}); err != nil {
				failed = append(failed, name)
				results[name] = M{"error": publicError(err)}
			}
			continue
		}
		values, err := s.decode(ciphertext, "")
		if err != nil {
			failed = append(failed, name)
			results[name] = M{"error": publicError(err)}
			fmt.Fprintln(os.Stderr, "nixus: secret materialization failed for", name+":", err)
			continue
		}
		if _, err := materializeProjectSecrets(name, values); err != nil {
			failed = append(failed, name)
			results[name] = M{"error": publicError(err)}
			fmt.Fprintln(os.Stderr, "nixus: secret materialization failed for", name+":", err)
			continue
		}
		results[name] = M{"files": len(values)}
	}
	if len(failed) > 0 {
		return M{"projects": results}, Public("Secret materialization failed for: " + strings.Join(failed, ", "))
	}
	return M{"projects": results}, nil
}

// deliverPublishedSecrets updates one app's tmpfs secret files and live
// container environment right after a change.
func deliverPublishedSecrets(name string) M {
	inventory, err := liveInventory()
	project := obj(obj(inventory["projects"])[name])
	if err != nil || project == nil {
		return M{"files": 0, "note": "delivered when the app is deployed"}
	}
	n, err := deliverProjectSecrets(name, project)
	if err != nil {
		return M{"files": n, "error": publicError(err)}
	}
	return M{"files": n}
}

// liveInventory is the inventory of the last published project review or,
// on a freshly restored host without one, of the live workspace.
func liveInventory() (M, error) {
	t := NewProjectTransactions("", "")
	if _, inventory, err := publishedProjectPolicy(t); err == nil && inventory != nil {
		return inventory, nil
	}
	if _, err := validateWorkspace(t.workspace, true); err != nil {
		return nil, nil
	}
	return evaluateProjects(t.workspace, tokenHex(16))
}

// backupKeyFiles are the credentials that let a new host decrypt and reach
// its secrets and backups. They are read in place by restic, so they only
// ever leave the host inside the encrypted snapshot.
var backupKeyFiles = []string{projectsIdentity, hostKeyFile, "/var/lib/nixus-secrets"}

func presentKeyFiles() []string {
	var out []string
	for _, p := range backupKeyFiles {
		if lexists(p) && !isSymlink(p) {
			out = append(out, p)
		}
	}
	return out
}

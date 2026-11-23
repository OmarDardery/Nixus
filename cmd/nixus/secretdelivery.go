package main

// Runtime secret delivery. Each app's SOPS ciphertext is decrypted on the host
// with the projects age identity and every value is written into the app's
// instances as a file, the Docker/Compose secrets convention:
// /run/secrets/<KEY>, root-owned, mode 0444. Plaintext only touches a
// root-only tmpfs file for the duration of one push. A container's /run is
// cleared on restart, so delivery also runs at boot and on a timer.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var secretDeliveryDir = "/run/nixus-secret-delivery"

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
// the keys bound to it (by instance or service name), the same rule file
// delivery follows, so a database credential never reaches the web container (#105).
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
		if isDNSSidecar(incusProject, str(inst["name"])) {
			continue
		}
		result = append(result, M{"name": inst["name"], "service": obj(inst["config"])[composeServiceLabel], "status": inst["status"]})
	}
	return result
}

// pushSecret writes one value into an instance through a root-only tmpfs file.
var pushSecret = func(incusProject, instance, destination string, value []byte) error {
	if err := os.MkdirAll(secretDeliveryDir, 0o700); err != nil {
		return err
	}
	os.Chmod(secretDeliveryDir, 0o700)
	f, err := os.CreateTemp(secretDeliveryDir, "s-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	f.Chmod(0o600)
	if _, err := f.Write(value); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if _, err := updateIncus(60*time.Second, "file", "push", f.Name(), instance+destination, "--project", incusProject,
		"--uid", "0", "--gid", "0", "--mode", "0444", "--create-dirs"); err != nil {
		return Public("Could not deliver a secret to " + instance)
	}
	return nil
}

// deliverProjectSecrets delivers one app's secrets; apps without ciphertext
// are skipped. Returns how many files were written.
func deliverProjectSecrets(name string, project M) (int, error) {
	if !isTrue(project["enable"]) {
		return 0, nil
	}
	s := NewSecrets("", "", "")
	dir := filepath.Join(s.projects, name)
	ciphertext, err := s.cipher(dir)
	if err != nil || ciphertext == nil {
		return 0, err
	}
	values, err := s.decode(ciphertext, "")
	if err != nil {
		return 0, err
	}
	if len(values) == 0 {
		return 0, nil
	}
	instances := appInstances(updateIncus, str(project["incusProject"]))
	targets, err := secretTargets(project, values, instances)
	if err != nil {
		return 0, err
	}
	for _, inst := range instances {
		if _, err := injectEnv(str(project["incusProject"]), str(inst["name"]), envValuesFor(project, values, inst)); err != nil {
			return 0, err
		}
	}
	for _, t := range targets {
		if err := pushSecret(str(project["incusProject"]), t.Instance, t.Destination, []byte(str(values[t.Key]))); err != nil {
			return 0, err
		}
	}
	if len(targets) > 0 {
		audit("project-secrets-delivered", M{"project": name, "files": len(targets)})
	}
	return len(targets), nil
}

// deliverAllSecrets re-delivers every published app's secrets (boot/timer).
func deliverAllSecrets() (M, error) {
	inventory, err := liveInventory()
	if err != nil || inventory == nil {
		return M{"projects": M{}}, err
	}
	results := M{}
	var failed []string
	for _, name := range keys(obj(inventory["projects"])) {
		n, err := deliverProjectSecrets(name, obj(obj(inventory["projects"])[name]))
		if err != nil {
			failed = append(failed, name)
			results[name] = M{"error": publicError(err)}
			fmt.Fprintln(os.Stderr, "nixus: secret delivery failed for", name+":", err)
			continue
		}
		results[name] = M{"files": n}
	}
	if len(failed) > 0 {
		return M{"projects": results}, Public("Secret delivery failed for: " + strings.Join(failed, ", "))
	}
	return M{"projects": results}, nil
}

// deliverPublishedSecrets delivers one app's secrets right after a change,
// reporting rather than failing: the timer retries.
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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// deleteApp removes an app and everything Nixus and Incus hold for it: its
// files in the project workspace (with its encrypted variables), the Incus
// project with all instances, snapshots, volumes, images, profiles and
// networks (Incus's force delete), published source revisions,
// image build records, deployment and update records, drafts and holds.
// Every step skips what is already gone, so a failed delete can be retried.
// Off-host backups are kept: each snapshot holds all apps together and ages
// out under the retention policy.
func deleteApp(actor string, body M) (M, error) {
	project := str(body["project"])
	if !fullmatch(projectName, project) {
		return nil, Public("Choose an app")
	}
	if str(body["confirm"]) != project {
		return nil, Public("Type the app's name to confirm")
	}
	if appJobActive(project) || activeProjectDeployment(STATE) != "" {
		return nil, Public("Wait for the running deployment to finish, then delete the app")
	}
	inventory, err := liveInventory()
	if err != nil {
		return nil, Public("App inventory unavailable; retry when it can be verified")
	}
	incusProjects, err := appIncusProjects(project, obj(obj(inventory["projects"])[project]))
	if err != nil {
		return nil, err
	}

	// 1. The app's files and variables leave the workspace through a normal
	// review, so the published source stays consistent.
	t := NewProjectTransactions("", "")
	if isFile(filepath.Join(t.workspace, project, "default.nix")) {
		review, err := t.review(M{project + "/": nil}, actor, nil)
		if err != nil {
			return nil, err
		}
		if _, err := t.publish(review["id"], review["planHash"]); err != nil {
			t.cancel(review["id"])
			return nil, err
		}
	}
	// 2. Incus removes the project and everything in it.
	for _, name := range incusProjects {
		if err := deleteIncusProject(name); err != nil {
			return nil, Failed("The app's files were removed, but Incus could not delete project "+name+"; retry the delete", err)
		}
	}
	// 3. Nixus's own records.
	b := NewOCIBuilds("", nil)
	os.RemoveAll(filepath.Join(b.publisher.root, project))
	entries, _ := os.ReadDir(b.jobs)
	for _, e := range entries {
		dir := filepath.Join(b.jobs, e.Name())
		if fullmatch(jobID, e.Name()) && !isSymlink(dir) && str(readObj(filepath.Join(dir, "job.json"))["project"]) == project {
			os.RemoveAll(dir)
		}
	}
	os.RemoveAll(filepath.Join(NewSecrets("", "", "").state, "projects", project))
	for _, p := range []string{appJobPath(project), appEnvPath(project), draftPath(project), updateJournalPath(project)} {
		os.Remove(p)
	}
	forgetKey(imageHoldsPath(), project)
	if updates := readObj(imageUpdatesPath()); updates != nil {
		delete(obj(updates["projects"]), project)
		writeJSON(imageUpdatesPath(), updates)
	}
	audit("app-deleted", M{"principal": actor, "project": project, "incusProjects": strings2any(incusProjects)})
	out := M{"deleted": project}
	if str(readObj(appsRepoConfigPath)["url"]) != "" {
		out["note"] = "If " + project + " is in your apps repository, remove it there too or the next sync deploys it again."
	}
	return out, nil
}

// appIncusProjects returns the Incus projects that belong to the app and that
// Nixus owns; anything else is never deleted.
func appIncusProjects(project string, declared M) ([]string, error) {
	// A failed lookup must not look like an empty inventory: source and
	// recovery records must survive until the runtime can be verified.
	raw, err := updateIncus(30*time.Second, "query", "/1.0/projects?recursion=1")
	if err != nil {
		return nil, Public("Incus inventory unavailable; no app files were removed")
	}
	payload, err := parseJSON([]byte(raw))
	items, ok := payload.([]any)
	if err != nil || !ok {
		return nil, Public("Invalid Incus inventory; no app files were removed")
	}
	configs := map[string]M{}
	for _, item := range items {
		p := obj(item)
		if str(p["name"]) == "" || obj(p["config"]) == nil {
			return nil, Public("Invalid Incus project; no app files were removed")
		}
		configs[str(p["name"])] = obj(p["config"])
	}
	candidates := []string{str(declared["incusProject"])}
	if derived, err := incusProjectName(project); err == nil {
		candidates = append(candidates, derived)
	}
	var out []string
	seen := map[string]bool{}
	for _, name := range candidates {
		if name == "" || name == "default" || seen[name] {
			continue
		}
		seen[name] = true
		config := configs[name]
		if str(config[imageOwnerKey]) != "true" {
			continue
		}
		if owner := str(config[projectNameKey]); owner != "" && owner != project {
			continue
		}
		if str(config[projectNameKey]) == "" && str(config[imageBackendKey]) != composeBackend {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

// deleteIncusProject removes an Incus project and everything in it through the
// API (projects_force_delete). The CLI's `project delete --force` always asks
// for confirmation on stdin, which a service cannot answer.
func deleteIncusProject(name string) error {
	if _, err := updateIncus(0, "query", "-X", "DELETE", "/1.0/projects/"+name+"?force=true"); err != nil {
		return err
	}
	// The app's network lives in the default project (features.networks is
	// off), so the project delete leaves it.
	if incusQueryObj(updateIncus, "/1.0/networks/"+appNetworkName(name)) != nil {
		if _, err := updateIncus(0, "query", "-X", "DELETE", "/1.0/networks/"+appNetworkName(name)); err != nil {
			return Failed("Could not delete the app's network", err)
		}
	}
	// incus-compose's DNS sidecar holds a client certificate restricted to the
	// project; the trust store is outside the project, so remove it too.
	out, err := updateIncus(0, "query", "/1.0/certificates?recursion=1")
	if err != nil {
		return nil
	}
	certs, err := parseJSON([]byte(out))
	if err != nil {
		return nil
	}
	for _, raw := range list(certs) {
		cert := obj(raw)
		if str(cert["name"]) == "ic-dns-"+name && fullmatch(re(`[0-9a-f]{64}`), str(cert["fingerprint"])) {
			updateIncus(0, "query", "-X", "DELETE", "/1.0/certificates/"+str(cert["fingerprint"]))
		}
	}
	return nil
}

func forgetKey(path, key string) {
	m := readObj(path)
	if _, ok := m[key]; !ok {
		return
	}
	delete(m, key)
	if err := writeJSONMode(path, m, 0o640, ""); err != nil {
		fmt.Fprintln(os.Stderr, "nixus: could not update", path, err)
	}
}

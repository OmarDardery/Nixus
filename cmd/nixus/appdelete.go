package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// deleteApp removes an app and everything Nixus and Incus hold for it: its
// files in the project workspace (with its encrypted variables), the Incus
// project with all instances, snapshots, volumes, images, profiles and
// networks (`incus project delete --force`), published source revisions,
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
	inventory, _ := liveInventory()
	incusProjects := appIncusProjects(project, obj(obj(inventory["projects"])[project]))

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
		if _, err := updateIncus(0, "project", "delete", name, "--force"); err != nil {
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
func appIncusProjects(project string, declared M) []string {
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
		config := obj(incusQueryObj(updateIncus, "/1.0/projects/"+name)["config"])
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
	return out
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

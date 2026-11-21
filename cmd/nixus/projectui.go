package main

// Read-only views behind the Projects console: a per-project overview that
// joins the reviewed inventory, published sources, deployment journal, live
// Incus state and backup coverage; current project Nix file content for the
// editor; and bounded instance logs. Nothing here mutates state.

import (
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

var editableProjectFile = re(`(?:backups\.nix|[a-z][a-z0-9-]{0,62}/(?:default\.nix|modules/(?:[A-Za-z0-9][A-Za-z0-9_-]*/)*[A-Za-z0-9][A-Za-z0-9_-]*\.nix))`)

// lastProjectJob returns the latest reviewed transaction's inventory and plan.
func lastProjectJob(t *ProjectTransactions) (M, M, M) {
	id := str(readObj(filepath.Join(t.state, "project-last.json"))["id"])
	if id == "" {
		id = str(readObj(filepath.Join(t.state, "project-active.json"))["id"])
	}
	if id == "" {
		return nil, nil, nil
	}
	dir, err := t.job(id)
	if err != nil {
		return nil, nil, nil
	}
	status, _ := t.status(id)
	return readObj(filepath.Join(dir, "inventory.json")), readObj(filepath.Join(dir, "runtime-plan.json")), status
}

func runtimeInstances(incusProject string) []any {
	out := []any{}
	for _, raw := range incusQueryList(nativeIncus, "/1.0/instances?recursion=1&project="+url.QueryEscape(incusProject)) {
		i := obj(raw)
		out = append(out, M{"name": i["name"], "type": i["type"], "status": truncate(str(i["status"]), 32),
			"owned": str(jget(i, "config", OWNER)) == "true", "compose": str(jget(i, "config", composeServiceLabel)) != ""})
	}
	return out
}

func projectOverview() M {
	t := NewProjectTransactions("", "")
	inventory, plan, transaction := lastProjectJob(t)
	if inventory == nil {
		return M{"available": false, "projects": []any{}, "reason": "no reviewed project revision yet"}
	}
	coverage := obj(projectBackupStatus()["coverage"])
	publisher := NewPublishedSources("")
	retained := map[string][]any{}
	for _, r := range list(plan["retained"]) {
		p := str(obj(r)["project"])
		retained[p] = append(retained[p], r)
	}
	projects := []any{}
	all := obj(inventory["projects"])
	for _, name := range keys(all) {
		p := obj(all[name])
		incusProject := str(p["incusProject"])
		entry := M{"name": name, "backend": p["backend"], "enable": p["enable"], "incusProject": incusProject,
			"resources": p["resources"], "declaredInstances": strings2any(keys(obj(p["instances"]))),
			"declaredVolumes": strings2any(keys(obj(p["volumes"]))), "claims": p["claims"],
			"backup": p["backup"], "backupCoverage": coverage[name], "retained": retained[incusProject]}
		if current, err := publisher.current(name); err == nil && current != nil {
			entry["sourceRevision"] = current["revision"]
		}
		entry["instances"] = runtimeInstances(incusProject)
		projects = append(projects, entry)
	}
	deployment := M{}
	if transaction != nil {
		for _, k := range []string{"id", "status", "deployment", "deploymentResources", "recoveryRequired", "candidateHash"} {
			deployment[k] = transaction[k]
		}
	}
	return M{"available": true, "projects": projects, "transaction": deployment, "backupPolicy": inventory["backups"] != nil}
}

// projectFile returns the current reviewed text of one editable Nix file.
func projectFile(path string) (M, error) {
	if !fullmatch(editableProjectFile, path) || strings.Contains("/"+path+"/", "/../") {
		return nil, Public("Only project default.nix, modules/**/*.nix and backups.nix can be opened")
	}
	t := NewProjectTransactions("", "")
	live, err := ownedWorkspace(t.workspace)
	if err != nil {
		return nil, err
	}
	manifest, err := validateWorkspace(live, true)
	if err != nil {
		return nil, err
	}
	entry := obj(obj(manifest["files"])[path])
	if entry == nil {
		return M{"path": path, "exists": false, "content": ""}, nil
	}
	if size, _ := intValue(entry["size"]); size > 65536 {
		return nil, Public("The file exceeds the 64 KiB editor limit")
	}
	data, err := safeBytes(live, path, entry)
	if err != nil {
		return nil, err
	}
	return M{"path": path, "exists": true, "content": string(data), "sha256": entry["sha256"], "workspaceHash": manifest["sourceHash"]}, nil
}

// projectLog returns a bounded instance log for a project-declared namespace.
func projectLog(incusProject, instance string) (M, error) {
	if !fullmatch(projectName, incusProject) || !fullmatch(incusIdent, instance) || len(instance) > 63 {
		return nil, Public("Choose a project instance")
	}
	inventory, _, _ := lastProjectJob(NewProjectTransactions("", ""))
	known := false
	for _, p := range obj(inventory["projects"]) {
		known = known || str(obj(p)["incusProject"]) == incusProject
	}
	if !known {
		return nil, Public("Logs are available only for Incus projects declared in the reviewed workspace")
	}
	res, err := run([]string{"incus", "--force-local", "info", instance, "--project", incusProject, "--show-log"}, nil, 15*time.Second, nil, "")
	if err != nil || res.Code != 0 {
		return nil, Public("The instance log is unavailable")
	}
	text := strings.ToValidUTF8(string(res.Stdout), "?")
	truncated := false
	if len(text) > 65536 {
		text, truncated = text[len(text)-65536:], true
	}
	return M{"project": incusProject, "instance": instance, "log": text, "truncated": truncated}, nil
}

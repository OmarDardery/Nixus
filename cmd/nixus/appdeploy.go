package main

// One-step app deployment for the portal. The worker runs the same reviewed,
// hash-checked steps the individual broker actions expose: publish the staged
// source, build it offline, then review, publish and deploy the project
// revision. A Nix-only app skips the source steps.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultComposeDeclaration = "{ ... }: {\n  nixus.project.backend = \"incus-compose\";\n}\n"

func appJobPath(project string) string { return filepath.Join(STATE, "app-deploy-"+project+".json") }

// appEnvPath holds variables entered with a deploy until the app exists and
// they can join its secrets. The file is age ciphertext to the projects key;
// plaintext never touches disk. Removed after use.
func appEnvPath(project string) string {
	return filepath.Join(STATE, "app-deploy-"+project+".env.age")
}

func sealDeployEnv(project string, vars M) error { return sealVars(appEnvPath(project), vars) }

func openDeployEnv(project string) (M, error) { return openVars(appEnvPath(project)) }

// sealVars encrypts variables to the secrets key; the plaintext never touches disk.
func sealVars(path string, vars M) error {
	recipient, err := NewSecrets("", "", "").recipient()
	if err != nil {
		return Public("Create the secrets encryption key first: Backups → Encryption key & recovery kit")
	}
	sealed, err := secretRun([]string{"age", "-r", recipient}, jsonFile(vars), "")
	if err != nil {
		return err
	}
	return atomic(path, sealed, 0o600, "")
}

func openVars(path string) (M, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plain, err := secretRun([]string{"age", "-d", "-i", NewSecrets("", "", "").identity}, sealed, "")
	if err != nil {
		return nil, err
	}
	return parseObject(plain)
}

// deployEnv validates variables sent with a deploy, with the same rules as
// the Environment Variables tab. Nil means none were sent.
func deployEnv(raw any) (M, error) {
	if raw == nil {
		return nil, nil
	}
	m, ok := raw.(M)
	if !ok || len(m) > 64 {
		return nil, Public("Keep up to 64 variables")
	}
	total := 0
	for name, text := range m {
		if !fullmatch(secretKey, name) || !validSecretText(text) {
			return nil, Public("Variable names use letters, digits and _; values are text up to 8 KiB")
		}
		total += len(text.(string))
	}
	if total > maxPlaintext {
		return nil, Public("Variables exceed 64 KiB in total")
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

// applyDeployEnv adds the variables to the app's encrypted secrets and
// delivers them into its instances, keeping variables it already had.
func applyDeployEnv(actor, project string, vars M) error {
	s := NewSecrets("", "", "")
	_, err := lockedValue(true, func() (M, error) {
		dir, err := s.project(project)
		if err != nil {
			return nil, err
		}
		existing, err := s.cipher(dir)
		if err != nil {
			return nil, err
		}
		review, err := s.review(actor, project, nil, "import", vars, hashOrNil(existing))
		if err != nil {
			return nil, err
		}
		return s.publish(actor, review["reviewId"], true)
	})
	if err != nil {
		return err
	}
	deliverPublishedSecrets(project)
	return nil
}

func appJobs() M {
	out := M{}
	matches, _ := filepath.Glob(filepath.Join(STATE, "app-deploy-*.json"))
	for _, p := range matches {
		job := readObj(p)
		if name := str(job["project"]); fullmatch(projectName, name) {
			delete(job, "declaration")
			out[name] = job
		}
	}
	return out
}

func appJobActive(project string) bool {
	switch str(readObj(appJobPath(project))["status"]) {
	case "", "deployed", "failed":
		return false
	}
	return true
}

// startAppDeploy validates a request, records it and starts the worker unit.
func startAppDeploy(actor string, body M) (M, error) {
	project, _ := body["project"].(string)
	if !fullmatch(projectName, project) {
		return nil, Public("Use a lowercase name: letters, digits and dashes")
	}
	if appJobActive(project) {
		return nil, Public("A deployment for this app is already running")
	}
	job := M{"format": 1, "project": project, "actor": actor, "status": "queued", "startedAt": now()}
	declaration, _ := body["declaration"].(string)
	if len(declaration) > 65536 || strings.Contains(declaration, "\x00") {
		return nil, Public("The Nix declaration is too large")
	}
	switch str(body["kind"]) {
	case "source":
		id, ok1 := body["stagingId"].(string)
		hash, ok2 := body["manifestHash"].(string)
		if !ok1 || !ok2 || !fullmatch(jobID, id) || !fullmatch(hex64, hash) {
			return nil, Public("Upload or paste the app's files first")
		}
		job["kind"], job["stagingId"], job["manifestHash"] = "source", id, hash
	case "nix":
		if strings.TrimSpace(declaration) == "" {
			return nil, Public("Enter the app's Nix declaration")
		}
		job["kind"] = "nix"
	default:
		return nil, Public("Choose files or a Nix declaration")
	}
	if strings.TrimSpace(declaration) != "" {
		job["declaration"] = declaration
	}
	vars, err := deployEnv(body["env"])
	if err != nil {
		return nil, err
	}
	os.Remove(appEnvPath(project))
	if vars != nil {
		if err := sealDeployEnv(project, vars); err != nil {
			return nil, err
		}
		job["envKeys"] = strings2any(keys(vars))
	}
	if err := writeJSONMode(appJobPath(project), job, 0o600, ""); err != nil {
		os.Remove(appEnvPath(project))
		return nil, err
	}
	if _, err := check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-app-deploy-" + project,
		"--property=RuntimeMaxSec=7200", "--setenv=NIXUS_STATE=" + STATE, "--setenv=PATH=" + os.Getenv("PATH"),
		"--setenv=NIXUS_OCI_VM_TEST=" + os.Getenv("NIXUS_OCI_VM_TEST"),
		adminLauncher(), "admin", "apps", "deploy", project}, nil, 20*time.Second); err != nil {
		job["status"], job["error"] = "failed", "Could not start the deployment worker"
		writeJSONMode(appJobPath(project), job, 0o600, "")
		os.Remove(appEnvPath(project))
		return nil, Public("Could not start the deployment worker")
	}
	audit("app-deploy-requested", M{"principal": actor, "project": project, "kind": job["kind"]})
	delete(job, "declaration")
	return job, nil
}

// ensureWorkspace creates an empty reviewed workspace on first use.
func ensureWorkspace(actor string) error {
	t := NewProjectTransactions("", "")
	if lexists(t.workspace) {
		return nil
	}
	_, err := t.initialize("{ outputs = { self }: {}; }\n", `{"nodes":{"root":{}},"root":"root","version":7}`, actor)
	return err
}

// deployChange reviews, publishes and deploys Nix edits and/or source
// rebinds, waiting for the deployment to verify.
func deployChange(actor string, changes, refs M) (string, error) {
	t := NewProjectTransactions("", "")
	var sourceRefs any
	if len(refs) > 0 {
		sourceRefs = refs
	}
	review, err := t.review(changes, actor, sourceRefs)
	if err != nil {
		return "", err
	}
	id := str(review["id"])
	if _, err := t.publish(review["id"], review["planHash"]); err != nil {
		t.cancel(id)
		return id, err
	}
	if _, err := t.deploy(review["id"], review["planHash"], false); err != nil {
		return id, err
	}
	deadline := time.Now().Add(45 * time.Minute)
	for time.Now().Before(deadline) {
		status, err := t.status(id)
		if err != nil {
			return id, err
		}
		switch str(status["deployment"]) {
		case "verified":
			return id, nil
		case "partial", "interrupted":
			detail := str(status["deploymentError"])
			if detail == "" {
				detail = "deployment stopped"
			}
			return id, Public(detail)
		}
		time.Sleep(updatePoll)
	}
	return id, Public("The deployment timed out")
}

func runAppDeploy(project string) error {
	if !fullmatch(projectName, project) {
		return Public("Invalid app name")
	}
	job := readObj(appJobPath(project))
	if str(job["status"]) != "queued" {
		return Public("No queued deployment for this app")
	}
	actor := str(job["actor"])
	defer os.Remove(appEnvPath(project))
	save := func(status string, extra M) {
		job["status"], job["updatedAt"] = status, now()
		for k, v := range extra {
			job[k] = v
		}
		writeJSONMode(appJobPath(project), job, 0o600, "")
	}
	var deploymentID string
	fail := func(err error) error {
		fmt.Fprintln(os.Stderr, "nixus: app deployment failed:", err)
		if deploymentID != "" {
			// Release a stopped deployment so the app can be fixed and redeployed.
			NewProjectTransactions("", "").abandonDeployment(deploymentID, "app deployment failed")
		}
		save("failed", M{"error": publicError(err), "completedAt": now()})
		audit("app-deploy-failed", M{"project": project})
		return err
	}
	save("preparing", nil)
	if err := ensureWorkspace(actor); err != nil {
		return fail(err)
	}
	changes, refs := M{}, M{}
	declaration := str(job["declaration"])
	declared := isFile(filepath.Join(NewProjectTransactions("", "").workspace, project, "default.nix"))
	if str(job["kind"]) == "source" {
		save("publishing", nil)
		revision, err := publishStaged(actor, M{"id": job["stagingId"], "manifestHash": job["manifestHash"]})
		if err != nil {
			return fail(err)
		}
		save("building", M{"revision": revision})
		if _, err := buildRevision(actor, project, revision); err != nil {
			return fail(err)
		}
		refs[project] = revision
		if declaration == "" && !declared {
			declaration = defaultComposeDeclaration
		}
	}
	if declaration != "" {
		changes[project+"/default.nix"] = declaration
	}
	save("deploying", nil)
	id, err := deployChange(actor, changes, refs)
	deploymentID = id
	if err != nil {
		return fail(err)
	}
	if isFile(appEnvPath(project)) {
		save("configuring", nil)
		vars, err := openDeployEnv(project)
		os.Remove(appEnvPath(project))
		if err == nil {
			err = applyDeployEnv(actor, project, vars)
		}
		if err != nil {
			return fail(Public("Deployed, but the environment variables were not saved: " + publicError(err)))
		}
	}
	delete(job, "declaration")
	save("deployed", M{"completedAt": now(), "error": nil})
	deleteDraft(project) // the form is no longer needed once the app is live
	audit("app-deployed", M{"project": project, "kind": job["kind"]})
	return nil
}

func appsCLI(args []string) error {
	if len(args) == 2 && args[0] == "deploy" {
		return runAppDeploy(args[1])
	}
	if len(args) == 1 && args[0] == "status" {
		printJSON(appJobs())
		return nil
	}
	if len(args) == 1 && args[0] == "deliver-secrets" {
		result, err := deliverAllSecrets()
		if result != nil {
			printJSON(result)
		}
		return err
	}
	return Public("usage: nixus-admin apps {status|deploy APP|deliver-secrets}")
}

// saveBackupPolicy reviews and publishes backups.nix in one step. The policy
// is evaluated and validated by the normal project review.
func saveBackupPolicy(actor string, text any) (M, error) {
	policy, ok := text.(string)
	if !ok || strings.TrimSpace(policy) == "" || len(policy) > 65536 {
		return nil, Public("Enter the backup policy")
	}
	if err := ensureWorkspace(actor); err != nil {
		return nil, err
	}
	t := NewProjectTransactions("", "")
	review, err := t.review(M{"backups.nix": policy}, actor, nil)
	if err != nil {
		return nil, err
	}
	if _, err := t.publish(review["id"], review["planHash"]); err != nil {
		t.cancel(review["id"])
		return nil, err
	}
	audit("backup-policy-saved", M{"principal": actor})
	return M{"saved": true}, nil
}

// startProjectBackup runs the published backup policy now in a worker unit.
func startProjectBackup(actor string) (M, error) {
	if _, err := check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-project-backup-now",
		"--property=RuntimeMaxSec=43200", "--setenv=NIXUS_STATE=" + STATE, "--setenv=PATH=" + os.Getenv("PATH"),
		adminLauncher(), "admin", "project-backup", "run"}, nil, 20*time.Second); err != nil {
		return nil, Public("A backup is already running")
	}
	audit("project-backup-requested", M{"principal": actor})
	return M{"started": true}, nil
}

// appPower starts, stops or restarts every instance of an app.
func appPower(actor string, body M) (M, error) {
	project, action := str(body["project"]), str(body["action"])
	if !fullmatch(projectName, project) || (action != "start" && action != "stop" && action != "restart") {
		return nil, Public("Choose an app and start, stop or restart")
	}
	inventory, _ := liveInventory()
	p := obj(obj(inventory["projects"])[project])
	if p == nil {
		return nil, Public("Unknown app")
	}
	incusProject := str(p["incusProject"])
	instances := appInstances(updateIncus, incusProject)
	if len(instances) == 0 {
		return nil, Public("The app has no instances")
	}
	for _, inst := range instances {
		running := str(inst["status"]) == "Running"
		if (action == "start" && running) || (action == "stop" && !running) {
			continue
		}
		verb := action
		if action == "restart" && !running {
			verb = "start"
		}
		args := []string{verb, str(inst["name"]), "--project", incusProject}
		if verb != "start" {
			args = append(args, "--timeout", "30")
		}
		if _, err := updateIncus(3*time.Minute, args...); err != nil && verb != "start" {
			// The app ignored the shutdown signal: force it, like docker stop.
			_, err = updateIncus(3*time.Minute, verb, str(inst["name"]), "--project", incusProject, "--force")
			if err != nil {
				return nil, Public("Could not " + action + " " + str(inst["name"]))
			}
		} else if err != nil {
			return nil, Public("Could not " + action + " " + str(inst["name"]))
		}
	}
	if action != "stop" {
		deliverPublishedSecrets(project) // /run/secrets is cleared on restart
	}
	audit("app-power", M{"principal": actor, "project": project, "action": action})
	return M{"done": true}, nil
}

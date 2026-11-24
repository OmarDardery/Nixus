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
	"sync"
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

// appWorkerActive reports whether the transient worker unit for an app is
// running. Tests replace it.
var appWorkerActive = func(project string) bool {
	res, err := run([]string{"systemctl", "is-active", "--quiet", "nixus-app-deploy-" + project}, nil, 10*time.Second, nil, "")
	// If systemd cannot be asked, assume the worker is alive rather than start a second one.
	return err != nil || (res.Code != 3 && res.Code != 4)
}

// appJobActive reports whether a deployment of the app is really running. A
// saved non-terminal job whose worker is gone (reboot, timeout, crash) is
// marked interrupted so the operator can redeploy.
func appJobActive(project string) bool {
	job := readObj(appJobPath(project))
	switch str(job["status"]) {
	case "", "deployed", "failed", "interrupted":
		return false
	}
	updated, ok := num(job["updatedAt"])
	if !ok {
		updated, _ = num(job["startedAt"])
	}
	// A worker is started right after the job is written; give it a moment.
	if now()-updated > 30 && !appWorkerActive(project) {
		job["status"], job["updatedAt"] = "interrupted", now()
		job["error"] = "The deployment stopped before it finished (the server restarted or the worker timed out). Deploy again to retry."
		job["completedAt"] = now()
		writeJSONMode(appJobPath(project), job, 0o600, "")
		audit("app-deploy-interrupted", M{"project": project})
		return false
	}
	return true
}

// appDeployMu keeps two requests for the same app from both passing the
// "already running" check before either has recorded its job.
var appDeployMu sync.Mutex

// startAppDeploy validates a request, records it and starts the worker unit.
func startAppDeploy(actor string, body M) (M, error) {
	appDeployMu.Lock()
	defer appDeployMu.Unlock()
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
	case "network":
		if body["lan"] == nil {
			return nil, Public("Choose the services that get their own LAN address")
		}
		job["kind"] = "network"
	default:
		return nil, Public("Choose files or a Nix declaration")
	}
	if strings.TrimSpace(declaration) != "" {
		job["declaration"] = declaration
	}
	if body["lan"] != nil {
		lan, err := lanSetting(body["lan"])
		if err != nil {
			return nil, err
		}
		job["lan"] = strings2any(lan)
	}
	vars, err := deployEnv(body["env"])
	if err != nil {
		return nil, err
	}
	os.Remove(appEnvPath(project))
	if vars != nil {
		// An existing app gets the variables now, so they show in its
		// Environment Variables tab and every later deploy uses them. A new app
		// does not exist yet; its variables wait sealed until it does.
		if _, perr := NewSecrets("", "", "").project(project); perr == nil {
			if err := applyDeployEnv(actor, project, vars); err != nil {
				return nil, Public("Could not save the variables: " + publicError(err))
			}
		} else if err := sealDeployEnv(project, vars); err != nil {
			return nil, err
		}
		job["envKeys"] = strings2any(keys(vars))
	}
	if err := writeJSONMode(appJobPath(project), job, 0o600, ""); err != nil {
		os.Remove(appEnvPath(project))
		return nil, err
	}
	if _, err := check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-app-deploy-" + project,
		"--property=RuntimeMaxSec=7200", "--setenv=NIXUS_STATE=" + STATE, "--setenv=PATH=" + os.Getenv("PATH"), "--setenv=INCUS_COMPOSE_HEALTHD_IMAGE=" + os.Getenv("INCUS_COMPOSE_HEALTHD_IMAGE"), "--setenv=INCUS_COMPOSE_DNS_IMAGE=" + os.Getenv("INCUS_COMPOSE_DNS_IMAGE"), "--setenv=INCUS_COMPOSE_SLEEP_IMAGE=" + os.Getenv("INCUS_COMPOSE_SLEEP_IMAGE"),
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
	// keepVars saves the variables entered with this deploy as the app's
	// secrets, so a retry or redeploy still has them.
	keepVars := func() error {
		if !isFile(appEnvPath(project)) {
			return nil
		}
		vars, err := openDeployEnv(project)
		if err == nil {
			err = applyDeployEnv(actor, project, vars)
		}
		if err == nil {
			os.Remove(appEnvPath(project))
		}
		return err
	}
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
		// The app's files are published even when its containers failed;
		// keep the variables so fixing and redeploying does not lose them.
		if kerr := keepVars(); kerr != nil {
			fmt.Fprintln(os.Stderr, "nixus: could not keep the app's variables:", kerr)
		}
		if deploymentID != "" {
			// Release a stopped deployment so the app can be fixed and redeployed.
			NewProjectTransactions("", "").abandonDeployment(deploymentID, "app deployment failed")
		}
		save("failed", M{"error": publicError(err), "completedAt": now(), "failedStep": job["status"]})
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
	if lan, ok := job["lan"]; ok {
		names, _ := anyStrings(lan)
		module := filepath.Join(NewProjectTransactions("", "").workspace, project, "modules", lanModule)
		if len(names) > 0 {
			changes[project+"/modules/"+lanModule] = lanModuleText(names)
		} else if isFile(module) {
			changes[project+"/modules/"+lanModule] = nil
		}
	}
	if len(changes) == 0 && len(refs) == 0 {
		delete(job, "declaration")
		save("deployed", M{"completedAt": now(), "error": nil})
		return nil
	}
	save("deploying", nil)
	id, err := deployChange(actor, changes, refs)
	deploymentID = id
	if err != nil {
		return fail(err)
	}
	if isFile(appEnvPath(project)) {
		save("configuring", nil)
		if err := keepVars(); err != nil {
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
		"--property=RuntimeMaxSec=43200", "--setenv=NIXUS_STATE=" + STATE, "--setenv=PATH=" + os.Getenv("PATH"), "--setenv=INCUS_COMPOSE_HEALTHD_IMAGE=" + os.Getenv("INCUS_COMPOSE_HEALTHD_IMAGE"), "--setenv=INCUS_COMPOSE_DNS_IMAGE=" + os.Getenv("INCUS_COMPOSE_DNS_IMAGE"), "--setenv=INCUS_COMPOSE_SLEEP_IMAGE=" + os.Getenv("INCUS_COMPOSE_SLEEP_IMAGE"),
		adminLauncher(), "admin", "project-backup", "run"}, nil, 20*time.Second); err != nil {
		return nil, Public("A backup is already running")
	}
	audit("project-backup-requested", M{"principal": actor})
	return M{"started": true}, nil
}

// appPower starts, stops or restarts an app. Compose apps delegate directly
// to incus-compose; native Incus apps manage their instances directly.
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
	if str(p["backend"]) == composeBackend {
		if handled, err := composeProjectCommand(project, action); handled {
			if err != nil {
				return nil, err
			}
			audit("app-power", M{"principal": actor, "project": project, "action": action})
			return M{"done": true}, nil
		}
	}
	instances := appInstances(updateIncus, incusProject)
	if len(instances) == 0 {
		return nil, Public("The app has no instances")
	}
	for _, inst := range instances {
		running := str(inst["status"]) == "Running"
		if str(p["backend"]) == composeBackend {
			if err := setComposeStopped(updateIncus, incusProject, str(inst["name"]), action == "stop"); err != nil {
				return nil, Public("Could not update the app's stop intent")
			}
		}
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
	audit("app-power", M{"principal": actor, "project": project, "action": action})
	return M{"done": true}, nil
}

// The "own IP on your router" setting lives in the app's own Nix module, so
// it is reviewed, published and backed up with the app.
const lanModule = "nixus-network.nix"

func lanSetting(raw any) ([]string, error) {
	names, ok := anyStrings(raw)
	if !ok || len(names) > 16 {
		return nil, Public("Choose up to 16 services")
	}
	for _, n := range names {
		if !fullmatch(composeServiceName, n) {
			return nil, Public("Invalid service name: " + n)
		}
	}
	return uniqueSorted(names), nil
}

func lanModuleText(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = "\"" + n + "\""
	}
	return "{ ... }: {\n  # Services that also get their own address on the LAN.\n  nixus.project.network.lan.services = [ " + strings.Join(quoted, " ") + " ];\n}\n"
}

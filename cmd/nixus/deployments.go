package main

// Reviewed guest rollout journal and the local Incus transport for existing
// NixOS guests. Host access confirmation never certifies guest health; the
// transport never creates or replaces guest disks.

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const deploymentVersion = 1
const incusLock = "/run/lock/nixus-incus.lock"
const deploymentBoundary = "OS generations only: guest disks, databases, application schemas and external systems are not rolled back."

var storePathRe = re(`/nix/store/[a-z0-9]{32}-[^/\s]+`)
var guestNameRe = re(`[A-Za-z0-9][A-Za-z0-9_.-]{0,62}`)

// DeploymentError is a public, fixed-text guest rollout failure.
type DeploymentError struct{ msg string }

func (e *DeploymentError) Error() string { return e.msg }

func depErr(msg string) error { return &DeploymentError{msg} }

func storePath(v any) (string, error) {
	s, ok := v.(string)
	if !ok || !fullmatch(storePathRe, s) {
		return "", depErr("Expected an immutable local Nix store path")
	}
	return s, nil
}

func activeSystem() string {
	p, _ := filepath.EvalSymlinks("/run/current-system")
	return p
}

func deploymentOrder(targets M) ([]string, error) {
	if len(targets) > 16 {
		return nil, Public("Declare at most 16 deployment targets")
	}
	var result []string
	done, visiting := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(key string) error {
		if visiting[key] {
			return Public("Guest deployment dependency cycle")
		}
		if done[key] {
			return nil
		}
		spec, ok := targets[key]
		if !ok {
			return Public("Guest deployment dependency is not declared")
		}
		visiting[key] = true
		deps, _ := anyStrings(obj(spec)["dependsOn"])
		for _, d := range deps {
			if err := visit(d); err != nil {
				return err
			}
		}
		delete(visiting, key)
		done[key] = true
		result = append(result, key)
		return nil
	}
	for _, key := range keys(targets) {
		if err := visit(key); err != nil {
			return nil, err
		}
	}
	return result, nil
}

var targetKey = re(`[a-z][a-z0-9-]{0,31}`)

func validateDeployments(manifest M) (M, error) {
	if len(manifest) > 16 {
		return nil, Public("Declare at most 16 deployment targets")
	}
	targets := cloneM(manifest)
	if targets == nil {
		targets = M{}
	}
	identities := map[string]bool{}
	for key, raw := range targets {
		spec := obj(raw)
		if !fullmatch(targetKey, key) || spec == nil {
			return nil, Public("Invalid deployment target key")
		}
		for _, k := range []string{"project", "name"} {
			if !fullmatch(guestNameRe, str(spec[k])) {
				return nil, Public("Invalid deployment guest identity")
			}
		}
		identity := str(spec["project"]) + "/" + str(spec["name"])
		if identities[identity] {
			return nil, Public("Duplicate deployment guest identity")
		}
		identities[identity] = true
		for _, f := range []string{"system", "probe"} {
			if _, err := storePath(spec[f]); err != nil {
				return nil, err
			}
		}
		if p := str(spec["restartPolicy"]); p != "defer" && p != "reboot" {
			return nil, Public("Unsupported guest restart policy")
		}
		if _, ok := anyStrings(spec["dependsOn"]); !ok || spec["dependsOn"] == nil {
			return nil, Public("Invalid deployment dependencies")
		}
		for _, f := range []struct {
			name string
			max  int
		}{{"maxAttempts", 5}, {"healthTimeout", 300}} {
			v, ok := intValue(spec[f.name])
			if !ok || v < 1 || v > f.max {
				return nil, Public("Invalid deployment retry/health bound")
			}
		}
		if _, ok := spec["rollbackOnFailure"].(bool); !ok {
			return nil, Public("Invalid deployment rollback policy")
		}
	}
	if _, err := deploymentOrder(targets); err != nil {
		return nil, err
	}
	return targets, nil
}

// --- guest transport -------------------------------------------------------

type guestTransport struct{ project, name string }

func newTransport(project, name string) (*guestTransport, error) {
	if !fullmatch(guestNameRe, project) || !fullmatch(guestNameRe, name) {
		return nil, depErr("Expected local Incus project and guest names")
	}
	return &guestTransport{project, name}, nil
}

func (t *guestTransport) execArgs(args []string, stdin bool) []string {
	out := []string{"incus", "--force-local", "exec", t.name, "--project", t.project, "--mode=non-interactive",
		"--env=PATH=/run/current-system/sw/bin:/run/wrappers/bin"}
	if !stdin {
		out = append(out, "--disable-stdin")
	}
	return append(append(out, "--"), args...)
}

func (t *guestTransport) execute(timeout time.Duration, checkStatus bool, args ...string) (CmdResult, error) {
	res, err := run(t.execArgs(args, false), nil, timeout, nil, "")
	if err != nil {
		return res, depErr("Guest command did not finish within its transport deadline")
	}
	if checkStatus && res.Code != 0 {
		return res, depErr(fmt.Sprintf("Guest command failed (exit status %d); inspect the guest locally in Incus", res.Code))
	}
	return res, nil
}

func (t *guestTransport) inspect() (M, error) {
	out, err := check([]string{"incus", "--force-local", "query", instancePath(t.project, t.name)}, nil, 10*time.Second)
	if err != nil {
		return nil, depErr("Guest inventory unavailable; no guest is created by deployment")
	}
	current, err := parseObject(out)
	if err != nil {
		return nil, depErr("Guest inventory unavailable; no guest is created by deployment")
	}
	config := obj(current["config"])
	if str(config[OWNER]) != "true" {
		return nil, depErr("Native-owned guest is observed only; explicit source ownership is required")
	}
	if str(config["user.nixus.restore-review"]) == "required" {
		return nil, depErr("Release the guest from restore quarantine before deployment")
	}
	if str(current["status"]) != "Running" {
		return nil, depErr("Start this source-owned guest in Incus before deployment")
	}
	if str(config["volatile.uuid"]) == "" {
		return nil, depErr("Guest has no stable instance identity")
	}
	if res, err := t.execute(10*time.Second, false, "test", "-e", "/etc/NIXOS"); err != nil || res.Code != 0 {
		return nil, depErr("Non-NixOS guest is observed only; no OS deployment is attempted")
	}
	readlink := func(p string) (string, error) {
		res, err := t.execute(10*time.Second, true, "readlink", "-f", p)
		if err != nil {
			return "", err
		}
		return storePath(strings.TrimSpace(string(res.Stdout)))
	}
	profile, err := readlink("/nix/var/nix/profiles/system")
	if err != nil {
		return nil, err
	}
	active, err := readlink("/run/current-system")
	if err != nil {
		return nil, err
	}
	topology := M{}
	for _, k := range []string{"type", "profiles", "devices", "expanded_devices"} {
		topology[k] = current[k]
	}
	stable := M{}
	for k, v := range config {
		if !strings.HasPrefix(k, "volatile.") {
			stable[k] = v
		}
	}
	topology["config"] = stable
	return M{"uuid": config["volatile.uuid"], "fingerprint": sha256hex([]byte(canonicalSpaced(topology))),
		"profile": profile, "active": active, "type": current["type"]}, nil
}

func (t *guestTransport) missingPaths(paths []string) ([]string, error) {
	var missing []string
	for start := 0; start < len(paths); start += 128 {
		end := min(start+128, len(paths))
		batch := paths[start:end]
		res, err := t.execute(90*time.Second, false, append([]string{"nix-store", "--check-validity", "--print-invalid"}, batch...)...)
		if err != nil || res.Code != 0 {
			return paths, nil
		}
		allowed := map[string]bool{}
		for _, p := range batch {
			allowed[p] = true
		}
		seen := map[string]bool{}
		for _, line := range strings.Split(strings.TrimSpace(string(res.Stdout)), "\n") {
			if line == "" {
				continue
			}
			if seen[line] || !allowed[line] {
				return nil, depErr("Guest reported an invalid store-path inventory")
			}
			seen[line] = true
			missing = append(missing, line)
		}
	}
	return missing, nil
}

func (t *guestTransport) transfer(roots ...string) error {
	for _, r := range roots {
		if _, err := storePath(r); err != nil {
			return err
		}
	}
	out, err := check(append([]string{"nix-store", "--query", "--requisites"}, roots...), nil, 60*time.Second)
	if err != nil {
		return depErr("Cannot enumerate the reviewed closure")
	}
	paths := strings.Fields(string(out))
	if len(paths) == 0 || len(paths) > 20000 {
		return depErr("Closure inventory is empty or exceeds the transport limit")
	}
	for _, p := range paths {
		if _, err := storePath(p); err != nil {
			return err
		}
	}
	if paths, err = t.missingPaths(paths); err != nil {
		return err
	}
	if len(paths) == 0 {
		return nil
	}
	exporter := exec.Command("nix-store", append([]string{"--export"}, paths...)...)
	receiver := exec.Command(t.execArgs([]string{"nix-store", "--import"}, true)[0], t.execArgs([]string{"nix-store", "--import"}, true)[1:]...)
	pipe, err := exporter.StdoutPipe()
	if err != nil {
		return depErr("Closure transfer interrupted or timed out; retry is safe before activation")
	}
	receiver.Stdin = pipe
	if exporter.Start() != nil || receiver.Start() != nil {
		exporter.Process.Kill()
		return depErr("Closure transfer interrupted or timed out; retry is safe before activation")
	}
	done := make(chan error, 2)
	go func() { done <- receiver.Wait() }()
	go func() { done <- exporter.Wait() }()
	timer := time.After(600 * time.Second)
	var failed bool
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				failed = true
			}
		case <-timer:
			exporter.Process.Kill()
			receiver.Process.Kill()
			return depErr("Closure transfer interrupted or timed out; retry is safe before activation")
		}
	}
	if failed {
		return depErr("Closure transfer failed; imported store paths can be reused on retry")
	}
	return nil
}

func (t *guestTransport) retain(deployment, previous, target string) error {
	if !fullmatch(re(`[a-z0-9-]{1,80}`), deployment) {
		return depErr("Invalid deployment identity")
	}
	dir := "/nix/var/nix/gcroots/nixus-deployments"
	if _, err := t.execute(30*time.Second, true, "mkdir", "-p", "-m", "0700", dir); err != nil {
		return err
	}
	for _, pair := range [][2]string{{"previous", previous}, {"target", target}} {
		p, err := storePath(pair[1])
		if err != nil {
			return err
		}
		if _, err := t.execute(60*time.Second, true, "nix-store", "--add-root", dir+"/"+deployment+"-"+pair[0], "--realise", p); err != nil {
			return err
		}
	}
	return nil
}

func (t *guestTransport) activate(closure string) error {
	if _, err := storePath(closure); err != nil {
		return err
	}
	if _, err := t.execute(10*time.Second, true, "test", "-x", closure+"/bin/switch-to-configuration"); err != nil {
		return err
	}
	script := "nix-env --profile /nix/var/nix/profiles/system --set \"$1\"\nexec \"$1/bin/switch-to-configuration\" switch"
	_, err := t.execute(630*time.Second, true, "timeout", "--kill-after=10s", "600", "flock", "--exclusive", "--timeout", "300",
		"/run/lock/nixus-guest-deployment.lock", "sh", "-eu", "-c", script, "nixus-guest-switch", closure)
	return err
}

func (t *guestTransport) rebootRequired(current M) (bool, error) {
	if str(current["type"]) != "virtual-machine" {
		return false, nil
	}
	bootState := func(root string) ([]string, error) {
		var artifacts []string
		for _, name := range []string{"kernel", "initrd"} {
			res, err := t.execute(10*time.Second, false, "readlink", "-e", root+"/"+name)
			if err != nil || (res.Code != 0 && res.Code != 1) || (name == "kernel" && res.Code != 0) {
				return nil, depErr("Cannot determine the guest boot configuration")
			}
			p := strings.TrimSpace(string(res.Stdout))
			if res.Code == 0 && p == "" {
				return nil, depErr("Cannot determine the guest boot configuration")
			}
			if res.Code != 0 {
				p = "\x00none"
			}
			artifacts = append(artifacts, p)
		}
		res, err := t.execute(10*time.Second, true, "cat", root+"/kernel-params")
		if err != nil {
			return nil, err
		}
		return append(artifacts, string(res.Stdout)), nil
	}
	booted, err := bootState("/run/booted-system")
	if err != nil {
		return false, err
	}
	target, err := bootState(str(current["profile"]))
	if err != nil {
		return false, err
	}
	return strings.Join(booted, "\x01") != strings.Join(target, "\x01"), nil
}

func (t *guestTransport) reboot() error {
	res, err := run([]string{"incus", "--force-local", "restart", t.name, "--project", t.project, "--timeout=60"}, nil, 90*time.Second, nil, "")
	if err != nil || res.Code != 0 {
		return depErr("Guest reboot did not complete; no forced power-off was attempted")
	}
	return nil
}

func (t *guestTransport) healthy(probe string, timeout float64) bool {
	p, err := storePath(probe)
	if err != nil {
		return false
	}
	seconds := int(math.Max(1, math.Ceil(timeout)))
	res, err := t.execute(time.Duration(seconds+3)*time.Second, false, "timeout", "--kill-after=2s", fmt.Sprint(seconds), p+"/bin/nixus-guest-health")
	return err == nil && res.Code == 0
}

// --- rollout journal ------------------------------------------------------

func deploymentObservation(spec M) (M, any) {
	t, err := newTransport(str(spec["project"]), str(spec["name"]))
	if err != nil {
		return nil, err.Error()
	}
	current, err := t.inspect()
	if err != nil {
		return nil, err.Error()
	}
	return current, nil
}

func publicTargets(targets, observations M) []any {
	out := []any{}
	for _, key := range keys(targets) {
		spec := obj(targets[key])
		obs := obj(observations[key])
		message := obs["error"]
		if message == nil {
			message = "Observed source-owned NixOS guest"
		}
		units := spec["healthUnits"]
		if units == nil {
			units = []any{}
		}
		checks := spec["httpChecks"]
		if checks == nil {
			checks = 0
		}
		out = append(out, M{"id": key, "project": spec["project"], "name": spec["name"], "targetSystem": spec["system"],
			"currentSystem": jget(obj(obs["current"]), "profile"), "dependsOn": spec["dependsOn"],
			"restartPolicy": spec["restartPolicy"], "maxAttempts": spec["maxAttempts"], "healthTimeout": spec["healthTimeout"],
			"healthUnits": units, "httpChecks": checks, "observation": message})
	}
	return out
}

func deploymentsPrepare(directory string, manifest M) error {
	targets, err := validateDeployments(manifest)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}
	observations := M{}
	for key, spec := range targets {
		current, e := deploymentObservation(obj(spec))
		var c any = current
		if current == nil {
			c = nil
		}
		observations[key] = M{"current": c, "error": e}
	}
	bundle := normalize(M{"format": deploymentVersion, "targets": targets, "observations": observations}).(M)
	if err := writeJSON(filepath.Join(directory, "deployment-plan.json"), bundle); err != nil {
		return err
	}
	job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
	if err != nil {
		return err
	}
	order, _ := deploymentOrder(targets)
	job["deploymentDigest"] = digestJSON(bundle)
	job["guestPlan"] = M{"format": deploymentVersion, "targets": publicTargets(targets, observations),
		"order": strings2any(order), "boundary": deploymentBoundary}
	return writeJSON(filepath.Join(directory, "job.json"), job)
}

func readDeploymentPlan(directory string) (M, error) {
	p := filepath.Join(directory, "deployment-plan.json")
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return nil, Public("Build a new review with guest deployment targets")
	}
	bundle, err := mustReadObj(p)
	if err != nil {
		return nil, err
	}
	job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
	if err != nil {
		return nil, err
	}
	if v, _ := num(bundle["format"]); v != deploymentVersion || digestJSON(bundle) != str(job["deploymentDigest"]) {
		return nil, Public("Guest deployment evidence changed; rebuild the review")
	}
	if _, err := validateDeployments(obj(bundle["targets"])); err != nil {
		return nil, err
	}
	return bundle, nil
}

// checkIdle refuses host changes during guest or project deployments.
func checkIdle(state, allowProject string) error {
	if v, _ := readJSON(filepath.Join(state, "deployment-active.json"), nil); v != nil && !equalJSON(v, M{}) {
		return Public("Finish or resume the active guest deployment before changing host configuration")
	}
	project := readObj(filepath.Join(state, "project-deploy-active.json"))
	if len(project) > 0 && str(project["id"]) != allowProject {
		return Public("Finish or recover the active project deployment before changing host configuration")
	}
	return nil
}

type Deployments struct{ root, state string }

func NewDeployments(root, state string) *Deployments {
	if root == "" {
		root = ROOT
	}
	if state == "" {
		state = STATE
	}
	return &Deployments{root, state}
}

func (d *Deployments) directory(id string) (string, error) {
	return jobDirectory(filepath.Join(d.state, "jobs"), id, "deployment transaction")
}

func (d *Deployments) host(directory string) (M, error) {
	job, err := readJobRecord(filepath.Join(directory, "job.json"), nil)
	if err != nil {
		return nil, err
	}
	if v, _ := readJSON(filepath.Join(d.state, "pending.json"), nil); str(job["status"]) != "confirmed" || (v != nil && !equalJSON(v, M{})) {
		return nil, Public("Confirm host access before deploying guests")
	}
	system, _ := filepath.EvalSymlinks(filepath.Join(directory, "system"))
	if system == "" || activeSystem() != system {
		return nil, Public("The reviewed host generation is no longer active; build a new deployment")
	}
	digest, err := digestSource(filepath.Join(directory, "source"))
	if err != nil || str(job["candidateDigest"]) != digest || job["baseDigest"] == nil {
		return nil, Public("The reviewed deployment source changed")
	}
	return job, nil
}

func (d *Deployments) status(id string) (any, error) { return d.statusPrivate(id, false) }

func (d *Deployments) statusPrivate(id string, private bool) (any, error) {
	directory, err := d.directory(id)
	if err != nil {
		return nil, err
	}
	record, err := readJobRecord(filepath.Join(directory, "deployment.json"), M{})
	if err != nil {
		return nil, err
	}
	if len(record) == 0 {
		return nil, nil
	}
	updated, _ := num(record["updatedAt"])
	if s := str(record["status"]); (s == "queued" || s == "running") && now()-updated > 30 {
		if active, err := workerActive("nixus-deploy-" + id); err == nil && !active {
			record["status"] = "interrupted"
			record["error"] = "Worker stopped. Resume rechecks the guest identity and generations before continuing."
		}
	}
	if !private {
		for _, t := range obj(record["targets"]) {
			delete(obj(t), "precondition")
		}
	}
	return record, nil
}

func (d *Deployments) submit(id string, resume any, principal string) (M, error) {
	if err := requireNormal(); err != nil {
		return nil, err
	}
	r, ok := resume.(bool)
	if !ok {
		return nil, Public("Resume must be a boolean")
	}
	return lockedValue(false, func() (M, error) {
		directory, err := d.directory(id)
		if err != nil {
			return nil, err
		}
		if _, err := d.host(directory); err != nil {
			return nil, err
		}
		if err := checkConfigIdle(d.state); err != nil {
			return nil, err
		}
		bundle, err := readDeploymentPlan(directory)
		if err != nil {
			return nil, err
		}
		raw, err := d.statusPrivate(id, true)
		if err != nil {
			return nil, err
		}
		record := obj(raw)
		active := readObj(filepath.Join(d.state, "deployment-active.json"))
		if len(active) > 0 && str(active["id"]) != id {
			return nil, Public("Another guest deployment is active")
		}
		status := str(record["status"])
		if record != nil && (status == "queued" || status == "running") {
			return nil, Public("Guest deployment is already running")
		}
		if record != nil && status == "abandoned" {
			return nil, Public("Build a new review after abandoning a deployment")
		}
		if record != nil && !r {
			return nil, Public("Resume the existing deployment instead of replacing its journal")
		}
		if record == nil {
			if r {
				return nil, Public("Start the reviewed guest deployment first")
			}
			targets := obj(bundle["targets"])
			states := M{}
			for _, key := range keys(targets) {
				spec := obj(targets[key])
				current, e := deploymentObservation(spec)
				reviewed := obj(jget(obj(bundle["observations"]), key, "current"))
				if current != nil {
					differs := reviewed == nil || !equalJSON(current["uuid"], reviewed["uuid"]) ||
						!equalJSON(current["fingerprint"], reviewed["fingerprint"]) ||
						(str(current["profile"]) != str(reviewed["profile"]) && str(current["profile"]) != str(spec["system"])) ||
						(str(current["active"]) != str(reviewed["active"]) && str(current["active"]) != str(spec["system"]))
					if differs {
						e, current = "Guest identity, configuration or OS generation differs from review; build a new review", nil
					}
				}
				var c any = current
				if current == nil {
					c = nil
				}
				states[key] = M{"phase": "pending", "attempts": 0, "precondition": c, "error": e}
			}
			system, _ := filepath.EvalSymlinks(filepath.Join(directory, "system"))
			record = M{"format": deploymentVersion, "id": id, "hostSystem": system, "planDigest": digestJSON(bundle),
				"createdAt": now(), "principal": principal, "boundary": deploymentBoundary, "targets": states}
		}
		record["status"], record["updatedAt"], record["error"] = "queued", now(), nil
		if err := writeJSON(filepath.Join(directory, "deployment.json"), record); err != nil {
			return nil, err
		}
		if err := writeJSON(filepath.Join(d.state, "deployment-active.json"), M{"id": id}); err != nil {
			return nil, err
		}
		if _, err := check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-deploy-" + id,
			"--property=RuntimeMaxSec=10800", "--setenv=NIXUS_ROOT=" + d.root, "--setenv=NIXUS_STATE=" + d.state,
			"--setenv=PATH=" + os.Getenv("PATH"), adminLauncher(), "admin", "deployment-job", id}, nil, 20*time.Second); err != nil {
			record["status"], record["error"], record["updatedAt"] = "interrupted", "Could not start deployment worker", now()
			writeJSON(filepath.Join(directory, "deployment.json"), record)
			durableUnlink(filepath.Join(d.state, "deployment-active.json"))
			return nil, Public("Could not start deployment worker; resume this journal")
		}
		audit("guest-deployment-requested", M{"job": id, "principal": principal, "resume": r})
		return M{"id": id}, nil
	})
}

func (d *Deployments) abandon(id string) (M, error) {
	return lockedValue(false, func() (M, error) {
		directory, err := d.directory(id)
		if err != nil {
			return nil, err
		}
		raw, err := d.statusPrivate(id, true)
		if err != nil {
			return nil, err
		}
		record := obj(raw)
		if s := str(record["status"]); record == nil || s == "queued" || s == "running" {
			return nil, Public("Only a stopped deployment can be abandoned")
		}
		record["status"] = "abandoned"
		record["error"] = "Retries abandoned; guest generations and data were not changed"
		d.save(directory, record)
		if str(readObj(filepath.Join(d.state, "deployment-active.json"))["id"]) == id {
			durableUnlink(filepath.Join(d.state, "deployment-active.json"))
		}
		audit("guest-deployment-abandoned", M{"job": id})
		return M{"id": id}, nil
	})
}

func (d *Deployments) save(directory string, record M) error {
	record["updatedAt"] = now()
	return writeJSON(filepath.Join(directory, "deployment.json"), record)
}

func (d *Deployments) phase(directory string, record M, key, phase string, values M) {
	state := obj(obj(record["targets"])[key])
	state["phase"] = phase
	for k, v := range values {
		state[k] = v
	}
	d.save(directory, record)
}

func (d *Deployments) verify(t *guestTransport, state, spec M) (M, error) {
	current, err := t.inspect()
	if err != nil {
		return nil, err
	}
	expected := obj(state["precondition"])
	if expected == nil {
		if e := str(state["error"]); e != "" {
			return nil, depErr(e)
		}
		return nil, depErr("Guest was not eligible at deployment start; rebuild the review")
	}
	if !equalJSON(current["uuid"], expected["uuid"]) || !equalJSON(current["fingerprint"], expected["fingerprint"]) {
		return nil, depErr("Guest identity or configuration changed during deployment; inspect it and rebuild the review")
	}
	previous := str(state["previousSystem"])
	if _, ok := state["previousSystem"]; !ok {
		previous = str(expected["profile"])
	}
	allowed := map[string]bool{previous: true, str(spec["system"]): true}
	if !allowed[str(current["profile"])] || !allowed[str(current["active"])] {
		return nil, depErr("A native guest OS generation conflicts with the deployment; no automatic adoption")
	}
	return current, nil
}

func (d *Deployments) health(t *guestTransport, spec M) error {
	timeout, _ := num(spec["healthTimeout"])
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		remaining := time.Until(deadline).Seconds()
		if t.healthy(str(spec["probe"]), math.Max(1, math.Min(10, remaining))) {
			return nil
		}
		remaining = time.Until(deadline).Seconds()
		if remaining <= 0 {
			return depErr("Guest health checks failed within the configured deadline")
		}
		time.Sleep(time.Duration(math.Min(2, remaining) * float64(time.Second)))
	}
}

func (d *Deployments) rollbackTarget(directory string, record M, key string, spec M, t *guestTransport) error {
	state := obj(obj(record["targets"])[key])
	if _, err := d.verify(t, state, spec); err != nil {
		return err
	}
	d.phase(directory, record, key, "rolling-back", nil)
	previous := str(state["previousSystem"])
	if err := t.activate(previous); err != nil {
		return err
	}
	current, err := t.inspect()
	if err != nil {
		return err
	}
	if str(current["profile"]) != previous || str(current["active"]) != previous {
		return depErr("Previous OS generation could not be restored")
	}
	reboot, _ := t.rebootRequired(current)
	d.phase(directory, record, key, "rolled-back", M{"currentSystem": previous, "rollbackRebootRequired": reboot})
	return nil
}

func (d *Deployments) target(directory string, record M, key string, spec M) error {
	state := obj(obj(record["targets"])[key])
	t, err := newTransport(str(spec["project"]), str(spec["name"]))
	if err != nil {
		return err
	}
	current, err := d.verify(t, state, spec)
	if err != nil {
		return err
	}
	if p := str(state["phase"]); p == "rolling-back" || p == "rollback-failed" {
		if err := d.rollbackTarget(directory, record, key, spec, t); err != nil {
			return err
		}
		if current, err = d.verify(t, state, spec); err != nil {
			return err
		}
	}
	system := str(spec["system"])
	phase := str(state["phase"])
	prev, hasPrev := state["previousSystem"]
	mutated := phase == "activating" || phase == "activated" || phase == "checking" || phase == "rebooting" ||
		(hasPrev && prev != nil && str(prev) != system && (system == str(current["profile"]) || system == str(current["active"])))
	rollback := isTrue(spec["rollbackOnFailure"])
	attempts, _ := num(state["attempts"])
	maxAttempts, _ := num(spec["maxAttempts"])
	tryRollback := func() {
		if err := d.rollbackTarget(directory, record, key, spec, t); err != nil {
			d.phase(directory, record, key, "rollback-failed", nil)
		}
	}
	if str(current["profile"]) != system || str(current["active"]) != system {
		if attempts >= maxAttempts {
			if mutated && rollback && str(state["previousSystem"]) != "" {
				tryRollback()
			}
			return depErr("Retry budget exhausted; inspect the guest and build a new reviewed deployment")
		}
		previous := str(state["previousSystem"])
		if previous == "" {
			previous = str(current["profile"])
		}
		d.phase(directory, record, key, "transferring", M{"previousSystem": previous, "targetSystem": system, "attempts": attempts + 1, "error": nil})
		if err := t.transfer(system, str(spec["probe"])); err != nil {
			return err
		}
		d.phase(directory, record, key, "transferred", nil)
		if _, err := d.verify(t, state, spec); err != nil {
			return err
		}
		if err := t.retain(filepath.Base(directory)+"-"+key, previous, system); err != nil {
			return err
		}
		d.phase(directory, record, key, "activating", nil)
		mutated = true
		if err := t.activate(system); err != nil {
			if rollback {
				tryRollback()
			}
			return err
		}
		d.phase(directory, record, key, "activated", nil)
	} else if phase == "pending" || phase == "failed" || phase == "blocked" || phase == "transferring-probe" {
		if attempts >= maxAttempts {
			return depErr("Retry budget exhausted while importing the guest health probe")
		}
		previous := str(state["previousSystem"])
		if previous == "" {
			previous = str(current["profile"])
		}
		d.phase(directory, record, key, "transferring-probe", M{"attempts": attempts + 1, "previousSystem": previous, "targetSystem": system})
		if err := t.transfer(str(spec["probe"])); err != nil {
			return err
		}
		d.phase(directory, record, key, "transferred", nil)
	}
	err = func() error {
		current, err := d.verify(t, state, spec)
		if err != nil {
			return err
		}
		if str(current["active"]) != system {
			return depErr("Guest activation did not reach its target generation")
		}
		reboot, err := t.rebootRequired(current)
		if err != nil {
			return err
		}
		if reboot {
			if str(spec["restartPolicy"]) == "defer" {
				d.phase(directory, record, key, "reboot-pending", M{"targetSystem": system, "currentSystem": system,
					"error": "Reboot this guest in Incus, then resume to run health checks"})
				return nil
			}
			d.phase(directory, record, key, "rebooting", nil)
			if err := t.reboot(); err != nil {
				return err
			}
			deadline := time.Now().Add(120 * time.Second)
			for {
				if c, err := d.verify(t, state, spec); err == nil {
					if r, err := t.rebootRequired(c); err == nil && !r {
						break
					}
				}
				if time.Now().After(deadline) {
					return depErr("Guest did not return on the target boot configuration within the reboot deadline")
				}
				time.Sleep(2 * time.Second)
			}
		}
		d.phase(directory, record, key, "checking", M{"targetSystem": system})
		if err := d.health(t, spec); err != nil {
			return err
		}
		d.phase(directory, record, key, "healthy", M{"currentSystem": system, "checkedAt": now(), "error": nil})
		return nil
	}()
	if err != nil {
		if mutated && rollback {
			tryRollback()
		}
		return err
	}
	return nil
}

func (d *Deployments) run(id string) (M, error) {
	if err := requireNormal(); err != nil {
		return nil, err
	}
	directory, err := d.directory(id)
	if err != nil {
		return nil, err
	}
	return lockedValue(true, func() (M, error) {
		release, err := lockFile(incusLock, true)
		if err != nil {
			return nil, err
		}
		defer release()
		record, err := readJobRecord(filepath.Join(directory, "deployment.json"), nil)
		if err != nil {
			return nil, err
		}
		defer func() {
			if str(readObj(filepath.Join(d.state, "deployment-active.json"))["id"]) == id {
				durableUnlink(filepath.Join(d.state, "deployment-active.json"))
			}
		}()
		fail := func(err error) (M, error) {
			record["status"] = "interrupted"
			record["error"] = "Deployment interrupted or preconditions changed; inspect host/guest state before resuming"
			d.save(directory, record)
			return nil, err
		}
		if _, err := d.host(directory); err != nil {
			return fail(err)
		}
		bundle, err := readDeploymentPlan(directory)
		if err != nil {
			return fail(err)
		}
		if s := str(record["status"]); s != "queued" && s != "running" {
			return fail(depErr("Deployment was not queued"))
		}
		if str(record["planDigest"]) != digestJSON(bundle) {
			return fail(depErr("Deployment plan changed"))
		}
		record["status"] = "running"
		d.save(directory, record)
		targets := obj(bundle["targets"])
		order, _ := deploymentOrder(targets)
		states := obj(record["targets"])
		for _, key := range order {
			spec := obj(targets[key])
			deps, _ := anyStrings(spec["dependsOn"])
			blocked := false
			for _, dep := range deps {
				if str(obj(states[dep])["phase"]) != "healthy" {
					blocked = true
				}
			}
			if blocked {
				d.phase(directory, record, key, "blocked", M{"error": "A dependency is not healthy; resume after resolving it"})
				continue
			}
			if err := d.target(directory, record, key, spec); err != nil {
				var de *DeploymentError
				if !errors.As(err, &de) {
					return fail(err)
				}
				phase := str(obj(states[key])["phase"])
				if phase != "rolled-back" && phase != "rollback-failed" {
					phase = "failed"
				}
				d.phase(directory, record, key, phase, M{"error": err.Error()})
			}
		}
		healthy := true
		for _, s := range states {
			if str(obj(s)["phase"]) != "healthy" {
				healthy = false
			}
		}
		record["status"] = "partial"
		if healthy {
			record["status"] = "healthy"
		}
		record["finishedAt"] = now()
		d.save(directory, record)
		audit("guest-deployment-finished", M{"job": id, "status": record["status"]})
		return record, nil
	})
}

var _ = sort.Strings

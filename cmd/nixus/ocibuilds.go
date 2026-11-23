package main

// Reviewed Compose sources and the Compose deploy adapter. A review parses the
// published source with the pinned incus-compose, validates it against Nixus's
// rules and records the result; deploying runs incus-compose directly, which
// pulls prebuilt images and builds the rest with buildah.

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

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
		return "", Public("Invalid review ID")
	}
	p := filepath.Join(b.jobs, s)
	if isSymlink(p) || !isDir(p) {
		return "", Public("Unknown review ID")
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
	out := M{}
	for _, k := range []string{"id", "project", "revision", "status", "planHash", "createdAt", "intentHash", "services", "importedAt"} {
		out[k] = record[k]
	}
	return out, nil
}

// imported returns the newest reviewed record of exactly this revision.
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

// review materialises the published source, parses and validates it, and
// records the approved services. Nothing runs until the project is deployed.
func (b *OCIBuilds) review(project, revision any, principal string) (M, error) {
	return lockedValue(false, func() (M, error) {
		p, ok1 := project.(string)
		rev, ok2 := revision.(string)
		if !ok1 || !ok2 {
			return nil, Public("Invalid published source identity")
		}
		plan, err := sourcePlan(p, rev, b.publisher)
		if err != nil {
			return nil, err
		}
		mode := str(plan["mode"])
		for _, blocker := range list(plan["blocking"]) {
			if str(blocker) == "unsupported-buildkit-feature-requires-explicit-policy" || str(blocker) == "dockerfile-base-image-must-be-pinned-by-digest" {
				return nil, Public("The source uses build syntax Nixus does not support, or a Dockerfile base image that is not pinned by digest")
			}
		}
		if mode != "compose" && mode != "dockerfile" {
			return nil, Public("The source needs a compose.yaml or a Dockerfile")
		}
		files, err := checkFiles(plan["sourceFiles"])
		if err != nil {
			return nil, err
		}
		scratch, err := os.MkdirTemp(STATE, "review-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(scratch)
		os.Chmod(scratch, 0o700)
		source := filepath.Join(scratch, "source")
		os.Mkdir(source, 0o700)
		if err := verifiedSource(filepath.Join(b.publisher.root, p, "revisions", rev, "source"), files, source); err != nil {
			return nil, err
		}
		parsed, err := composeModel(plan, source, scratch)
		if err != nil {
			return nil, err
		}
		if str(parsed["sourceHash"]) != rev || str(parsed["project"]) != p {
			return nil, Public("The Compose parser did not attest the reviewed source")
		}
		if _, err := b.publisher.attest(p, rev); err != nil {
			return nil, err
		}
		incusProject, err := incusProjectName(p)
		if err != nil {
			return nil, err
		}
		if err := ensureComposeProject(incusProject, b.incus); err != nil {
			return nil, err
		}
		identity := tokenHex(16)
		record := M{"id": identity, "format": 1, "project": p, "revision": rev, "status": "imported", "createdAt": now(), "importedAt": now(),
			"principal": principal, "intentHash": parsed["intentHash"], "services": parsed["services"], "sourceHash": rev}
		record["planHash"] = digestJSON(M{"project": p, "revision": rev, "intentHash": parsed["intentHash"], "services": parsed["services"]})
		dir := filepath.Join(b.jobs, identity)
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
		writeJSON(filepath.Join(dir, "intent.json"), parsed)
		writeJSON(filepath.Join(dir, "job.json"), record)
		audit("compose-reviewed", M{"project": p, "identity": identity, "principal": principal, "revision": rev})
		writeJSON(filepath.Join(b.state, "oci-build-last.json"), M{"id": identity})
		return b.status(identity)
	})
}

// --- Compose deploy adapter (#45) ------------------------------------------

const composeServiceLabel = "user.label.incus-compose.service"

// defaultDNSImage is incus-compose's own DNS sidecar for this incus-compose
// version, pinned by digest. It lets an app's services reach each other by
// name, as with docker compose. NIXUS_COMPOSE_DNS_IMAGE overrides it (tests,
// hosts with their own registry mirror).
const defaultDNSImage = "ghcr.io/lxc/incus-compose/ic-dns:1.4.1@sha256:854d0f70b643e7699e5abe39f86de30d58d148c5865489be67e7ea9b32d695a0"

func composeDNSImage() string {
	if v := os.Getenv("NIXUS_COMPOSE_DNS_IMAGE"); v != "" {
		return v
	}
	return defaultDNSImage
}

// isDNSSidecar reports whether an instance is incus-compose's DNS sidecar for
// the project; it belongs to the project, not to any of the app's services.
func isDNSSidecar(incusProject, name string) bool { return name == incusProject+"-ic-dns" }

const composeIntentKey = "user.nixus.compose-intent"

var composeStable = []string{"kind", "project", "name", "sourceProject", "revision", "buildId", "intentHash", "services"}

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
	built := map[string]bool{}
	for _, raw := range list(build["services"]) {
		if item := obj(raw); isTrue(item["built"]) {
			built[str(item["service"])] = true
		}
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
		if isDNSSidecar(incusProject, str(instance["name"])) {
			continue
		}
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
			if str(om["status"]) != "Running" {
				current = false
			}
		}
		if count == 0 {
			current = false
		}
	}
	if !current && str(config[composeIntentKey]) != str(build["intentHash"]) {
		// A new revision rebuilds its own services; incus-compose recreates them.
		for s := range built {
			recreates = append(recreates, s)
		}
	}
	if !current && str(config[composeIntentKey]) != str(build["intentHash"]) {
		// A new revision rebuilds its own services; incus-compose recreates them.
		for s := range built {
			recreates = append(recreates, s)
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
		"revision": revision, "buildId": build["id"], "intentHash": build["intentHash"],
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
	// The app's variables go into the Compose model like any other
	// environment entry, so incus-compose creates each container with them
	// set, the way docker compose does with a stack's variables.
	values, err := appStartEnv(sourceProject)
	if err != nil {
		return Failed("Could not read the variables entered for this app", err)
	}
	if len(values) > 0 {
		var names []string
		for _, s := range list(build["services"]) {
			names = append(names, str(obj(s)["service"]))
		}
		p := filepath.Join(scratch, "nixus-env.yaml")
		if err := atomic(p, envOverride(names, values), 0o600, ""); err != nil {
			return err
		}
		flags = append(flags, "-f", p)
		fmt.Fprintf(os.Stderr, "nixus: deploying %s with variables %v\n", sourceProject, keys(values))
	}
	binary := os.Getenv("NIXUS_OCI_COMPOSE_BIN")
	if binary == "" {
		binary = "incus-compose"
	}
	previous := str(obj(incusQueryObj(a.incus, "/1.0/projects/"+incusProject)["config"])[composeIntentKey])
	args, env, err := composeUpCommand(binary, flags, build, scratch)
	if err != nil {
		return err
	}
	if previous != "" && previous != str(build["intentHash"]) {
		// A new revision replaces the running instances so the new images are
		// used. incus-compose's own --recreate also tears down shared DNS wiring
		// and fails when there is none, so remove them here; named volumes
		// keep their data.
		for _, inst := range appInstances(a.incus, incusProject) {
			if _, err := a.incus(0, "delete", str(inst["name"]), "--project", incusProject, "--force"); err != nil {
				return Failed("Could not replace the running app", err)
			}
		}
	}
	if msg := portConflicts(a.incus, incusProject, composeHostPorts(list(build["services"]))); msg != "" {
		return Public(msg)
	}
	runUp := func(args []string) error {
		res, err := run(args, nil, 1800*time.Second, env, source)
		if err != nil || res.Code != 0 {
			tail := string(res.Stderr)
			if len(tail) > 3000 {
				tail = tail[len(tail)-3000:]
			}
			fmt.Fprintln(os.Stderr, "nixus: incus-compose up failed:", tail)
			if os.Getenv("NIXUS_OCI_VM_TEST") == "1" {
				os.Stdout.WriteString("COMPOSE-VM-STDERR: " + tail + "\n")
			}
			if msg := explainBindError(a.incus, incusProject, tail); msg != "" {
				return Public(msg)
			}
			return Public("incus-compose could not bring the project up: " + lastLine(tail))
		}
		return nil
	}
	if err := runUp(args); err != nil {
		return err
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
		return nil, Public("Compose services are not all running the reviewed images" + notRunning(verified) +
			startDetail(a.incus, str(approved["sourceProject"]), str(approved["project"]), verified))
	}
	return M{"status": "verified", "newEtag": verified["etag"], "health": "Running"}, nil
}

var _ = path.Base

// appStartEnv returns the variables an app needs before its containers start:
// the ones already saved as encrypted secrets, overridden by those entered with
// the deploy that has not applied them yet.
func appStartEnv(project string) (M, error) {
	values := M{}
	s := NewSecrets("", "", "")
	if ciphertext, err := s.cipher(filepath.Join(s.projects, project)); err == nil && ciphertext != nil {
		saved, err := s.decode(ciphertext, "")
		if err != nil {
			return nil, err
		}
		for k, v := range saved {
			values[k] = v
		}
	}
	if isFile(appEnvPath(project)) {
		pending, err := openDeployEnv(project)
		if err != nil {
			return nil, err
		}
		for k, v := range pending {
			values[k] = v
		}
	}
	return values, nil
}

// envOverride is a Compose override that gives every service the app's
// variables. JSON is valid YAML; "$" is doubled so Compose does not
// interpolate values.
func envOverride(services []string, values M) []byte {
	env := map[string]string{}
	for k, v := range values {
		env[k] = strings.ReplaceAll(str(v), "$", "$$")
	}
	out := M{}
	for _, name := range services {
		out[name] = M{"environment": env}
	}
	b, _ := json.Marshal(M{"services": out})
	return b
}

// composeUpCommand builds the incus-compose invocation. Prebuilt images are
// pulled; services with a Dockerfile are built with buildah.
func composeUpCommand(binary string, flags []string, build M, scratch string) ([]string, []string, error) {
	needsBuild := false
	for _, raw := range list(build["services"]) {
		needsBuild = needsBuild || isTrue(obj(raw)["built"])
	}
	buildFlags := []string{"--no-build"}
	storage := filepath.Join(scratch, "storage.conf")
	if needsBuild {
		buildah := os.Getenv("NIXUS_OCI_BUILDAH_BIN")
		if buildah == "" {
			buildah = "buildah"
		}
		buildFlags = []string{"--build", "--builder", buildah}
		conf := "[storage]\ndriver = \"vfs\"\nrunroot = \"" + scratch + "/runroot\"\ngraphroot = \"" + scratch + "/graphroot\"\n"
		if err := os.WriteFile(storage, []byte(conf), 0o600); err != nil {
			return nil, nil, err
		}
		// Buildah refuses to run without a signature policy, and hosts without
		// the containers module have none. Images are pinned by digest, which
		// already fixes their content, so no signatures are required.
		policyDir := filepath.Join(scratch, ".config", "containers")
		if err := os.MkdirAll(policyDir, 0o700); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(filepath.Join(policyDir, "policy.json"), []byte(`{"default":[{"type":"insecureAcceptAnything"}]}`+"\n"), 0o600); err != nil {
			return nil, nil, err
		}
	}
	args := append(append([]string{binary, "--ansi", "never"}, flags...), "--image-cache", "", "up", "--detach")
	args = append(append(args, buildFlags...), "--pull", "missing", "--no-healthd", "--no-dns")
	env := []string{"PATH=" + os.Getenv("NIXUS_OCI_PATH") + ":" + os.Getenv("PATH"), "HOME=" + scratch, "BUILDAH_ISOLATION=chroot",
		"CONTAINERS_STORAGE_CONF=" + storage, "TMPDIR=" + scratch, "INCUS_COMPOSE_DNS_IMAGE=" + composeDNSImage()}
	return args, env, nil
}

// notRunning names the services that are not running after a deployment, with
// their state, so a failure says which container to look at.
// startDetail says which variables the containers were created with (names
// only) and what each stopped container printed last, so a failed deployment
// explains itself without a shell.
func startDetail(incus func(time.Duration, ...string) (string, error), sourceProject, incusProject string, resource M) string {
	var b strings.Builder
	if values, err := appStartEnv(sourceProject); err == nil && len(values) > 0 {
		b.WriteString("\n\nStarted with variables: " + strings.Join(keys(values), ", "))
	} else {
		b.WriteString("\n\nStarted with no variables. Add them in Environment Variables, then redeploy.")
	}
	for _, name := range keys(obj(resource["instances"])) {
		inst := obj(obj(resource["instances"])[name])
		if str(inst["status"]) == "Running" {
			continue
		}
		out, err := incus(0, "console", name, "--project", incusProject, "--show-log")
		if err != nil || strings.TrimSpace(out) == "" {
			continue
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) > 10 {
			lines = lines[len(lines)-10:]
		}
		tail := strings.Join(lines, "\n")
		if len(tail) > 1500 {
			tail = tail[len(tail)-1500:]
		}
		b.WriteString("\n\n" + str(inst["service"]) + " log:\n" + tail)
	}
	return b.String()
}

func notRunning(resource M) string {
	byService := map[string]string{}
	for _, raw := range obj(resource["instances"]) {
		inst := obj(raw)
		byService[str(inst["service"])] = str(inst["status"])
	}
	var problems []string
	for _, raw := range list(resource["services"]) {
		name := str(raw)
		switch state, ok := byService[name]; {
		case !ok:
			problems = append(problems, name+" has no instance")
		case state != "Running":
			problems = append(problems, name+" is "+state)
		}
	}
	if len(problems) == 0 {
		return ""
	}
	return ": " + strings.Join(problems, ", ") + ". A container that stops right after starting usually needs a variable or a setting; check its logs"
}

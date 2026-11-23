package main

// Reviewed Compose sources and the Compose deploy adapter. A review parses the
// published source with the pinned incus-compose, validates it against Nixus's
// rules and records the result; deploying runs incus-compose directly, which
// pulls prebuilt images and builds the rest with buildah.

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
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
	binary := os.Getenv("NIXUS_OCI_COMPOSE_BIN")
	if binary == "" {
		binary = "incus-compose"
	}
	previous := str(obj(incusQueryObj(a.incus, "/1.0/projects/"+incusProject)["config"])[composeIntentKey])
	args, env, err := composeUpCommand(binary, flags, build, previous, scratch)
	if err != nil {
		return err
	}
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
		return Public("incus-compose could not bring the project up: " + lastLine(tail))
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
		return nil, Public("Compose services are not all running the reviewed images")
	}
	return M{"status": "verified", "newEtag": verified["etag"], "health": "Running"}, nil
}

var _ = path.Base

// composeUpCommand builds the incus-compose invocation. Prebuilt images are
// pulled; services with a Dockerfile are built with buildah. A new revision of
// an existing project recreates its instances so the new images are used;
// named volumes keep their data.
func composeUpCommand(binary string, flags []string, build M, previousIntent, scratch string) ([]string, []string, error) {
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
	}
	args := append(append([]string{binary, "--ansi", "never"}, flags...), "--image-cache", "", "up", "--detach")
	args = append(append(args, buildFlags...), "--pull", "missing", "--no-healthd", "--no-dns")
	if previousIntent != "" && previousIntent != str(build["intentHash"]) {
		args = append(args, "--recreate")
	}
	env := []string{"PATH=" + os.Getenv("NIXUS_OCI_PATH") + ":" + os.Getenv("PATH"), "HOME=" + scratch, "BUILDAH_ISOLATION=chroot",
		"CONTAINERS_STORAGE_CONF=" + storage, "TMPDIR=" + scratch}
	return args, env, nil
}

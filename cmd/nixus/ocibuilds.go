package main

// Reviewed Compose sources and the Compose deploy adapter. A review parses the
// published source with the pinned incus-compose, validates it against Nixus's
// rules and records the result; deploying runs incus-compose directly, which
// pulls prebuilt images and builds the rest with buildah.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

// isComposeSidecar reports whether an instance is an incus-compose managed
// infrastructure sidecar (DNS or health daemon), not one of the app's services.
func isComposeSidecar(incusProject, name string) bool {
	return name == incusProject+"-ic-dns" || name == incusProject+"-ic-healthd"
}

// Upstream prefetches all three tools even with --no-dns. Pin them together;
// official INCUS_COMPOSE_*_IMAGE variables support mirrors/offline registries.
const defaultHealthdImage = "ghcr.io/lxc/incus-compose/ic-healthd:1.4.1@sha256:abb8261776b7a5eb966ca8db698e53dd7bf825ba1a630e2e6ebdbf1088f3d84b"
const defaultDNSImage = "ghcr.io/lxc/incus-compose/ic-dns:1.4.1@sha256:854d0f70b643e7699e5abe39f86de30d58d148c5865489be67e7ea9b32d695a0"
const defaultSleepImage = "ghcr.io/lxc/incus-compose/ic-sleep:1.4.1@sha256:dbf21a1f638ec9d8df9e09e0618bffae3f3364560b30a2cb2258d184924324ac"

func composeToolImage(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// A local Unix-socket client cannot use upstream's remote-URL fallback when
// Incus listens on a wildcard. Supply the actual controller bridge endpoint.
func composeControllerURL(incus incusFunc) (string, error) {
	bind, err := incus(0, "config", "get", "core.https_address")
	if err != nil {
		return "", Public("Could not read the Incus HTTPS listener")
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(bind))
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 {
		return "", Public("Configure a reachable Incus HTTPS listener before deploying Compose health policies")
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		network := incusQueryObj(incus, "/1.0/networks/icompose0?project=default")
		cidr, err := netip.ParsePrefix(str(jget(network, "config", "ipv4.address")))
		if err != nil || !cidr.Addr().Is4() || cidr.Addr().IsUnspecified() || cidr.Addr().IsLoopback() {
			return "", Public("The Compose controller bridge is unavailable; apply the host configuration first")
		}
		host = cidr.Addr().String()
	}
	if address, err := netip.ParseAddr(host); err == nil && address.IsLoopback() {
		return "", Public("The Incus HTTPS listener is loopback-only; the Compose controller needs a reachable listener")
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

const composeStoppedKey = "user.healthcheck.stopped"

// setComposeStopped uses the upstream controller's intent marker: stopping an
// instance for backup or by request must not trigger its restart policy.
func setComposeStopped(incus incusFunc, project, instance string, stopped bool) error {
	_, err := incus(0, "config", "set", instance, composeStoppedKey+"="+fmt.Sprint(stopped), "--project", project)
	return err
}

func restoreComposeStopped(incus incusFunc, guest M) error {
	if !isTrue(guest["compose"]) {
		return nil
	}
	args := []string{"config", "unset", str(guest["name"]), composeStoppedKey, "--project", str(guest["project"])}
	if value, ok := guest["healthStopped"].(string); ok {
		args = []string{"config", "set", str(guest["name"]), composeStoppedKey + "=" + value, "--project", str(guest["project"])}
	}
	_, err := incus(0, args...)
	return err
}

const composeRuntimeKey = "user.nixus.compose-runtime"
const composeRuntimeVersion = "3"

const composeIntentKey = "user.nixus.compose-intent"

var composeStable = []string{"kind", "project", "name", "sourceProject", "revision", "buildId", "intentHash", "services"}

type composeAdapter struct {
	builds *OCIBuilds
	incus  incusFunc
	up     func(sourceProject, incusProject, revision string) error
	// lan is the services that get their own LAN address, as approved; nil
	// keeps what the project has (image updates, restarts).
	lan *string
}

// composeLANKey records on the Incus project which services have a LAN
// network attachment, so a change of the setting triggers compose reconciliation.
const composeLANKey = "user.nixus.lan"

// lanServices is the app's "own IP on your router" setting, sorted and
// comma-joined as stored on the Incus project.
func lanServices(project M) string {
	names, _ := anyStrings(jget(project, "network", "lan", "services"))
	return strings.Join(uniqueSorted(names), ",")
}

var effectiveSettingsPath = "/etc/nixus/effective-settings.json"

// lanNetworkName returns the Incus network name used to attach a Compose
// service directly to the LAN: the host bridge when management runs on a
// bridge, or the preseeded nixus-lan macvlan network on wired Ethernet.
func lanNetworkName() (string, error) {
	cfg := readObj(effectiveSettingsPath)
	iface := str(jget(cfg, "management", "interface"))
	wifiEnabled := isTrue(jget(cfg, "radios", "wifi", "enable"))
	wifiIface := str(jget(cfg, "radios", "wifi", "interface"))
	if iface == "" || (wifiEnabled && iface == wifiIface) {
		return "", Public("This server has no wired LAN interface for apps; configure wired Ethernet or a host bridge first")
	}
	for _, raw := range list(jget(cfg, "connectivity", "bridges")) {
		if str(obj(raw)["name"]) == iface {
			return iface, nil
		}
	}
	return "nixus-lan", nil
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
		if isComposeSidecar(incusProject, str(instance["name"])) {
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
		health := str(settings["user.healthcheck.status"])
		if health == "" {
			health = str(settings["user.incus-compose.health"])
		}
		observed[str(instance["name"])] = M{"service": service, "status": truncate(str(instance["status"]), 32),
			"image": str(settings["volatile.base_image"]), "health": health, "healthCheck": str(settings["user.healthcheck.enabled"]) == "true" && str(settings["user.healthcheck.test"]) != ""}
	}
	current := str(config[composeIntentKey]) == str(build["intentHash"]) && str(config[composeRuntimeKey]) == composeRuntimeVersion
	var recreates []string
	for _, s := range services {
		count := 0
		for _, o := range observed {
			om := obj(o)
			if str(om["service"]) != s {
				continue
			}
			count++
			if str(om["status"]) != "Running" || str(om["health"]) == "unhealthy" || isTrue(om["healthCheck"]) && str(om["health"]) != "healthy" {
				current = false
			}
		}
		if count == 0 {
			current = false
		}
	}
	if !current && (str(config[composeIntentKey]) != str(build["intentHash"]) || str(config[composeRuntimeKey]) != composeRuntimeVersion) {
		recreates = append(recreates, services...)
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
	resource := M{"kind": "compose", "project": incusProject, "name": "compose", "sourceProject": sourceProject, "lanCurrent": str(config[composeLANKey]),
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
	projectConfig := obj(incusQueryObj(a.incus, "/1.0/projects/"+incusProject)["config"])
	storedLAN := str(projectConfig[composeLANKey])
	wantLAN := storedLAN
	if a.lan != nil {
		wantLAN = *a.lan
	}
	values, err := appStartEnv(sourceProject)
	if err != nil {
		return Failed("Could not read the variables entered for this app", err)
	}
	var names []string
	for _, s := range list(build["services"]) {
		names = append(names, str(obj(s)["service"]))
	}
	var lanFor map[string]bool
	var lanNet string
	if wantLAN != "" {
		lanFor = map[string]bool{}
		for _, s := range strings.Split(wantLAN, ",") {
			if !slices.Contains(names, s) {
				return Public("The app has no service named " + s + " to give a LAN address; check Settings → Network")
			}
			lanFor[s] = true
		}
		if lanNet, err = lanNetworkName(); err != nil {
			return err
		}
	}
	inventory, err := liveInventory()
	if err != nil {
		return Public("Could not verify the app secret bindings")
	}
	declaration := obj(obj(inventory["projects"])[sourceProject])
	if declaration == nil {
		return Public("The app declaration is unavailable")
	}
	if err := validateComposeSecretBindings(declaration, names); err != nil {
		return err
	}
	secretDirs := M{}
	for _, name := range names {
		dir, err := materializeInstanceSecrets(sourceProject, declaration, values, M{"name": name, "service": name})
		if err != nil {
			return Failed("Could not prepare scoped app secrets", err)
		}
		secretDirs[name] = dir
	}
	override := filepath.Join(scratch, "nixus-services.yaml")
	var overrideDoc M
	if err := json.Unmarshal(appComposeOverride(names, values, lanFor, lanNet, secretDirs, declaration), &overrideDoc); err != nil {
		return err
	}
	controlNetwork := incusQueryObj(a.incus, "/1.0/networks/icompose0?project=default")
	networks := obj(obj(build["intent"])["networks"])
	if networks == nil {
		model, err := composeJSON(plan, source, scratch, "")
		if err != nil {
			return err
		}
		networks = obj(model["networks"])
	}
	policy := composeNetworkPolicy(networks, readObj(effectiveSettingsPath), str(jget(controlNetwork, "config", "ipv4.address")))
	mergedNetworks := obj(overrideDoc["networks"])
	if mergedNetworks == nil {
		mergedNetworks = M{}
	}
	for name, raw := range policy {
		entry := cloneM(obj(mergedNetworks[name]))
		if entry == nil {
			entry = M{}
		}
		for k, v := range obj(raw) {
			entry[k] = v
		}
		mergedNetworks[name] = entry
	}
	overrideDoc["networks"] = mergedNetworks
	if err := atomic(override, jsonFile(overrideDoc), 0o600, ""); err != nil {
		return err
	}
	flags = append(flags, "-f", override)
	if len(values) > 0 {
		fmt.Fprintf(os.Stderr, "nixus: deploying %s with variables %v\n", sourceProject, keys(values))
	}
	binary := composeBinary()
	args, env, err := composeUpCommand(binary, flags, build, scratch)
	if err != nil {
		return err
	}
	controllerURL, err := composeControllerURL(a.incus)
	if err != nil {
		return err
	}
	args = append(args, "--healthd-incus", controllerURL, "--dns-incus", controllerURL)
	if len(appInstances(a.incus, incusProject)) > 0 && (str(projectConfig[composeRuntimeKey]) != composeRuntimeVersion || str(projectConfig[composeIntentKey]) != str(build["intentHash"]) || storedLAN != wantLAN) {
		args = append(args, "--recreate")
		args = append(args, names...)
	}

	if msg := portConflicts(a.incus, incusProject, composeHostPorts(list(build["services"]))); msg != "" {
		return Public(msg)
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
		if msg := explainBindError(a.incus, incusProject, tail); msg != "" {
			return Public(msg)
		}
		return Public("incus-compose could not bring the project up: " + lastLine(tail))
	}
	os.RemoveAll(filepath.Join(secretMountRoot, sourceProject)) // obsolete project-wide mount after reviewed migration
	_, err = a.incus(0, "project", "set", incusProject, composeIntentKey+"="+str(build["intentHash"]), composeLANKey+"="+wantLAN, composeRuntimeKey+"="+composeRuntimeVersion)
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
	lanChanged := approved["lan"] != nil && str(approved["lan"]) != str(actual["lanCurrent"])
	if str(actual["action"]) == "noop" && !lanChanged {
		return M{"status": "verified", "newEtag": actual["etag"], "health": "Running"}, nil
	}
	if approved["lan"] != nil {
		lan := str(approved["lan"])
		a.lan = &lan
	}
	if !verifyOnly && str(actual["etag"]) != str(approved["etag"]) {
		return nil, Public("Compose instances changed since review; re-review before deployment")
	}
	if err := a.up(str(approved["sourceProject"]), str(approved["project"]), str(approved["revision"])); err != nil {
		return nil, err
	}
	ok := func(r M) bool {
		return str(r["action"]) == "noop" && (approved["lan"] == nil || str(approved["lan"]) == str(r["lanCurrent"]))
	}
	verified, err := waitRunning(func() (M, error) {
		return a.observe(str(approved["sourceProject"]), str(approved["project"]), str(approved["revision"]))
	}, ok)
	if err != nil {
		return nil, err
	}
	if !ok(verified) {
		return nil, Public("Compose services are not all running the reviewed images" + notRunning(verified) +
			startDetail(a.incus, str(approved["sourceProject"]), str(approved["project"]), verified))
	}
	return M{"status": "verified", "newEtag": verified["etag"], "health": "Running"}, nil
}

func composeBinary() string {
	if b := os.Getenv("NIXUS_OCI_COMPOSE_BIN"); b != "" {
		return b
	}
	return "incus-compose"
}

// composeEnv builds the minimal environment for incus-compose commands.
func composeEnv(scratch, storage string) []string {
	env := []string{
		"PATH=" + os.Getenv("NIXUS_OCI_PATH") + ":" + os.Getenv("PATH"),
		"HOME=" + scratch,
		"TMPDIR=" + scratch,
	}
	if storage != "" {
		env = append(env, "BUILDAH_ISOLATION=chroot", "CONTAINERS_STORAGE_CONF="+storage)
	}
	for k, fallback := range map[string]string{"INCUS_COMPOSE_DNS_IMAGE": defaultDNSImage, "INCUS_COMPOSE_HEALTHD_IMAGE": defaultHealthdImage, "INCUS_COMPOSE_SLEEP_IMAGE": defaultSleepImage} {
		env = append(env, k+"="+composeToolImage(k, fallback))
	}
	return env
}

// composeProjectCommand runs an incus-compose lifecycle verb (start, stop,
// restart, down) against a published Compose project. Returns (false, nil) if
// the project has no published Compose source.
func composeProjectCommand(sourceProject string, subcmd ...string) (bool, error) {
	pub := NewPublishedSources("")
	current, err := pub.current(sourceProject)
	if err != nil || current == nil {
		return false, nil
	}
	rev := str(current["revision"])
	plan, err := sourcePlan(sourceProject, rev, pub)
	if err != nil {
		return false, nil
	}
	mode := str(plan["mode"])
	if mode != "compose" && mode != "dockerfile" {
		return false, nil
	}
	srcDir := filepath.Join(pub.root, sourceProject, "revisions", rev, "source")
	if !isDir(srcDir) {
		return false, nil
	}
	scratch, err := os.MkdirTemp(STATE, "compose-ctl-")
	if err != nil {
		return true, err
	}
	defer os.RemoveAll(scratch)
	os.Chmod(scratch, 0o700)
	var compose string
	if g := str(plan["generatedCompose"]); g != "" {
		compose = filepath.Join(scratch, "generated-compose.yaml")
		if err := atomicString(compose, g, 0o600); err != nil {
			return true, err
		}
	} else if e := str(plan["entrypoint"]); e != "" {
		compose = filepath.Join(srcDir, e)
	} else {
		return false, nil
	}
	args := []string{composeBinary(), "--ansi", "never", "-p", sourceProject, "-P", srcDir, "-f", compose}
	offline := os.Getenv("NIXUS_OCI_VM_TEST") == "1" || os.Getenv("NIXUS_COMPOSE_OFFLINE") == "1"
	if offline {
		args = append(args, "--image-cache", "")
	}
	args = append(args, subcmd...)

	res, err := run(args, nil, 5*time.Minute, composeEnv(scratch, ""), srcDir)
	if err != nil || res.Code != 0 {
		return true, cmdFailed("incus-compose "+strings.Join(subcmd, " ")+" failed", res, err)
	}
	return true, nil
}

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

// appComposeOverride produces the minimal Compose override Nixus layers onto a
// Compose app:
//   - environment carries the app's variables ("$" doubled so Compose does not
//     interpolate them)
//   - x-incus-compose.devices.nixus-secrets mounts the host tmpfs secret
//     directory read-only at /run/secrets so secrets persist across restarts
//   - services set to "own IP on your router" join the external Incus LAN
//     network via standard Compose networks:
//   - upstream restart policies own autostart and recovery behavior.
//
// Networking, DNS (ic-dns), and health/restart supervision (ic-healthd) are
// left to incus-compose natively. JSON is valid YAML.
func appComposeOverride(services []string, values M, lanFor map[string]bool, lanNet string, secretDirs M, declaration M) []byte {
	out := M{}
	useLAN := false
	for _, name := range services {
		scoped := envValuesFor(declaration, values, M{"name": name, "service": name})
		env := map[string]string{}
		for k, v := range scoped {
			env[k] = strings.ReplaceAll(str(v), "$", "$$")
		}
		xIncus := M{envKeysConfig: strings.Join(keys(scoped), ",")}
		svc := M{"x-incus": xIncus}
		if len(env) > 0 {
			svc["environment"] = env
		}
		if secretDir := str(secretDirs[name]); secretDir != "" {
			svc["x-incus-compose"] = M{
				"devices": M{
					"nixus-secrets": M{
						"type":     "disk",
						"source":   secretDir,
						"path":     "/run/secrets",
						"readonly": "true",
					},
				},
			}
		}
		if lanFor[name] && lanNet != "" {
			useLAN = true
			svc["networks"] = M{"default": M{}, "nixus_lan": M{}}
		}
		out[name] = svc
	}
	doc := M{"services": out}
	if useLAN {
		doc["networks"] = M{
			"default":   M{},
			"nixus_lan": M{"name": lanNet, "external": true},
		}
	}
	b, _ := json.Marshal(doc)
	return b
}

// composeUpCommand builds the incus-compose invocation. Prebuilt images are
// pulled; services with a Dockerfile are built with buildah using persistent
// overlay storage. Native ic-dns and ic-healthd are enabled by default and
// disabled only in air-gapped/offline VM test mode.
func composeUpCommand(binary string, flags []string, build M, scratch string) ([]string, []string, error) {
	needsBuild := false
	for _, raw := range list(build["services"]) {
		needsBuild = needsBuild || isTrue(obj(raw)["built"])
	}
	buildFlags := []string{"--no-build"}
	storage := ""
	if needsBuild {
		buildah := os.Getenv("NIXUS_OCI_BUILDAH_BIN")
		if buildah == "" {
			buildah = "buildah"
		}
		buildFlags = []string{"--build", "--builder", buildah}
		storage = filepath.Join(scratch, "storage.conf")
		driver, graphroot := "overlay", filepath.Join(STATE, "buildah")
		if os.Getenv("NIXUS_OCI_VM_TEST") == "1" {
			// VM test state lives on tmpfs; keep per-build vfs isolated.
			driver, graphroot = "vfs", filepath.Join(scratch, "graphroot")
		} else {
			os.MkdirAll(graphroot, 0o700)
		}
		conf := fmt.Sprintf("[storage]\ndriver = %q\nrunroot = %q\ngraphroot = %q\n", driver, filepath.Join(scratch, "runroot"), graphroot)
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
	offline := os.Getenv("NIXUS_OCI_VM_TEST") == "1" || os.Getenv("NIXUS_COMPOSE_OFFLINE") == "1"
	args := append([]string{binary, "--ansi", "never"}, flags...)
	if offline {
		args = append(args, "--image-cache", "")
	}
	args = append(args, "up", "--detach")
	args = append(append(args, buildFlags...), "--pull", "missing")

	return args, composeEnv(scratch, storage), nil
}

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

var waitSleep = time.Sleep

// waitRunning confirms containers report Running after incus-compose up,
// retrying briefly if Incus is still finishing startup transitions.
func waitRunning(observe func() (M, error), ok func(M) bool) (M, error) {
	var last M
	for i := 0; i < 6; i++ {
		if i > 0 {
			waitSleep(2 * time.Second)
		}
		r, err := observe()
		if err != nil {
			return nil, err
		}
		last = r
		if ok(r) {
			return r, nil
		}
	}
	return last, nil
}

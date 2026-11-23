package main

// Declarative project source: workspace preflight, restricted offline Nix
// evaluation, typed inventory, the native/Compose plan adapters and the
// reviewed source-publication + deployment journal.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var projectsWorkspace = envPath("NIXUS_PROJECTS", "/srv/nixus/projects")

const hostDesired = "/etc/nixus/desired-instances.json"

var ciphertextName = regexp.MustCompile(`(?i)^secrets\.enc\.(yaml|yml|json)$`)

// --- workspace preflight ---------------------------------------------------

func refuseSensitiveFile(name string) error {
	lower := strings.ToLower(name)
	if lower == ".env" || strings.HasPrefix(lower, ".env.") || lower == "id_rsa" || lower == "id_ed25519" || lower == "id_ecdsa" ||
		lower == "projects.agekey" || strings.HasSuffix(lower, ".agekey") || strings.HasSuffix(lower, ".p12") ||
		strings.HasSuffix(lower, ".pfx") || strings.HasSuffix(lower, ".key") ||
		(strings.HasPrefix(lower, "secrets.") && !ciphertextName.MatchString(lower)) {
		return Public("Potential plaintext credential file in project source: " + name)
	}
	return nil
}

func workspaceEntries(directory string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, Public("Unable to read project directory: " + directory)
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, Public("Symlink forbidden in project source: " + e.Name())
		}
		if !e.Type().IsRegular() && !e.IsDir() {
			return nil, Public("Unsupported filesystem object in project source: " + e.Name())
		}
	}
	return entries, nil
}

func validateWorkspace(root string, requireLock bool) (M, error) {
	root, _ = filepath.Abs(root)
	info, err := os.Lstat(root)
	if err != nil {
		return nil, Public("Project workspace directory is unavailable")
	}
	if !info.IsDir() {
		return nil, Public("Project workspace root must be a real directory")
	}
	rootEntries, err := workspaceEntries(root)
	if err != nil {
		return nil, err
	}
	types := map[string]os.DirEntry{}
	for _, e := range rootEntries {
		types[e.Name()] = e
	}
	if e, ok := types["flake.nix"]; !ok || !e.Type().IsRegular() {
		return nil, Public("Workspace flake.nix is missing")
	}
	if requireLock {
		e, ok := types["flake.lock"]
		if !ok || !e.Type().IsRegular() {
			return nil, Public("Pinned workspace flake.lock is required")
		}
		lock := readObj(filepath.Join(root, "flake.lock"))
		if v, _ := num(lock["version"]); v != 7 || obj(lock["nodes"]) == nil || obj(lock["nodes"])[str(lock["root"])] == nil {
			return nil, Public("Invalid pinned workspace flake.lock")
		}
	}
	files := M{}
	var total int64
	var walk func(string, int) error
	walk = func(directory string, depth int) error {
		if depth > 16 {
			return Public("Project source exceeds directory nesting limit")
		}
		entries, err := workspaceEntries(directory)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if depth == 0 && e.Name() == ".git" && e.IsDir() {
				continue
			}
			p := filepath.Join(directory, e.Name())
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if e.IsDir() {
				if depth == 0 && (e.Name() == "state" || e.Name() == "backups-local") {
					return Public("Mutable data must be outside the projects flake")
				}
				if err := walk(p, depth+1); err != nil {
					return err
				}
				continue
			}
			if err := refuseSensitiveFile(e.Name()); err != nil {
				return err
			}
			st, err := os.Lstat(p)
			if err != nil {
				return err
			}
			if st.Sys().(*syscall.Stat_t).Nlink != 1 {
				return Public("Hardlinked file forbidden in project source: " + rel)
			}
			if st.Size() > 1024*1024 {
				return Public("Project source file exceeds 1 MiB: " + rel)
			}
			total += st.Size()
			if total > 32*1024*1024 {
				return Public("Project source exceeds 32 MiB")
			}
			if len(files) >= 4096 {
				return Public("Project workspace exceeds file limit")
			}
			digest, err := fileSHA256(p)
			if err != nil {
				return err
			}
			files[rel] = M{"size": st.Size(), "sha256": digest}
		}
		return nil
	}
	if err := walk(root, 0); err != nil {
		return nil, err
	}
	var moduleFilesOf func(string, int) ([]any, error)
	moduleFilesOf = func(directory string, depth int) ([]any, error) {
		if depth > 8 {
			return nil, Public("Project module nesting exceeds eight directories")
		}
		entries, err := workspaceEntries(directory)
		if err != nil {
			return nil, err
		}
		result := []any{}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "_") || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			p := filepath.Join(directory, e.Name())
			if e.IsDir() {
				sub, err := moduleFilesOf(p, depth+1)
				if err != nil {
					return nil, err
				}
				result = append(result, sub...)
			} else if strings.HasSuffix(e.Name(), ".nix") {
				rel, _ := filepath.Rel(root, p)
				result = append(result, filepath.ToSlash(rel))
			}
		}
		return result, nil
	}
	discovered := M{}
	for _, e := range rootEntries {
		if strings.HasPrefix(e.Name(), "_") || strings.HasPrefix(e.Name(), ".") || !e.IsDir() {
			continue
		}
		directory := filepath.Join(root, e.Name())
		def := filepath.Join(directory, "default.nix")
		if !lexists(def) {
			continue
		}
		if !fullmatch(projectName, e.Name()) {
			return nil, Public("Invalid project directory name: " + e.Name())
		}
		if !isFile(def) || isSymlink(def) {
			return nil, Public("Project default.nix must be a regular source file")
		}
		if len(discovered) >= 128 {
			return nil, Public("Too many projects")
		}
		modulesRoot := filepath.Join(directory, "modules")
		modules := []any{}
		if lexists(modulesRoot) {
			if !isDir(modulesRoot) {
				return nil, Public("Project modules entry must be a directory")
			}
			if modules, err = moduleFilesOf(modulesRoot, 0); err != nil {
				return nil, err
			}
		}
		if len(modules) > 256 {
			return nil, Public("Project module count exceeds 256")
		}
		discovered[e.Name()] = M{"default": e.Name() + "/default.nix", "modules": modules}
	}
	return M{"schemaVersion": 1, "sourceHash": digestJSON(files), "bytes": total, "files": files, "projects": discovered}, nil
}

// --- restricted evaluation and typed inventory --------------------------------

var storeSource = re(`/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+`)
var storeLib = re(`/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+(?:/[A-Za-z0-9._-]+)*`)

func cachedSource(source string) (string, error) {
	if lexists(filepath.Join(source, ".git")) {
		return "", Public("Unreviewed Git metadata cannot be copied into the public Nix store")
	}
	before, err := validateWorkspace(source, true)
	if err != nil {
		return "", err
	}
	res, err := run([]string{"nix-store", "--add", source}, nil, 60*time.Second, nil, "")
	stored := strings.TrimSpace(string(res.Stdout))
	if err != nil || res.Code != 0 || len(res.Stdout) > 256 || !fullmatch(storeSource, stored) {
		return "", Public("Could not pin project source in the Nix store")
	}
	after, err := validateWorkspace(stored, true)
	if err != nil || str(after["sourceHash"]) != str(before["sourceHash"]) {
		return "", Public("Nix store project snapshot differs from reviewed source")
	}
	return stored, nil
}

var evaluateProjects = func(source, identity string) (M, error) {
	if !fullmatch(jobID, identity) {
		return nil, Public("Invalid reviewed source identity")
	}
	stored, err := cachedSource(source)
	if err != nil {
		return nil, err
	}
	evaluator, nixpkgsLib := os.Getenv("NIXUS_PROJECT_EVAL_LIB"), os.Getenv("NIXUS_PROJECT_NIXPKGS_LIB")
	for _, v := range []string{evaluator, nixpkgsLib} {
		if !fullmatch(storeLib, v) {
			return nil, Public("Trusted project evaluator is not installed")
		}
	}
	expression := "let lib = import " + nixpkgsLib + "; evaluate = import " + evaluator + " { inherit lib; }; in evaluate { root = " + stored + "; }"
	nix := lookPath("nix-instantiate")
	if nix == "" {
		nix = "/run/current-system/sw/bin/nix-instantiate"
	}
	command := []string{"systemd-run", "--pipe", "--wait", "--collect", "--quiet", "--unit=nixus-project-eval-" + identity,
		"--property=Type=exec", "--property=DynamicUser=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
		"--property=PrivateTmp=yes", "--property=PrivateDevices=yes", "--property=PrivateNetwork=yes", "--property=IPAddressDeny=any",
		"--property=RestrictAddressFamilies=AF_UNIX", "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
		"--property=SystemCallFilter=~@mount", "--property=MemoryMax=536870912", "--property=TasksMax=32", "--property=RuntimeMaxSec=90",
		"--property=UMask=0077",
		"--property=InaccessiblePaths=-/var/lib/incus -/var/lib/nixus-secrets -/var/lib/nixus-admin -/etc/nixus -/run/nix -/nix/var/nix/daemon-socket",
		"--setenv=HOME=/tmp", "--setenv=NIX_PATH=", "--setenv=NIX_REMOTE=local?read-only=true",
		"--", nix, "--extra-experimental-features", "read-only-local-store", "--eval", "--strict", "--json",
		"--option", "restrict-eval", "true", "--option", "allow-import-from-derivation", "false", "--option", "substituters", "",
		"--option", "builders", "", "-I", "nixus-evaluator=" + evaluator, "-I", "nixus-lib=" + nixpkgsLib, "-I", "nixus-source=" + stored,
		"--expr", expression}
	res, err := run(command, nil, 110*time.Second, nil, "")
	if err != nil {
		return nil, Public("Restricted project evaluation could not start or timed out")
	}
	if res.Code != 0 || len(res.Stdout) > 1024*1024 {
		return nil, Public("Restricted project evaluation failed; check offline project Nix source")
	}
	raw, err := parseObject(res.Stdout)
	if err != nil {
		return nil, Public("Invalid project evaluation output")
	}
	return validateInventory(raw)
}

var memoryValue = re(`[1-9][0-9]*(?:KiB|MiB|GiB)`)
var claimRe = re(`(instance|volume|network)/([A-Za-z0-9_.-]+)`)
var bindingName = re(`[A-Za-z_][A-Za-z0-9_]{0,127}`)
var secretDestination = re(`/run/secrets/[A-Za-z_][A-Za-z0-9_/-]*`)
var serviceUnit = re(`[A-Za-z0-9_.@-]+\.service`)

func exactKeys(m M, want ...string) bool {
	if len(m) != len(want) {
		return false
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

func validateInventory(raw M) (M, error) {
	if !(exactKeys(raw, "schemaVersion", "projects") || exactKeys(raw, "schemaVersion", "projects", "backups")) || raw["schemaVersion"] != float64(1) && raw["schemaVersion"] != 1 {
		return nil, Public("Unsupported typed project inventory")
	}
	backups, err := validateBackupPolicy(raw["backups"])
	if err != nil {
		return nil, err
	}
	projects := obj(raw["projects"])
	if projects == nil || len(projects) > 128 {
		return nil, Public("Invalid number of declarative projects")
	}
	results := M{}
	claimed := map[string]bool{}
	incusProjects := map[string]bool{}
	for _, name := range keys(projects) {
		p := obj(projects[name])
		if !fullmatch(projectName, name) || p == nil {
			return nil, Public("Invalid declarative project identity")
		}
		if !exactKeys(p, "name", "enable", "backend", "incusProject", "resources", "secrets", "backup", "claims", "source", "modules", "storagePool", "volumes", "instances") &&
			!exactKeys(p, "name", "enable", "backend", "incusProject", "resources", "secrets", "backup", "claims", "source", "modules", "storagePool", "volumes", "instances", "updates") {
			return nil, Public("Unknown project inventory field")
		}
		if err := validateUpdatePolicy(p["updates"]); err != nil {
			return nil, err
		}
		if err := validateNativeDeclarations(p); err != nil {
			return nil, err
		}
		backend := str(p["backend"])
		if str(p["name"]) != name || str(p["source"]) != name || (backend != "incus-native" && backend != "incus-compose") {
			return nil, Public("Project inventory identity/backend mismatch")
		}
		if _, ok := p["enable"].(bool); !ok || !fullmatch(projectName, str(p["incusProject"])) {
			return nil, Public("Unsupported project state")
		}
		res := obj(p["resources"])
		cpus, ok := intValue(res["cpus"])
		if !exactKeys(res, "cpus", "memory") || !ok || cpus < 1 || cpus > 128 || !fullmatch(memoryValue, str(res["memory"])) {
			return nil, Public("Invalid bounded project resources")
		}
		secret := obj(p["secrets"])
		bindings := obj(secret["bindings"])
		file := secret["file"]
		validFile := file == nil
		if s, ok := file.(string); ok {
			validFile = true
			for _, part := range strings.Split(s, "/") {
				if part == "" || part == "." || part == ".." {
					validFile = false
				}
			}
		}
		if !exactKeys(secret, "file", "bindings") || !validFile || bindings == nil || len(bindings) > 128 || (len(bindings) > 0 && file == nil) {
			return nil, Public("Invalid encrypted secret reference")
		}
		for bname, raw := range bindings {
			b := obj(raw)
			units := list(b["restartUnits"])
			valid := fullmatch(bindingName, bname) && exactKeys(b, "key", "instance", "backend", "destination", "restartUnits") &&
				fullmatch(bindingName, str(b["key"])) && fullmatch(projectName, str(b["instance"])) &&
				(str(b["backend"]) == "nixos-sops" || str(b["backend"]) == "incus-file") &&
				fullmatch(secretDestination, str(b["destination"])) && !strings.Contains("/"+str(b["destination"])+"/", "/../") &&
				b["restartUnits"] != nil && len(units) <= 64
			for _, u := range units {
				if !fullmatch(serviceUnit, str(u)) {
					valid = false
				}
			}
			if !valid {
				return nil, Public("Invalid typed secret consumer reference")
			}
		}
		backup := obj(p["backup"])
		consistency := str(backup["consistency"])
		if _, ok := backup["enable"].(bool); !exactKeys(backup, "enable", "consistency") || !ok ||
			(consistency != "stop" && consistency != "quiesce" && consistency != "none") {
			return nil, Public("Invalid project backup policy")
		}
		for _, m := range list(p["modules"]) {
			if !isStr(m) || strings.Contains("/"+str(m)+"/", "/../") {
				return nil, Public("Invalid project source module identity")
			}
		}
		if p["modules"] == nil || list(p["modules"]) == nil && p["modules"] != nil {
			if _, ok := p["modules"].([]any); !ok {
				return nil, Public("Invalid project source module identity")
			}
		}
		claims, ok := p["claims"].([]any)
		if !ok || len(claims) > 64 {
			return nil, Public("Invalid project claim count")
		}
		for _, c := range claims {
			if !fullmatch(claimRe, str(c)) {
				return nil, Public("Unsupported resource claim")
			}
			identity := str(p["incusProject"]) + "/" + str(c)
			if claimed[identity] {
				return nil, Public("Overlapping Incus ownership claims")
			}
			claimed[identity] = true
		}
		incusProjects[str(p["incusProject"])] = true
		results[name] = p
	}
	if len(incusProjects) != len(results) {
		return nil, Public("Multiple projects claim a single Incus project")
	}
	return M{"schemaVersion": 1, "backups": backups, "projects": results}, nil
}

// --- plans ----------------------------------------------------------------------

func nativeSpec(project M, name string, current M) (M, error) {
	if str(jget(current, "config", OWNER)) != "true" {
		return nil, Public("Refusing to adopt an Incus instance without Nixus ownership")
	}
	if t := str(current["type"]); t != "container" && t != "virtual-machine" {
		return nil, Public("Unsupported existing Incus instance type")
	}
	last, err := parseObject([]byte(str(jget(current, "config", LAST_APPLIED))))
	if err != nil {
		if str(jget(current, "config", LAST_APPLIED)) == "" {
			last = M{}
		} else {
			return nil, Public("Invalid previous Incus ownership metadata")
		}
	}
	if v, _ := num(last["version"]); v != 1 {
		return nil, Public("Existing instance must have last-applied Nixus ownership")
	}
	if obj(last["config"]) == nil || obj(last["devices"]) == nil || list(last["profiles"]) == nil && last["profiles"] == nil {
		return nil, Public("Incomplete Incus ownership record")
	}
	config := cloneM(obj(last["config"]))
	cpus, _ := intValue(jget(project, "resources", "cpus"))
	config["limits.cpu"] = itoa(cpus)
	config["limits.memory"] = jget(project, "resources", "memory")
	return M{"project": project["incusProject"], "name": name, "type": current["type"], "config": config,
		"devices": last["devices"], "profiles": last["profiles"]}, nil
}

func itoa(n int) string { return strconv.Itoa(n) }

var nativeObservation = func(project M, guest string) (M, error) {
	current, etag, err := readInstance(str(project["incusProject"]), guest)
	if err != nil {
		return nil, err
	}
	spec, err := nativeSpec(project, guest, current)
	if err != nil {
		return nil, err
	}
	updated, err := reconcilePlan(current, spec)
	if err != nil {
		return nil, err
	}
	shape := M{}
	for _, k := range []string{"type", "config", "devices", "profiles"} {
		shape[k] = current[k]
	}
	action, desired := "noop", any(shape)
	if updated != nil {
		action, desired = "update", updated
	}
	cpus, _ := intValue(jget(project, "resources", "cpus"))
	return normalize(M{"project": project["incusProject"], "name": guest, "observedStatus": truncate(str(current["status"]), 32),
		"etag": etag, "before": M{"cpus": jget(current, "config", "limits.cpu"), "memory": jget(current, "config", "limits.memory")},
		"after": M{"cpus": itoa(cpus), "memory": jget(project, "resources", "memory")}, "fingerprint": digestJSON(shape),
		"action": action, "desiredHash": digestJSON(desired)}).(M), nil
}

var hostClaims = func() (map[string]bool, error) {
	fail := Public("Host-owned Incus inventory unavailable; refusing project adoption")
	if isSymlink(hostDesired) {
		resolved, _ := filepath.EvalSymlinks(hostDesired)
		if !strings.HasPrefix(resolved, "/nix/store/") {
			return nil, Public("Unexpected host Incus inventory symlink")
		}
	}
	raw, err := os.ReadFile(hostDesired)
	if err != nil {
		return nil, fail
	}
	v, err := parseJSON(raw)
	items, ok := v.([]any)
	if err != nil || !ok {
		return nil, Public("Invalid host-owned Incus inventory")
	}
	owners := map[string]bool{}
	for _, item := range items {
		m := obj(item)
		if m == nil || !isStr(m["name"]) || !isStr(m["project"]) {
			return nil, Public("Invalid host-owned instance declaration")
		}
		owners[str(m["project"])+"/"+str(m["name"])] = true
	}
	return owners, nil
}

var composeOwned = func(incusProject string) bool {
	current := incusQueryObj(defaultIncus, "/1.0/projects/"+incusProject)
	return str(jget(current, "config", imageBackendKey)) == composeBackend
}

var composeAdapterFactory = func() *composeAdapter { return newComposeAdapter() }

func planObserve(project, resource M) (M, error) {
	if strings.HasPrefix(str(resource["kind"]), "native-") {
		return nativeObserveAgain(project, resource)
	}
	if str(resource["kind"]) == "compose" {
		return composeAdapterFactory().observe(str(resource["sourceProject"]), str(resource["project"]), str(resource["revision"]))
	}
	return nativeObservation(project, str(resource["name"]))
}

func projectPlan(inventory M, sourceRefs M) (M, error) {
	items := []any{}
	retained := []any{}
	var hostOwned map[string]bool
	projects := obj(inventory["projects"])
	for _, key := range keys(projects) {
		project := obj(projects[key])
		if !isTrue(project["enable"]) {
			if len(obj(project["instances"])) > 0 || len(obj(project["volumes"])) > 0 {
				retained = append(retained, M{"project": project["incusProject"], "name": "project:" + str(project["incusProject"]),
					"reason": "project disabled; its instances and volumes are left untouched"})
			}
			continue
		}
		if str(project["backend"]) == "incus-compose" {
			if len(list(project["claims"])) > 0 {
				return nil, Public("Compose projects cannot claim native Incus resources")
			}
			if bound := obj(sourceRefs[key]); bound != nil {
				resource, err := composeAdapterFactory().observe(key, str(project["incusProject"]), str(bound["revision"]))
				if err != nil {
					return nil, err
				}
				items = append(items, resource)
			}
			continue
		}
		declaredItems, kept, err := nativeDeclaredPlan(project)
		if err != nil {
			return nil, err
		}
		items = append(items, declaredItems...)
		retained = append(retained, kept...)
		claims, _ := anyStrings(project["claims"])
		sort.Strings(claims)
		for _, claim := range claims {
			m := claimRe.FindStringSubmatch(claim)
			kind, name := m[1], m[2]
			if obj(project["instances"])[name] != nil {
				continue
			}
			if str(project["backend"]) != "incus-native" || kind != "instance" {
				return nil, Public("Unsupported Incus resource claim; #133 adapter required")
			}
			if str(project["incusProject"]) == "lab" {
				return nil, Public("Legacy lab project is host-owned; explicit #133 migration required")
			}
			if hostOwned == nil {
				var err error
				if hostOwned, err = hostClaims(); err != nil {
					return nil, err
				}
			}
			if hostOwned[str(project["incusProject"])+"/"+name] {
				return nil, Public("Instance is already host-flake owned; explicit #133 migration required")
			}
			if composeOwned(str(project["incusProject"])) {
				return nil, Public("The native adapter never edits resources in a Compose-owned Incus project")
			}
			observation, err := nativeObservation(project, name)
			if err != nil {
				return nil, err
			}
			items = append(items, observation)
		}
	}
	actions := []any{}
	for _, raw := range items {
		item := obj(raw)
		disruption := str(item["action"]) == "update" && str(item["observedStatus"]) == "Running"
		if str(item["kind"]) == "compose" {
			disruption = len(list(item["recreates"])) > 0
		}
		actions = append(actions, M{"project": item["project"], "name": item["name"], "action": item["action"],
			"before": item["before"], "after": item["after"], "potentialDisruption": disruption})
	}
	return normalize(M{"format": 1, "inventoryHash": digestJSON(inventory), "resources": items, "actions": actions, "retained": retained,
		"boundary": "Declared native projects, volumes and instances are created or reconciled; existing Nixus-owned instances and Compose projects are updated in place; nothing is stopped, resized or deleted because a declaration disappeared"}).(M), nil
}

func recheckAndApply(project, approved M, verifyOnly bool) (M, error) {
	if strings.HasPrefix(str(approved["kind"]), "native-") {
		return nativeApply(project, approved, verifyOnly)
	}
	if str(approved["kind"]) == "compose" {
		return composeAdapterFactory().recheckAndApply(approved, verifyOnly)
	}
	name := str(approved["name"])
	actual, err := nativeObservation(project, name)
	if err != nil {
		return nil, err
	}
	if !equalJSON(actual, approved) {
		if verifyOnly && str(actual["action"]) == "noop" && !(str(approved["observedStatus"]) == "Running" && str(actual["observedStatus"]) != "Running") {
			return M{"status": "verified", "newEtag": actual["etag"], "health": actual["observedStatus"]}, nil
		}
		return nil, Public("Incus state changed since project review; re-review before deployment")
	}
	if str(approved["action"]) == "noop" {
		return M{"status": "verified", "newEtag": approved["etag"], "health": approved["observedStatus"]}, nil
	}
	current, etag, err := readInstance(str(project["incusProject"]), name)
	if err != nil {
		return nil, err
	}
	if etag != str(approved["etag"]) {
		return nil, Public("Incus ETag drift during apply")
	}
	spec, err := nativeSpec(project, name, current)
	if err != nil {
		return nil, err
	}
	update, err := reconcilePlan(current, spec)
	if err != nil {
		return nil, err
	}
	if update == nil || digestJSON(update) != str(approved["desiredHash"]) {
		return nil, Public("Incus update differs from approved plan")
	}
	if err := writeInstance(str(project["incusProject"]), name, update, etag); err != nil {
		return nil, err
	}
	verified, err := nativeObservation(project, name)
	if err != nil {
		return nil, err
	}
	if str(verified["action"]) != "noop" {
		return nil, Public("Incus resource did not reach declared desired state")
	}
	if str(approved["observedStatus"]) == "Running" && str(verified["observedStatus"]) != "Running" {
		return nil, Public("Incus guest stopped during configuration update; manual health review required")
	}
	return M{"status": "verified", "newEtag": verified["etag"], "health": verified["observedStatus"]}, nil
}

// --- transactions ------------------------------------------------------------------

const projectJobLifetime = 15 * 60

var projectFragment = re(`[A-Za-z0-9][A-Za-z0-9_-]*`)
var projectModuleFile = re(`[A-Za-z0-9][A-Za-z0-9_-]*\.nix`)

func regularDirectory(p string) error {
	info, err := os.Lstat(p)
	if err != nil || !info.IsDir() {
		return Public("Project source path must be a real directory")
	}
	return nil
}

func ownedWorkspace(root string) (string, error) {
	root, _ = filepath.Abs(root)
	for _, p := range []string{filepath.Dir(root), root} {
		if err := regularDirectory(p); err != nil {
			return "", err
		}
		info, _ := os.Stat(p)
		if int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
			if p == root {
				return "", Public("Project workspace must be controlled by the Nixus broker")
			}
			return "", Public("Project workspace parent must be owned and not writable by other users")
		}
	}
	return root, nil
}

func projectPatches(changes M) (M, error) {
	if len(changes) < 1 || len(changes) > 16 {
		return nil, Public("Supply one to sixteen project Nix file edits")
	}
	total := 0
	for name, content := range changes {
		if len(name) > 255 || strings.Contains(name, "\x00") {
			return nil, Public("Invalid project file path")
		}
		if name != "backups.nix" {
			parts := strings.Split(name, "/")
			valid := len(parts) >= 2 && fullmatch(projectName, parts[0]) &&
				((len(parts) == 2 && parts[1] == "default.nix") || (len(parts) >= 3 && parts[1] == "modules" && fullmatch(projectModuleFile, parts[len(parts)-1])))
			if valid && len(parts) >= 3 && parts[1] == "modules" {
				for _, p := range parts[2 : len(parts)-1] {
					if !fullmatch(projectFragment, p) || strings.HasPrefix(p, "_") {
						valid = false
					}
				}
			}
			if !valid {
				return nil, Public("Project edits must target default.nix or modules/**/*.nix")
			}
		}
		if content == nil {
			if name == "backups.nix" || strings.HasSuffix(name, "/default.nix") {
				return nil, Public("Cannot implicitly remove project entrypoints or backup policy")
			}
			continue
		}
		text, ok := content.(string)
		if !ok || strings.Contains(text, "\x00") {
			return nil, Public("Project Nix edits must be UTF-8 text")
		}
		if len(text) > 65536 {
			return nil, Public("Individual Nix edit exceeds 64 KiB")
		}
		total += len(text)
	}
	if total > 128*1024 {
		return nil, Public("Project Nix changes exceed 128 KiB")
	}
	return changes, nil
}

func safeBytes(root, name string, expected M) ([]byte, error) {
	fail := Public("Project source changed during snapshot")
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail
	}
	parts := strings.Split(name, "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, fail
		}
		fd = next
	}
	ffd, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	unix.Close(fd)
	if err != nil {
		return nil, fail
	}
	f := os.NewFile(uintptr(ffd), name)
	defer f.Close()
	var st unix.Stat_t
	size, _ := intValue(expected["size"])
	if unix.Fstat(ffd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size != int64(size) {
		return nil, fail
	}
	data, _ := io.ReadAll(io.LimitReader(f, st.Size+1))
	h := sha256.Sum256(data)
	if int64(len(data)) != st.Size || hex.EncodeToString(h[:]) != str(expected["sha256"]) {
		return nil, fail
	}
	return data, nil
}

func copyVerified(source, destination string, manifest M) (M, error) {
	if err := os.Mkdir(destination, 0o700); err != nil {
		return nil, err
	}
	files := obj(manifest["files"])
	for _, rel := range keys(files) {
		target := filepath.Join(destination, rel)
		os.MkdirAll(filepath.Dir(target), 0o700)
		data, err := safeBytes(source, rel, obj(files[rel]))
		if err != nil {
			return nil, err
		}
		if err := atomic(target, data, 0o600, ""); err != nil {
			return nil, err
		}
	}
	result, err := validateWorkspace(destination, true)
	if err != nil {
		return nil, err
	}
	if str(result["sourceHash"]) != str(manifest["sourceHash"]) {
		return nil, Public("Project snapshot changed; retry the review")
	}
	return result, nil
}

var parseNix = func(paths []string) error {
	for _, p := range paths {
		res, err := run([]string{"nix-instantiate", "--parse", p}, nil, 15*time.Second, nil, "")
		if err != nil {
			return Public("Nix parser unavailable or timed out")
		}
		if res.Code != 0 {
			return Public("Project Nix syntax is invalid")
		}
	}
	return nil
}

func exchange(left, right string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, left, unix.AT_FDCWD, right, unix.RENAME_EXCHANGE); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(left))
}

func freeze(directory string) {
	filepath.WalkDir(directory, func(p string, d os.DirEntry, err error) error {
		if err == nil && p != directory {
			if d.IsDir() {
				os.Chmod(p, 0o500)
			} else {
				os.Chmod(p, 0o400)
			}
		}
		return nil
	})
	os.Chmod(directory, 0o500)
}

func attestSources(revisions any, inventory M) (M, error) {
	if revisions == nil {
		return M{}, nil
	}
	refs, ok := revisions.(M)
	if !ok || len(refs) > 16 {
		return nil, Public("Invalid published source references")
	}
	publisher := NewPublishedSources("")
	approved := M{}
	projects := obj(inventory["projects"])
	for _, project := range keys(refs) {
		p := obj(projects[project])
		if !fullmatch(projectName, project) || p == nil || !isTrue(p["enable"]) {
			return nil, Public("Source revision must reference an enabled declarative project")
		}
		attested, err := publisher.attest(project, refs[project])
		if err != nil {
			return nil, err
		}
		approved[project] = attested
	}
	return approved, nil
}

func recheckSources(approved, inventory M) error {
	if len(approved) == 0 {
		return nil
	}
	revisions := M{}
	for name, item := range approved {
		revisions[name] = obj(item)["revision"]
	}
	again, err := attestSources(revisions, inventory)
	if err != nil {
		return err
	}
	if !equalJSON(again, approved) {
		return Public("Published source bytes changed since project review")
	}
	return nil
}

type ProjectTransactions struct{ workspace, state, jobs string }

func NewProjectTransactions(workspace, state string) *ProjectTransactions {
	if workspace == "" {
		workspace = projectsWorkspace
	}
	if state == "" {
		state = STATE
	}
	workspace, _ = filepath.Abs(workspace)
	t := &ProjectTransactions{workspace, state, filepath.Join(state, "project-transactions")}
	os.MkdirAll(t.jobs, 0o700)
	return t
}

func (t *ProjectTransactions) job(id any) (string, error) {
	s, _ := id.(string)
	return jobDirectory(t.jobs, s, "project transaction")
}

func (t *ProjectTransactions) record(id any) (M, error) {
	dir, err := t.job(id)
	if err != nil {
		return nil, err
	}
	return readJobRecord(filepath.Join(dir, "job.json"), nil)
}

func (t *ProjectTransactions) write(id string, record M) error {
	dir, err := t.job(id)
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "job.json"), record)
}

func (t *ProjectTransactions) rootState(deployment string) error {
	if a := activeProjectDeployment(t.state); a != "" && a != deployment {
		return Public("Finish or recover the active project deployment")
	}
	if v, _ := readJSON(filepath.Join(t.state, "pending.json"), nil); v != nil && !equalJSON(v, M{}) {
		return Public("Finish the pending host activation before project changes")
	}
	if id := str(readObj(filepath.Join(t.state, "active.json"))["id"]); id != "" {
		record, err := readJobRecord(filepath.Join(t.state, "jobs", id, "job.json"), nil)
		if err != nil {
			return err
		}
		switch str(record["status"]) {
		case "building", "ready", "applying", "awaiting-confirmation", "rolling-back":
			return Public("Finish the active host transaction first")
		}
	}
	if err := checkIdle(t.state, deployment); err != nil {
		return err
	}
	return nil
}

func (t *ProjectTransactions) activeReview() error {
	if id := str(readObj(filepath.Join(t.state, "project-active.json"))["id"]); id != "" {
		record, err := t.record(id)
		if err != nil {
			return err
		}
		switch str(record["status"]) {
		case "ready", "applying-source", "rolling-back", "recovery-required":
			return Public("Finish or recover the active project review")
		}
	}
	return nil
}

func (t *ProjectTransactions) initialize(flake, lock any, principal string) (M, error) {
	f, ok1 := flake.(string)
	l, ok2 := lock.(string)
	if !ok1 || !ok2 || len(f) > 32768 || len(l) > 131072 || strings.TrimSpace(f) == "" || strings.TrimSpace(l) == "" {
		return nil, Public("Provide a bounded pinned workspace flake and lock")
	}
	locked, err := parseObject([]byte(l))
	if v, _ := num(locked["version"]); err != nil || v != 7 || obj(locked["nodes"]) == nil || obj(locked["nodes"])[str(locked["root"])] == nil {
		return nil, Public("A valid pinned flake.lock is required")
	}
	return lockedValue(false, func() (M, error) {
		if err := t.rootState(""); err != nil {
			return nil, err
		}
		if err := t.activeReview(); err != nil {
			return nil, err
		}
		parent := filepath.Dir(t.workspace)
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
			return nil, Public("Project workspace parent must be broker-owned")
		}
		if lexists(t.workspace) {
			return nil, Public("Project workspace already exists; use reviewed revisions")
		}
		scratch, err := os.MkdirTemp(parent, ".nixus-initialize-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(scratch)
		atomicString(filepath.Join(scratch, "flake.nix"), f, 0o600)
		atomicString(filepath.Join(scratch, "flake.lock"), l, 0o600)
		if err := parseNix([]string{filepath.Join(scratch, "flake.nix")}); err != nil {
			return nil, err
		}
		manifest, err := validateWorkspace(scratch, true)
		if err != nil {
			return nil, err
		}
		if err := os.Rename(scratch, t.workspace); err != nil {
			return nil, err
		}
		fsyncDir(parent)
		audit("project-workspace-initialized", M{"principal": principal, "sourceHash": manifest["sourceHash"]})
		return M{"available": true, "sourceHash": manifest["sourceHash"], "files": len(obj(manifest["files"])),
			"projects": len(obj(manifest["projects"]))}, nil
	})
}

func (t *ProjectTransactions) status(identity string) (M, error) {
	if identity == "" {
		identity = str(readObj(filepath.Join(t.state, "project-active.json"))["id"])
	}
	if identity == "" {
		return M{"active": nil, "deployment": "not-implemented"}, nil
	}
	record, err := t.record(identity)
	if err != nil {
		return nil, err
	}
	dir, _ := t.job(identity)
	deploymentPath := filepath.Join(dir, "deployment.json")
	deployment := readObj(deploymentPath)
	if s := str(deployment["status"]); s == "queued" || s == "applying" {
		updated, ok := num(deployment["updatedAt"])
		if !ok {
			if updated, ok = num(deployment["createdAt"]); !ok {
				updated = now()
			}
		}
		if now()-updated > 30 {
			if active, err := workerActive("nixus-project-deploy-" + identity); err == nil && !active {
				deployment["status"], deployment["errorCode"], deployment["updatedAt"] = "interrupted", "worker-interrupted", now()
				writeJSON(deploymentPath, deployment)
			}
		}
	}
	out := M{}
	for _, k := range []string{"id", "status", "created", "expires", "baseHash", "candidateHash", "planHash", "changes", "principal",
		"sourceOnly", "errorCode", "inventoryHash", "runtimeActions", "sourceRefs"} {
		out[k] = record[k]
	}
	ds := str(deployment["status"])
	if ds == "" {
		ds = "not-started"
	}
	resources := deployment["resources"]
	if resources == nil {
		resources = M{}
	}
	rs := str(record["status"])
	out["deployment"], out["deploymentResources"] = ds, resources
	out["deploymentError"] = deployment["errorDetail"]
	out["recoveryRequired"] = rs == "applying-source" || rs == "rolling-back" || rs == "recovery-required" || ds == "partial" || ds == "interrupted"
	return out, nil
}

func (t *ProjectTransactions) review(changesArg any, principal string, sourceRevisions any) (M, error) {
	changesM, ok := changesArg.(M)
	if !ok {
		return nil, Public("Supply one to sixteen project Nix file edits")
	}
	// A review may only rebind published source revisions (for example an
	// image update) without editing any Nix file.
	rebindOnly := len(changesM) == 0 && len(obj(sourceRevisions)) > 0
	changes := changesM
	var err error
	if !rebindOnly {
		if changes, err = projectPatches(changesM); err != nil {
			return nil, err
		}
	}
	return lockedValue(false, func() (M, error) {
		if err := t.rootState(""); err != nil {
			return nil, err
		}
		if err := t.activeReview(); err != nil {
			return nil, err
		}
		live, err := ownedWorkspace(t.workspace)
		if err != nil {
			return nil, err
		}
		if lexists(filepath.Join(live, ".git")) {
			return nil, Public("Move Git metadata outside the managed workspace before reviewing project changes")
		}
		before, err := validateWorkspace(live, true)
		if err != nil {
			return nil, err
		}
		identity := tokenHex(16)
		scratch, err := os.MkdirTemp(t.jobs, ".review-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(scratch)
		source := filepath.Join(scratch, "source")
		if _, err := copyVerified(live, source, before); err != nil {
			return nil, err
		}
		impact := []any{}
		var nixFiles []string
		beforeFiles := obj(before["files"])
		for _, rel := range keys(changes) {
			p := filepath.Join(source, rel)
			_, existed := beforeFiles[rel]
			op := "create"
			if changes[rel] == nil {
				if !existed {
					return nil, Public("Cannot remove an unknown module")
				}
				os.Remove(p)
				op = "remove"
			} else {
				if err := atomicString(p, str(changes[rel]), 0o600); err != nil {
					return nil, err
				}
				nixFiles = append(nixFiles, p)
				if existed {
					op = "update"
				}
			}
			impact = append(impact, M{"path": rel, "operation": op})
		}
		if err := parseNix(nixFiles); err != nil {
			return nil, err
		}
		after, err := validateWorkspace(source, true)
		if err != nil {
			return nil, err
		}
		inventory, err := evaluateProjects(source, identity)
		if err != nil {
			return nil, err
		}
		sourceRefs, err := attestSources(sourceRevisions, inventory)
		if err != nil {
			return nil, err
		}
		runtimePlan, err := projectPlan(inventory, sourceRefs)
		if err != nil {
			return nil, err
		}
		if str(before["sourceHash"]) == str(after["sourceHash"]) && !rebindOnly {
			return nil, Public("Project source has no changes to publish")
		}
		if again, err := validateWorkspace(live, true); err != nil || str(again["sourceHash"]) != str(before["sourceHash"]) {
			return nil, Public("Project source changed while being reviewed")
		}
		sourceOnly := true
		for _, a := range list(runtimePlan["actions"]) {
			if str(obj(a)["action"]) != "noop" {
				sourceOnly = false
			}
		}
		record := M{"id": identity, "status": "ready", "created": now(), "expires": now() + projectJobLifetime, "principal": principal,
			"baseHash": before["sourceHash"], "candidateHash": after["sourceHash"], "changes": impact, "sourceOnly": sourceOnly,
			"inventoryHash": runtimePlan["inventoryHash"], "runtimeActions": runtimePlan["actions"], "sourceRefs": sourceRefs}
		record["planHash"] = digestJSON(M{"id": identity, "base": record["baseHash"], "candidate": record["candidateHash"],
			"changes": impact, "inventoryHash": runtimePlan["inventoryHash"], "runtimePlan": runtimePlan, "sourceOnly": sourceOnly,
			"sourceRefs": sourceRefs})
		writeJSON(filepath.Join(scratch, "inventory.json"), inventory)
		writeJSON(filepath.Join(scratch, "runtime-plan.json"), runtimePlan)
		writeJSON(filepath.Join(scratch, "job.json"), record)
		freeze(source)
		if err := os.Rename(scratch, filepath.Join(t.jobs, identity)); err != nil {
			return nil, err
		}
		writeJSON(filepath.Join(t.state, "project-active.json"), M{"id": identity})
		audit("project-source-reviewed", M{"identity": identity, "paths": len(impact), "principal": principal})
		return t.status(identity)
	})
}

func (t *ProjectTransactions) paths(identity string) (string, string, string) {
	prefix := filepath.Dir(t.workspace)
	return filepath.Join(prefix, ".nixus-project-staged-"+identity), filepath.Join(prefix, ".nixus-project-before-"+identity),
		filepath.Join(prefix, ".nixus-project-reverted-"+identity)
}

func (t *ProjectTransactions) publish(identityArg, planHash any) (M, error) {
	identity, _ := identityArg.(string)
	return lockedValue(false, func() (M, error) {
		if err := t.rootState(""); err != nil {
			return nil, err
		}
		record, err := t.record(identity)
		if err != nil {
			return nil, err
		}
		if str(readObj(filepath.Join(t.state, "project-active.json"))["id"]) != identity || str(record["status"]) != "ready" {
			return nil, Public("Project review is no longer active")
		}
		hash, ok := planHash.(string)
		if !ok || !compareDigest(hash, str(record["planHash"])) {
			return nil, Public("The exact reviewed project plan must be approved")
		}
		if expires, _ := num(record["expires"]); now() >= expires {
			return nil, Public("Project review expired; submit a new review")
		}
		live, err := ownedWorkspace(t.workspace)
		if err != nil {
			return nil, err
		}
		dir, _ := t.job(identity)
		before, err1 := validateWorkspace(live, true)
		candidate, err2 := validateWorkspace(filepath.Join(dir, "source"), true)
		if err1 != nil || err2 != nil || str(before["sourceHash"]) != str(record["baseHash"]) || str(candidate["sourceHash"]) != str(record["candidateHash"]) {
			return nil, Public("Project source or reviewed candidate changed; re-review required")
		}
		runtimeInventory, err := evaluateProjects(filepath.Join(dir, "source"), identity)
		if err != nil {
			return nil, err
		}
		if digestJSON(runtimeInventory) != digestJSON(readObj(filepath.Join(dir, "inventory.json"))) {
			return nil, Public("Reviewed typed project inventory changed")
		}
		if err := recheckSources(obj(record["sourceRefs"]), runtimeInventory); err != nil {
			return nil, err
		}
		currentPlan, err := projectPlan(runtimeInventory, obj(record["sourceRefs"]))
		if err != nil {
			return nil, err
		}
		if !equalJSON(currentPlan, readObj(filepath.Join(dir, "runtime-plan.json"))) {
			return nil, Public("Incus observation changed since review; prepare a new project plan")
		}
		staged, previous, reverted := t.paths(identity)
		for _, p := range []string{staged, previous, reverted} {
			if lexists(p) {
				return nil, Public("Project recovery path already exists; inspect it locally")
			}
		}
		if _, err := copyVerified(filepath.Join(dir, "source"), staged, candidate); err != nil {
			return nil, err
		}
		record["status"], record["phase"] = "applying-source", "prepared"
		t.write(identity, record)
		if err := exchange(live, staged); err != nil {
			return nil, err
		}
		record["phase"] = "exchanged"
		t.write(identity, record)
		if err := os.Rename(staged, previous); err != nil {
			return nil, err
		}
		fsyncDir(filepath.Dir(previous))
		record["status"], record["phase"], record["publishedAt"] = "published-source", "published", now()
		t.write(identity, record)
		writeJSON(filepath.Join(t.state, "project-last.json"), M{"id": identity})
		audit("project-source-published", M{"identity": identity, "principal": record["principal"]})
		notifyAppsRepo()
		return t.status(identity)
	})
}

func (t *ProjectTransactions) recover(identityArg any) (M, error) {
	identity, _ := identityArg.(string)
	return lockedValue(false, func() (M, error) {
		record, err := t.record(identity)
		if err != nil {
			return nil, err
		}
		if str(readObj(filepath.Join(t.state, "project-active.json"))["id"]) != identity {
			return nil, Public("Recover the current project transaction only")
		}
		status := str(record["status"])
		if status != "applying-source" && status != "rolling-back" && status != "recovery-required" {
			return nil, Public("Project transaction is not interrupted")
		}
		staged, previous, _ := t.paths(identity)
		live := t.workspace
		matches := func(p string, expected any) bool {
			if !lexists(p) || isSymlink(p) {
				return false
			}
			m, err := validateWorkspace(p, true)
			return err == nil && str(m["sourceHash"]) == str(expected)
		}
		base, cand := record["baseHash"], record["candidateHash"]
		switch {
		case status == "rolling-back":
			if matches(live, base) && matches(previous, cand) {
				record["status"] = "rolled-back"
				durableUnlink(filepath.Join(t.state, "project-last.json"))
			} else if matches(live, cand) && matches(previous, base) {
				record["status"] = "published-source"
			} else {
				record["status"] = "recovery-required"
			}
		case matches(live, cand) && matches(previous, base):
			record["status"] = "published-source"
			writeJSON(filepath.Join(t.state, "project-last.json"), M{"id": identity})
		case matches(live, cand) && matches(staged, base):
			os.Rename(staged, previous)
			fsyncDir(filepath.Dir(previous))
			record["status"] = "published-source"
			writeJSON(filepath.Join(t.state, "project-last.json"), M{"id": identity})
		case matches(live, base) && matches(staged, cand):
			record["status"] = "recovered"
		default:
			record["status"] = "recovery-required"
		}
		record["phase"] = "reconciled"
		t.write(identity, record)
		if str(record["status"]) == "recovery-required" {
			return nil, Public("Project publication requires manual recovery; files were retained")
		}
		audit("project-source-recovered", M{"identity": identity, "outcome": record["status"]})
		return t.status(identity)
	})
}

func (t *ProjectTransactions) rollback(identityArg, planHash any) (M, error) {
	identity, _ := identityArg.(string)
	return lockedValue(false, func() (M, error) {
		if err := t.rootState(""); err != nil {
			return nil, err
		}
		record, err := t.record(identity)
		if err != nil {
			return nil, err
		}
		if str(record["status"]) != "published-source" || str(readObj(filepath.Join(t.state, "project-last.json"))["id"]) != identity {
			return nil, Public("Only the last published source revision can be rolled back")
		}
		dir, _ := t.job(identity)
		deployment := readObj(filepath.Join(dir, "deployment.json"))
		ds := str(deployment["status"])
		if ds != "" && ds != "not-started" && ds != "verified" {
			return nil, Public("Recover the partial Incus deployment before changing project source")
		}
		if ds == "verified" {
			for _, a := range list(record["runtimeActions"]) {
				if str(obj(a)["action"]) != "noop" {
					return nil, Public("Source-only rollback would leave applied Incus settings inconsistent; review a new forward change")
				}
			}
		}
		if other := str(readObj(filepath.Join(t.state, "project-active.json"))["id"]); other != "" && other != identity {
			o, err := t.record(other)
			if err != nil {
				return nil, err
			}
			switch str(o["status"]) {
			case "ready", "applying-source", "rolling-back", "recovery-required":
				return nil, Public("Finish the pending project review before rolling back older source")
			}
		}
		hash, ok := planHash.(string)
		if !ok || !compareDigest(hash, str(record["planHash"])) {
			return nil, Public("The reviewed project plan must be confirmed for rollback")
		}
		live, err := ownedWorkspace(t.workspace)
		if err != nil {
			return nil, err
		}
		staged, previous, reverted := t.paths(identity)
		if lexists(reverted) || lexists(staged) {
			return nil, Public("Unexpected project recovery path")
		}
		lv, err1 := validateWorkspace(live, true)
		pv, err2 := validateWorkspace(previous, true)
		if err1 != nil || err2 != nil || str(lv["sourceHash"]) != str(record["candidateHash"]) || str(pv["sourceHash"]) != str(record["baseHash"]) {
			return nil, Public("Project source drift; refuse blind rollback")
		}
		record["status"] = "rolling-back"
		t.write(identity, record)
		if err := exchange(live, previous); err != nil {
			return nil, err
		}
		record["status"], record["phase"] = "rolled-back", "rolled-back"
		t.write(identity, record)
		durableUnlink(filepath.Join(t.state, "project-last.json"))
		audit("project-source-rolled-back", M{"identity": identity})
		return t.status(identity)
	})
}

func (t *ProjectTransactions) deploy(identityArg, planHash any, resume bool) (M, error) {
	identity, _ := identityArg.(string)
	return lockedValue(false, func() (M, error) {
		if err := t.rootState(identity); err != nil {
			return nil, err
		}
		job, err := t.record(identity)
		if err != nil {
			return nil, err
		}
		if str(job["status"]) != "published-source" || str(readObj(filepath.Join(t.state, "project-last.json"))["id"]) != identity {
			return nil, Public("Publish the exact project source revision before deployment")
		}
		hash, ok := planHash.(string)
		if !ok || !compareDigest(hash, str(job["planHash"])) {
			return nil, Public("The exact reviewed deployment plan must be approved")
		}
		live, err := ownedWorkspace(t.workspace)
		if err != nil {
			return nil, err
		}
		if lv, err := validateWorkspace(live, true); err != nil || str(lv["sourceHash"]) != str(job["candidateHash"]) {
			return nil, Public("Published project source drifted before deployment")
		}
		dir, _ := t.job(identity)
		plan := readObj(filepath.Join(dir, "runtime-plan.json"))
		inventory := readObj(filepath.Join(dir, "inventory.json"))
		if digestJSON(inventory) != str(plan["inventoryHash"]) {
			return nil, Public("Reviewed inventory is corrupt")
		}
		if err := recheckSources(obj(job["sourceRefs"]), inventory); err != nil {
			return nil, err
		}
		for name := range obj(job["sourceRefs"]) {
			if str(jget(inventory, "projects", name, "backend")) != "incus-compose" {
				return nil, Public("Only Compose projects deploy uploaded Dockerfile/Compose source")
			}
		}
		existing := readObj(filepath.Join(dir, "deployment.json"))
		if len(existing) > 0 && !resume {
			if str(existing["status"]) == "verified" {
				return t.status(identity)
			}
			return nil, Public("Resume the current deployment journal; never restart blindly")
		}
		if resume && str(existing["status"]) != "partial" && str(existing["status"]) != "interrupted" {
			return nil, Public("No partial deployment to recover")
		}
		if len(existing) == 0 {
			current, err := projectPlan(inventory, obj(job["sourceRefs"]))
			if err != nil {
				return nil, err
			}
			if !equalJSON(current, plan) {
				return nil, Public("Incus state differs from approved deployment")
			}
			resources := M{}
			for _, r := range list(plan["resources"]) {
				rm := obj(r)
				resources[str(rm["project"])+"/"+str(rm["name"])] = M{"phase": "pending", "action": rm["action"]}
			}
			existing = M{"format": 1, "status": "queued", "createdAt": now(), "planHash": job["planHash"],
				"sourceHash": job["candidateHash"], "resources": resources}
		} else {
			existing["status"] = "queued"
		}
		existing["updatedAt"] = now()
		writeJSON(filepath.Join(dir, "deployment.json"), existing)
		writeJSON(filepath.Join(t.state, "project-deploy-active.json"), M{"id": identity})
		audit("project-deploy-requested", M{"identity": identity, "resume": resume, "principal": job["principal"]})
		pinErr := pinWorkerRuntime(dir)
		var runErr error
		if pinErr == nil {
			_, runErr = check([]string{"systemd-run", "--quiet", "--collect", "--no-block", "--unit=nixus-project-deploy-" + identity,
				"--property=RuntimeMaxSec=3600", "--setenv=NIXUS_STATE=" + t.state, "--setenv=NIXUS_PROJECTS=" + t.workspace,
				"--setenv=PATH=" + os.Getenv("PATH"), "--setenv=NIXUS_OCI_VM_TEST=" + os.Getenv("NIXUS_OCI_VM_TEST"),
				adminLauncher(), "admin", "project-deploy-job", identity}, nil, 20*time.Second)
		}
		if pinErr != nil || runErr != nil {
			existing["status"], existing["errorCode"] = "interrupted", "worker-start-failed"
			writeJSON(filepath.Join(dir, "deployment.json"), existing)
			return nil, Public("Project worker failed to start; use explicit resume")
		}
		return t.status(identity)
	})
}

func (t *ProjectTransactions) runDeployment(identity string) (M, error) {
	return lockedValue(true, func() (M, error) {
		release, err := lockFile(incusLock, true)
		if err != nil {
			return nil, err
		}
		defer release()
		dir, err := t.job(identity)
		if err != nil {
			return nil, err
		}
		record, err := t.record(identity)
		if err != nil {
			return nil, err
		}
		journal := readObj(filepath.Join(dir, "deployment.json"))
		plan := readObj(filepath.Join(dir, "runtime-plan.json"))
		inventory := readObj(filepath.Join(dir, "inventory.json"))
		ws, werr := validateWorkspace(t.workspace, true)
		js := str(journal["status"])
		if (js != "queued" && js != "partial" && js != "interrupted") || str(journal["planHash"]) != str(record["planHash"]) ||
			str(journal["sourceHash"]) != str(record["candidateHash"]) || digestJSON(inventory) != str(plan["inventoryHash"]) ||
			werr != nil || str(ws["sourceHash"]) != str(record["candidateHash"]) {
			return nil, Public("Project deployment journal or published source differs")
		}
		journal["status"], journal["updatedAt"] = "applying", now()
		writeJSON(filepath.Join(dir, "deployment.json"), journal)
		resources := obj(journal["resources"])
		projectFor := func(incusProject string) M {
			for _, p := range obj(inventory["projects"]) {
				if str(obj(p)["incusProject"]) == incusProject {
					return obj(p)
				}
			}
			return nil
		}
		err = func() error {
			for _, raw := range list(plan["resources"]) {
				resource := obj(raw)
				key := str(resource["project"]) + "/" + str(resource["name"])
				state := obj(resources[key])
				phase := str(state["phase"])
				project := projectFor(str(resource["project"]))
				if phase == "verified" {
					current, err := planObserve(project, resource)
					if err != nil {
						return err
					}
					if str(current["action"]) != "noop" || str(current["etag"]) != str(state["newEtag"]) {
						return Public("Previously verified Incus resource drifted; re-review")
					}
					continue
				}
				state["phase"] = "applying"
				writeJSON(filepath.Join(dir, "deployment.json"), journal)
				result, err := recheckAndApply(project, resource, phase == "applying")
				if err != nil {
					return err
				}
				health := result["health"]
				if health == nil {
					health = "unknown"
				}
				state["phase"], state["newEtag"], state["observedHealth"] = "verified", result["newEtag"], health
				journal["updatedAt"] = now()
				writeJSON(filepath.Join(dir, "deployment.json"), journal)
			}
			return nil
		}()
		if err == nil {
			// Deliver each app's secrets into its running instances.
			for _, name := range keys(obj(inventory["projects"])) {
				if _, derr := deliverProjectSecrets(name, obj(obj(inventory["projects"])[name])); derr != nil {
					err = derr
					break
				}
			}
		}
		if err != nil {
			journal["status"], journal["updatedAt"], journal["errorCode"] = "partial", now(), "resource-review-required"
			journal["errorDetail"] = publicError(err)
			fmt.Fprintln(os.Stderr, "nixus: project deployment stopped:", err)
			writeJSON(filepath.Join(dir, "deployment.json"), journal)
			audit("project-deploy-partial", M{"identity": identity})
			return t.status(identity)
		}
		journal["status"], journal["completedAt"] = "verified", now()
		writeJSON(filepath.Join(dir, "deployment.json"), journal)
		durableUnlink(filepath.Join(t.state, "project-deploy-active.json"))
		audit("project-deploy-verified", M{"identity": identity, "resources": len(list(plan["resources"]))})
		return t.status(identity)
	})
}

func (t *ProjectTransactions) cancel(identityArg any) (M, error) {
	identity, _ := identityArg.(string)
	return lockedValue(false, func() (M, error) {
		record, err := t.record(identity)
		if err != nil {
			return nil, err
		}
		if str(record["status"]) != "ready" {
			return nil, Public("Only an unapplied project source review can be cancelled")
		}
		record["status"] = "cancelled"
		t.write(identity, record)
		audit("project-source-cancelled", M{"identity": identity})
		return t.status(identity)
	})
}

// abandonDeployment releases a partial or interrupted deployment so a
// rollback can deploy the previous revision. The journal is kept and marked
// superseded; nothing in Incus is changed here.
func (t *ProjectTransactions) abandonDeployment(identity, reason string) error {
	_, err := lockedValue(false, func() (M, error) {
		if str(readObj(filepath.Join(t.state, "project-deploy-active.json"))["id"]) != identity {
			return nil, Public("Only the active project deployment can be superseded")
		}
		dir, err := t.job(identity)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(dir, "deployment.json")
		journal := readObj(path)
		if s := str(journal["status"]); s != "partial" && s != "interrupted" {
			return nil, Public("Only a stopped deployment can be superseded")
		}
		journal["status"], journal["supersededAt"], journal["supersededReason"] = "superseded", now(), reason
		if err := writeJSON(path, journal); err != nil {
			return nil, err
		}
		durableUnlink(filepath.Join(t.state, "project-deploy-active.json"))
		audit("project-deploy-superseded", M{"identity": identity, "reason": reason})
		return M{}, nil
	})
	return err
}

var projectWorkerActive = func(identity string) bool {
	res, err := run([]string{"systemctl", "is-active", "--quiet", "nixus-project-deploy-" + identity}, nil, 10*time.Second, nil, "")
	// If systemd cannot be asked, assume the worker is alive.
	return err != nil || (res.Code != 3 && res.Code != 4)
}

// activeProjectDeployment returns the deployment that holds the host, or "".
// A deployment whose worker is gone (crash, timeout, reboot, Nixus update) can
// never finish, so it is released instead of blocking every later change; its
// journal is kept and marked superseded.
func activeProjectDeployment(state string) string {
	marker := filepath.Join(state, "project-deploy-active.json")
	identity := str(readObj(marker)["id"])
	if identity == "" {
		return ""
	}
	dir, err := jobDirectory(filepath.Join(state, "project-transactions"), identity, "project transaction")
	if err != nil {
		// The marker names no deployment that could ever be resumed.
		durableUnlink(marker)
		return ""
	}
	path := filepath.Join(dir, "deployment.json")
	journal := readObj(path)
	updated, _ := num(journal["updatedAt"])
	// A worker is started right after the journal is written; give it a moment.
	if now()-updated < 60 || projectWorkerActive(identity) {
		return identity
	}
	if str(journal["status"]) != "verified" {
		journal["supersededFrom"] = journal["status"]
		journal["status"], journal["supersededAt"], journal["supersededReason"] = "superseded", now(), "worker stopped"
		writeJSON(path, journal)
	}
	durableUnlink(marker)
	fmt.Fprintln(os.Stderr, "nixus: released project deployment", identity, "whose worker had stopped")
	audit("project-deploy-superseded", M{"identity": identity, "reason": "worker stopped"})
	return ""
}

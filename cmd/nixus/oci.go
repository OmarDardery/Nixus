package main

// OCI source planning, Compose model validation, and the pinned incus-compose
// parse of a reviewed source.

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// --- source plan -----------------------------------------------------------

var composeNames = map[string]bool{"compose.yaml": true, "compose.yml": true, "docker-compose.yaml": true, "docker-compose.yml": true}
var dockerfileNames = map[string]bool{"Dockerfile": true, "Containerfile": true}
var buildkitPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?mi)^\s*#\s*syntax\s*=\s*docker/dockerfile:`),
	regexp.MustCompile(`(?mi)^\s*RUN\s+--(?:mount|security|device)\b`),
	regexp.MustCompile(`(?mi)^\s*(?:COPY|ADD)\s+--link\b`),
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func generatedCompose(project, revision, dockerfile string) (string, string) {
	parent := path.Dir(dockerfile)
	context := "./" + parent
	if parent == "." {
		context = "."
	}
	image := "localhost/nixus-" + truncate(project, 24) + "-app:" + revision[:32]
	return "services:\n  app:\n    image: " + jsonString(image) + "\n    build:\n      context: " + jsonString(context) +
		"\n      dockerfile: " + jsonString(path.Base(dockerfile)) + "\n", image
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func sourcePlan(project, revision any, publisher *PublishedSources) (M, error) {
	if publisher == nil {
		publisher = NewPublishedSources("")
	}
	attestation, err := publisher.attest(project, revision)
	if err != nil {
		return nil, err
	}
	p, rev := project.(string), revision.(string)
	folder := filepath.Join(publisher.root, p, "revisions", rev)
	files, err := checkFiles(readObj(filepath.Join(folder, "manifest.json"))["files"])
	if err != nil {
		return nil, err
	}
	byPath := map[string]sourceEntry{}
	var compose, dockerfiles []string
	for _, e := range files {
		byPath[e.Path] = e
		if composeNames[path.Base(e.Path)] {
			compose = append(compose, e.Path)
		}
		if dockerfileNames[path.Base(e.Path)] {
			dockerfiles = append(dockerfiles, e.Path)
		}
	}
	sort.Strings(compose)
	sort.Strings(dockerfiles)
	reasons := []string{}
	var generated, image, selected any
	mode := "unsupported"
	switch {
	case len(compose) == 1:
		mode, selected = "compose", compose[0]
		reasons = append(reasons, "sandboxed-incus-compose-compatibility-check-required")
	case len(compose) > 1:
		mode = "ambiguous-compose"
		reasons = append(reasons, "multiple-compose-files-require-explicit-selection")
	case len(dockerfiles) == 1:
		mode, selected = "dockerfile", dockerfiles[0]
		g, i := generatedCompose(p, rev, dockerfiles[0])
		generated, image = g, i
		if byPath[dockerfiles[0]].Size > 1024*1024 {
			reasons = append(reasons, "dockerfile-exceeds-preflight-source-size")
		} else {
			raw, _ := os.ReadFile(filepath.Join(folder, "source", dockerfiles[0]))
			for _, pattern := range buildkitPatterns {
				if pattern.Match(raw) {
					reasons = append(reasons, "unsupported-buildkit-feature-requires-explicit-policy")
					break
				}
			}
		}
	case len(dockerfiles) > 1:
		mode = "ambiguous-dockerfile"
		reasons = append(reasons, "multiple-dockerfiles-require-explicit-selection")
	default:
		reasons = append(reasons, "no-compose-or-dockerfile-entrypoint")
	}
	lock := imageLock(folder, files)
	if unpinnedBases(lock) {
		reasons = append(reasons, "dockerfile-base-image-must-be-pinned-by-digest")
	}
	return M{"format": 1, "project": p, "revision": attestation["revision"], "fileCount": attestation["fileCount"],
		"bytes": attestation["bytes"], "sourceFiles": entriesAny(files), "mode": mode, "entrypoint": selected,
		"generatedCompose": generated, "proposedImage": image, "buildContextHash": rev,
		"buildIdentity": sha256str(p + "\x00" + rev), "imageLock": lock, "canBuild": false, "canDeploy": false, "blocking": strings2any(reasons),
		"note": "Source-only planning: no OCI image, Incus resources or volume created"}, nil
}

// --- Compose model validation ----------------------------------------------

var secretKey = re(`[A-Za-z_][A-Za-z0-9_]{0,127}`)
var composeServiceName = re(`[a-z][a-z0-9_-]{0,62}`)
var composeSource = re(`[A-Za-z0-9][A-Za-z0-9_.-]*`)
var sensitiveEnv = regexp.MustCompile(`(?i)(?:PASSWORD|PASSWD|TOKEN|SECRET|PRIVATE|AUTH|KEY|CREDENTIAL)`)
var bannedService = map[string]bool{"privileged": true, "cap_add": true, "device_cgroup_rules": true,
	"security_opt": true, "userns_mode": true, "pid": true, "ipc": true, "uts": true, "cgroup": true, "cgroup_parent": true,
	"cgroupns_mode": true, "network_mode": true, "volumes_from": true, "extends": true, "develop": true, "secrets": true,
	"configs": true, "env_file": true, "x-incus": true}
var bannedTop = map[string]bool{"secrets": true, "configs": true, "include": true, "x-incus": true, "x-incus-compose": true}

func safeRelative(v any, allowDot bool) (string, error) {
	value, ok := v.(string)
	if !ok || strings.ContainsAny(value, "\\\x00") || strings.HasPrefix(value, "/") {
		return "", Public("Unsupported or absolute Compose source path")
	}
	parts := strings.Split(value, "/")
	var kept []string
	allDots := true
	for _, p := range parts {
		if p == ".." || p == "" {
			return "", Public("Compose context cannot escape its source directory")
		}
		if p != "." {
			allDots = false
			if strings.HasPrefix(p, "-") || !fullmatch(composeSource, p) {
				return "", Public("Unsupported Compose source component")
			}
			kept = append(kept, p)
		}
	}
	if allowDot && allDots {
		return ".", nil
	}
	return strings.Join(kept, "/"), nil
}

func composeSourcePath(base string, v any, allowDot bool) (string, error) {
	if s, ok := v.(string); ok && (s == "/context" || strings.HasPrefix(s, "/context/")) {
		relative := strings.TrimLeft(strings.TrimPrefix(s, "/context"), "/")
		if relative == "" {
			return ".", nil
		}
		return safeRelative(relative, allowDot)
	}
	var parts []string
	if base != "." {
		parts = strings.Split(base, "/")
	}
	leaf, err := safeRelative(v, allowDot)
	if err != nil {
		return "", err
	}
	if leaf != "." && leaf != "" {
		parts = append(parts, strings.Split(leaf, "/")...)
	}
	if len(parts) == 0 {
		return ".", nil
	}
	return strings.Join(parts, "/"), nil
}

func composeVolumes(v any) ([]string, error) {
	if v == nil {
		return []string{}, nil
	}
	items, ok := v.([]any)
	if !ok || len(items) > 32 {
		return nil, Public("Invalid Compose mounts")
	}
	names := []string{}
	for _, item := range items {
		switch x := item.(type) {
		case string:
			source, _, has := strings.Cut(x, ":")
			if !has || source == "" || strings.HasPrefix(source, "/") || strings.HasPrefix(source, ".") || strings.HasPrefix(source, "~") || strings.Contains(source, "/") {
				return nil, Public("Compose bind or anonymous mounts require explicit separate review")
			}
			if !fullmatch(composeServiceName, source) {
				return nil, Public("Invalid named volume")
			}
			names = append(names, source)
		case M:
			for k := range x {
				switch k {
				case "type", "source", "target", "read_only", "volume":
				default:
					return nil, Public("Unsupported Compose volume attributes")
				}
			}
			if str(x["type"]) != "volume" || !fullmatch(composeServiceName, str(x["source"])) {
				return nil, Public("Bind/anonymous mounts are forbidden in this deployment adapter")
			}
			names = append(names, str(x["source"]))
		default:
			return nil, Public("Invalid Compose volume")
		}
	}
	return names, nil
}

func composeEnvironments(v any) error {
	if v == nil {
		return nil
	}
	env, ok := v.(M)
	if !ok {
		return Public("Compose environment must be explicit named entries")
	}
	if len(env) > 64 {
		return Public("Compose environment exceeds review bounds")
	}
	for k, value := range env {
		if !fullmatch(re(`[A-Za-z_][A-Za-z0-9_]{0,79}`), k) {
			return Public("Invalid environment variable name")
		}
		if sensitiveEnv.MatchString(k) {
			return Public("Move " + k + " to the app's Env tab; secret-like variables are not allowed in compose.yaml")
		}
		switch value.(type) {
		case nil, string, float64, bool, json.Number:
		default:
			return Public("Unsupported Compose environment value")
		}
	}
	return nil
}

// plainNamedVolume accepts a local named volume as Compose normalizes it: no
// options, or only the default "<project>_<name>" name and external: false.
var serialSource = re(`/dev/(serial/by-(id|path)/[A-Za-z0-9._:+-]{1,200}|tty(ACM|USB)[0-9]{1,3})`)
var deviceTarget = re(`/dev/[A-Za-z0-9._-]{1,64}`)
var usbID = re(`([0-9a-f]{4}):([0-9a-f]{4})`)
var safeDeviceName = re(`[A-Za-z0-9][A-Za-z0-9_.-]{0,62}`)

// composeDevices validates the supported device subset:
//   - standard Compose serial devices (/dev/serial/by-id/..., /dev/ttyACM*, /dev/ttyUSB*)
//     translated into hotpluggable Incus unix-char devices
//   - native x-incus-compose.devices entries restricted to type: usb (vendorid/productid)
//     and type: unix-char (safe serial paths).
func composeDevices(v any, incusExt any) (M, error) {
	out := M{}
	refuse := Public("Only serial devices (/dev/serial/by-id/..., /dev/ttyACM*, /dev/ttyUSB*) and usb/serial entries in x-incus-compose.devices can be passed through")
	items, ok := v.([]any)
	if v != nil && !ok {
		return nil, refuse
	}
	if len(items) > 8 {
		return nil, refuse
	}
	for i, raw := range items {
		var source, target, perms string
		switch d := raw.(type) {
		case string:
			parts := strings.Split(d, ":")
			if len(parts) > 3 {
				return nil, refuse
			}
			source, target = parts[0], parts[0]
			if len(parts) > 1 {
				target = parts[1]
			}
			if len(parts) > 2 {
				perms = parts[2]
			}
		case M:
			for k := range d {
				if k != "source" && k != "target" && k != "permissions" {
					return nil, refuse
				}
			}
			source, target, perms = str(d["source"]), str(d["target"]), str(d["permissions"])
			if target == "" {
				target = source
			}
		default:
			return nil, refuse
		}
		if !fullmatch(serialSource, source) || !fullmatch(deviceTarget, target) && !fullmatch(serialSource, target) ||
			(perms != "" && perms != "rwm" && perms != "rw") || strings.Contains(source+target, "..") {
			return nil, refuse
		}
		out[fmt.Sprintf("nixus-serial%d", i)] = M{"type": "unix-char", "source": source, "path": target,
			"required": "false", "mode": "0666"}
	}
	if incusExt != nil {
		x := obj(incusExt)
		if x == nil || len(x) != 1 || x["devices"] == nil {
			return nil, Public("x-incus-compose supports only validated usb and serial devices")
		}
		devs := obj(x["devices"])
		if devs == nil || len(devs) > 8 {
			return nil, refuse
		}
		for name, raw := range devs {
			if !fullmatch(safeDeviceName, name) {
				return nil, refuse
			}
			d := obj(raw)
			if d == nil {
				return nil, refuse
			}
			switch str(d["type"]) {
			case "usb":
				for k := range d {
					if k != "type" && k != "vendorid" && k != "productid" && k != "required" {
						return nil, refuse
					}
				}
				if !fullmatch(hex4, str(d["vendorid"])) || !fullmatch(hex4, str(d["productid"])) {
					return nil, Public("USB devices require 4-digit hex vendorid and productid")
				}
				if req := str(d["required"]); req != "" && req != "true" && req != "false" {
					return nil, refuse
				}
			case "unix-char":
				for k := range d {
					if k != "type" && k != "source" && k != "path" && k != "required" && k != "mode" {
						return nil, refuse
					}
				}
				source, target := str(d["source"]), str(d["path"])
				if target == "" {
					target = source
				}
				if !fullmatch(serialSource, source) || (!fullmatch(deviceTarget, target) && !fullmatch(serialSource, target)) || strings.Contains(source+target, "..") {
					return nil, refuse
				}
				if mode := str(d["mode"]); mode != "" && !fullmatch(re(`0?[0-7]{3}`), mode) {
					return nil, refuse
				}
				if req := str(d["required"]); req != "" && req != "true" && req != "false" {
					return nil, refuse
				}
			default:
				return nil, refuse
			}
		}
	}
	return out, nil
}

func plainNamedVolume(project, name string, props any) bool {
	if props == nil {
		return true
	}
	for k, v := range obj(props) {
		switch {
		case k == "name" && v == project+"_"+name:
		case k == "external" && v == false:
		default:
			return false
		}
	}
	return obj(props) != nil
}

func validateComposeModel(model M, project, revision, composePath string, files []sourceEntry) (M, error) {
	if !fullmatch(composeServiceName, project) {
		return nil, Public("Invalid project")
	}
	if !fullmatch(hex64, revision) {
		return nil, Public("Invalid source revision")
	}
	if model == nil {
		return nil, Public("Compose demands unsupported privileged or secret resources")
	}
	for k := range model {
		if bannedTop[k] {
			return nil, Public("Compose demands unsupported privileged or secret resources")
		}
	}
	if v := model["volumes"]; v != nil {
		volumes, ok := v.(M)
		if !ok {
			return nil, Public("Custom storage drivers, external volumes and unsafe volume options are forbidden")
		}
		for name, props := range volumes {
			if !fullmatch(composeServiceName, name) || !plainNamedVolume(project, name, props) {
				return nil, Public("Custom storage drivers, external volumes and unsafe volume options are forbidden")
			}
		}
	}
	if v := model["networks"]; v != nil {
		networks, ok := v.(M)
		if !ok {
			return nil, Public("Invalid Compose networks definition")
		}
		for name, props := range networks {
			if !fullmatch(composeServiceName, name) {
				return nil, Public("Invalid Compose network name")
			}
			for k := range obj(props) {
				if strings.HasPrefix(k, "x-") {
					return nil, Public("Custom Incus extensions are not allowed on Compose networks")
				}
			}
		}
	}
	services := obj(model["services"])
	if len(services) < 1 || len(services) > 16 {
		return nil, Public("Compose requires 1–16 services")
	}
	known := map[string]bool{}
	for _, f := range files {
		known[f.Path] = true
	}
	base := path.Dir(composePath)
	preview := []any{}
	for _, service := range keys(services) {
		data := obj(services[service])
		if !fullmatch(composeServiceName, service) || data == nil {
			return nil, Public("Invalid Compose service")
		}
		for k := range data {
			if bannedService[k] || (strings.HasPrefix(k, "x-") && k != "x-incus-compose") {
				return nil, Public("Compose service requires forbidden host privileges or runtime secrets")
			}
		}
		if err := composeEnvironments(data["environment"]); err != nil {
			return nil, err
		}
		ports := data["ports"]
		portList, ok := ports.([]any)
		if ports == nil {
			portList, ok = []any{}, true
		}
		if !ok || len(portList) > 32 {
			return nil, Public("Invalid Compose host port exposure")
		}
		for _, p := range portList {
			switch p.(type) {
			case string, float64, M, json.Number:
			default:
				return nil, Public("Invalid Compose host port exposure")
			}
		}
		named, err := composeVolumes(data["volumes"])
		if err != nil {
			return nil, err
		}
		devices, err := composeDevices(data["devices"], data["x-incus-compose"])
		if err != nil {
			return nil, err
		}
		var context, dockerfile any
		switch build := data["build"].(type) {
		case string:
			context, dockerfile = build, "Dockerfile"
		case M:
			for k := range build {
				switch k {
				case "context", "dockerfile", "args", "target", "no_cache", "pull", "labels", "platforms":
				default:
					return nil, Public("Unsupported build options; source retained unchanged")
				}
			}
			for _, k := range []string{"args", "target", "platforms", "pull"} {
				if v := build[k]; v != nil && v != false && v != "" && !(obj(v) != nil && len(obj(v)) == 0) && !(list(v) != nil && len(list(v)) == 0) {
					return nil, Public("Build args, network/pull, target and platforms require explicit build policy")
				}
			}
			context, dockerfile = build["context"], build["dockerfile"]
			if context == nil {
				context = "."
			}
			if dockerfile == nil {
				dockerfile = "Dockerfile"
			}
		case nil:
		default:
			return nil, Public("Invalid Compose build definition")
		}
		var image any
		var contextPath, dockerfilePath any
		built := context != nil
		if built {
			cp, err := composeSourcePath(base, context, true)
			if err != nil {
				return nil, err
			}
			dp, err := composeSourcePath(cp, dockerfile, false)
			if err != nil {
				return nil, err
			}
			if !known[dp] {
				return nil, Public("Compose Dockerfile is missing from the exact published context")
			}
			contextPath, dockerfilePath = cp, dp
			image = fmt.Sprintf("localhost/nixus-%s-%s:%s", truncate(project, 24), truncate(service, 24), revision[:32])
		} else {
			img, ok := data["image"].(string)
			if !ok || !strings.Contains(img, "@sha256:") {
				return nil, Public("Non-built services must use explicit immutable OCI image digests")
			}
			image = img
		}
		preview = append(preview, M{"service": service, "image": image, "built": built, "context": contextPath,
			"dockerfile": dockerfilePath, "namedVolumes": strings2any(named), "ports": portList, "devices": devices})
	}
	lines := []string{"services:"}
	for _, raw := range preview {
		svc := obj(raw)
		devices := obj(svc["devices"])
		if !isTrue(svc["built"]) && len(devices) == 0 {
			continue
		}
		lines = append(lines, "  "+str(svc["service"])+":")
		if isTrue(svc["built"]) {
			lines = append(lines, "    image: "+jsonString(str(svc["image"])))
		}
		if len(devices) > 0 {
			lines = append(lines, "    x-incus-compose:", "      devices:")
			for _, name := range keys(devices) {
				lines = append(lines, "        "+name+":")
				d := obj(devices[name])
				for _, k := range keys(d) {
					lines = append(lines, "          "+k+": "+jsonString(str(d[k])))
				}
			}
		}
	}
	override := ""
	if len(lines) > 1 {
		override = strings.Join(lines, "\n") + "\n"
	}
	identity := digestJSON(M{"project": project, "revision": revision, "services": preview})
	wouldCreate := []any{}
	requiresBuilder := false
	for _, raw := range preview {
		wouldCreate = append(wouldCreate, obj(raw)["service"])
		requiresBuilder = requiresBuilder || isTrue(obj(raw)["built"])
	}
	return M{"format": 1, "project": project, "revision": revision, "services": preview, "separateOverride": override,
		"sourceHash": revision, "intentHash": identity, "requiresBuilder": requiresBuilder, "wouldCreateOrRecreate": wouldCreate,
		"networks": model["networks"], "note": "Intent only. Apply requires separate approval and exact Incus ownership checks."}, nil
}

const maxManifestJSON = 1024 * 1024

const imageOwnerKey = "user.nixus.owner"
const imageBackendKey = "user.nixus.backend"
const composeBackend = "incus-compose"

func incusProjectName(name string) (string, error) {
	value := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(name), "-")
	value = strings.Trim(regexp.MustCompile(`-+`).ReplaceAllString(value, "-"), "-")
	if value == "" {
		return "", Public("Project name has no Incus equivalent")
	}
	return value, nil
}

type incusFunc func(timeout time.Duration, args ...string) (string, error)

func defaultIncus(timeout time.Duration, args ...string) (string, error) {
	if timeout == 0 {
		timeout = 600 * time.Second
	}
	return opIncus(timeout, args...)
}

func incusQueryObj(incus incusFunc, p string) M {
	out, err := incus(0, "query", p)
	if err != nil {
		return nil
	}
	m, err := parseObject([]byte(out))
	if err != nil {
		return nil
	}
	return m
}

func ensureComposeProject(project string, incus incusFunc) error {
	if project == "default" || project == "lab" {
		return Public("Compose apps never use the default or host-owned lab Incus project")
	}
	current := incusQueryObj(incus, "/1.0/projects/"+project)
	if current == nil {
		_, err := incus(0, "project", "create", project, "-c", "features.images=true", "-c", "features.profiles=true",
			"-c", imageOwnerKey+"=true", "-c", imageBackendKey+"="+composeBackend)
		return err
	}
	config := obj(current["config"])
	if str(config[imageOwnerKey]) != "true" || str(config[imageBackendKey]) != composeBackend {
		return Public("The Incus project is not owned by Nixus for Compose; refusing to adopt it")
	}
	if str(config["features.images"]) != "true" {
		return Public("The Incus project shares the default image store; refusing to import into it")
	}
	return nil
}

// --- Compose model (parsed by the pinned incus-compose, then validated) --------

// composeExec runs the pinned compose binary for parsing only; it never talks
// to Incus and gets a minimal environment.
func composeExec(argv []string, cwd string) ([]byte, error) {
	res, err := run(argv, nil, 30*time.Second, []string{"PATH=" + os.Getenv("NIXUS_OCI_PATH"), "HOME=" + cwd}, cwd)
	if err != nil || res.Code != 0 {
		fmt.Fprintln(os.Stderr, "nixus: compose parse failed:", string(res.Stderr))
		return nil, Public("The Compose file could not be parsed: " + lastLine(string(res.Stderr)))
	}
	if len(res.Stdout) > maxManifestJSON {
		return nil, Public("Compose validation result is too large")
	}
	return res.Stdout, nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if len(last) > 700 {
		last = last[:700]
	}
	return last
}

// composeJSON renders the canonical model of the reviewed source in dir.
func composeJSON(spec M, dir, scratch, extra string) (M, error) {
	compose := os.Getenv("NIXUS_OCI_COMPOSE_BIN")
	if compose == "" {
		compose = "incus-compose"
	}
	var flags []string
	if e := str(spec["entrypoint"]); e != "" {
		flags = []string{"-f", filepath.Join(dir, e)}
	}
	if g := str(spec["generatedCompose"]); g != "" {
		original := path.Dir(str(spec["entrypoint"]))
		relative, absolute := "./"+original, dir+"/"+original
		if original == "." {
			relative, absolute = ".", dir
		}
		expected := "context: " + jsonString(relative)
		if strings.Count(g, expected) != 1 {
			return nil, Public("Reviewed Dockerfile context differs from generated launch manifest")
		}
		generated := filepath.Join(scratch, "generated.yaml")
		if err := os.WriteFile(generated, []byte(strings.Replace(g, expected, "context: "+jsonString(absolute), 1)), 0o600); err != nil {
			return nil, err
		}
		flags = []string{"-f", generated}
	}
	if extra != "" {
		flags = append(flags, "-f", extra)
	}
	base := append([]string{compose, "-p", str(spec["project"]), "-P", dir}, flags...)
	if _, err := composeExec(append(append([]string{}, base...), "config", "--quiet"), dir); err != nil {
		return nil, err
	}
	out, err := composeExec(append(append([]string{}, base...), "config", "--format", "json"), dir)
	if err != nil {
		return nil, err
	}
	// The model names paths under the materialised source; validation expects
	// them under the fixed /context root.
	m, err := parseObject([]byte(strings.ReplaceAll(string(out), dir, "/context")))
	if err != nil {
		return nil, Public("Pinned Compose parser produced an invalid model")
	}
	return m, nil
}

// composeModel parses and validates the reviewed source materialised in dir.
func composeModel(spec M, dir, scratch string) (M, error) {
	original, err := composeJSON(spec, dir, scratch, "")
	if err != nil {
		return nil, err
	}
	files, err := checkFiles(spec["sourceFiles"])
	if err != nil {
		return nil, err
	}
	composePath := str(spec["entrypoint"])
	if composePath == "" {
		composePath = "."
	}
	return validateComposeModel(original, str(spec["project"]), str(spec["revision"]), composePath, files)
}
